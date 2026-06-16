import os
from functools import wraps
from pathlib import Path

from flask import Flask, abort, flash, redirect, render_template, request, url_for
from flask_login import LoginManager, current_user, login_required, login_user, logout_user
from werkzeug.security import check_password_hash, generate_password_hash

from models import ModuleAccess, Tenant, User, db

MODULES = {
    "crm": {"label": "Intégrale Connect CRM", "short_label": "CRM", "field": "module_crm", "icon": "◇", "logo": "img/iaconnectcrm.png", "description": "Pipeline commercial, relances et suivi des candidats en temps réel."},
    "cpf": {"label": "Intégrale Connect CPF", "short_label": "CPF", "field": "module_cpf", "icon": "◈", "logo": "img/iaconnectcpf.png", "description": "Suivi CPF, conformité Qualiopi et dossiers administratifs centralisés."},
    "partenaires": {"label": "Intégrale Connect Partenaires", "short_label": "Partenaires", "field": "module_partenaires", "icon": "◎", "logo": "img/iaconnectpartenaires.png", "description": "Pilotage du réseau, conventions, opportunités et reporting partenaires."},
}


def normalize_database_url(url):
    if url and url.startswith("postgres://"):
        return url.replace("postgres://", "postgresql://", 1)
    return url


def default_sqlite_uri():
    """Use Render persistent disks when available, otherwise Flask's instance folder."""
    explicit_path = os.environ.get("SQLITE_PATH")
    if explicit_path:
        db_path = Path(explicit_path)
    elif Path("/data").exists():
        db_path = Path("/data/integrale_connect.db")
    else:
        db_path = Path.cwd() / "instance" / "integrale_connect.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{db_path}"


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")
    database_url = normalize_database_url(os.environ.get("DATABASE_URL"))
    app.config["SQLALCHEMY_DATABASE_URI"] = database_url or default_sqlite_uri()
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    db.init_app(app)

    login_manager = LoginManager(app)
    login_manager.login_view = "login"
    login_manager.login_message = "Veuillez vous connecter pour accéder à cette page."

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    def role_required(role):
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                if current_user.role != role:
                    flash("Vous n’avez pas les droits nécessaires pour accéder à cette page.", "error")
                    return redirect(url_for("super_admin_dashboard" if current_user.role == "super_admin" else "client_dashboard"))
                return func(*args, **kwargs)
            return wrapper
        return decorator

    def validate_siret(siret):
        return siret and siret.isdigit() and len(siret) == 14

    def get_client_user(tenant):
        return User.query.filter_by(tenant_id=tenant.id, role="client_admin").first()

    def ensure_module_access(tenant):
        if tenant.module_access:
            return tenant.module_access
        access = ModuleAccess(tenant_id=tenant.id)
        db.session.add(access)
        db.session.flush()
        return access

    def module_names(access):
        if not access:
            return []
        return [meta["label"].replace("Intégrale Connect ", "") for meta in MODULES.values() if getattr(access, meta["field"])]

    @app.context_processor
    def inject_globals():
        return {"modules_config": MODULES, "module_names": module_names}

    @app.route("/")
    def index():
        if current_user.is_authenticated:
            return redirect(url_for("super_admin_dashboard" if current_user.role == "super_admin" else "client_dashboard"))
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for("super_admin_dashboard" if current_user.role == "super_admin" else "client_dashboard"))
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            user = User.query.filter_by(username=username).first()
            if not user or not check_password_hash(user.password_hash, password):
                flash("Identifiants incorrects. Vérifiez votre nom utilisateur et votre mot de passe.", "error")
                return render_template("login.html")
            if not user.is_active or (user.tenant and not user.tenant.is_active):
                flash("Ce compte est désactivé. Contactez votre administrateur Intégrale Connect.", "error")
                return render_template("login.html")
            login_user(user)
            return redirect(url_for("super_admin_dashboard" if user.role == "super_admin" else "client_dashboard"))
        return render_template("login.html")

    @app.route("/logout")
    @login_required
    def logout():
        logout_user()
        flash("Vous êtes déconnecté.", "success")
        return redirect(url_for("login"))

    @app.route("/super-admin")
    @login_required
    @role_required("super_admin")
    def super_admin_dashboard():
        stats = {
            "tenants": Tenant.query.count(),
            "active_accounts": User.query.filter_by(is_active=True).count(),
            "crm": ModuleAccess.query.filter_by(module_crm=True).count(),
            "cpf": ModuleAccess.query.filter_by(module_cpf=True).count(),
            "partenaires": ModuleAccess.query.filter_by(module_partenaires=True).count(),
        }
        return render_template("super_admin/dashboard.html", stats=stats)

    @app.route("/super-admin/tenants")
    @login_required
    @role_required("super_admin")
    def tenants():
        all_tenants = Tenant.query.order_by(Tenant.created_at.desc()).all()
        return render_template("super_admin/tenants.html", tenants=all_tenants, get_client_user=get_client_user)

    @app.route("/super-admin/tenants/create", methods=["GET", "POST"])
    @login_required
    @role_required("super_admin")
    def create_tenant():
        if request.method == "POST":
            company_name = request.form.get("company_name", "").strip()
            siret = request.form.get("siret", "").strip()
            contact_name = request.form.get("contact_name", "").strip()
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            if not all([company_name, siret, contact_name, username, password]):
                flash("Tous les champs sont obligatoires.", "error")
            elif not validate_siret(siret):
                flash("Le SIRET doit contenir exactement 14 chiffres.", "error")
            elif User.query.filter_by(username=username).first():
                flash("Ce nom utilisateur existe déjà.", "error")
            elif Tenant.query.filter_by(siret=siret).first():
                flash("Ce SIRET existe déjà.", "error")
            else:
                tenant = Tenant(company_name=company_name, siret=siret, contact_name=contact_name)
                db.session.add(tenant)
                db.session.flush()
                user = User(tenant_id=tenant.id, username=username, password_hash=generate_password_hash(password), role="client_admin")
                access = ModuleAccess(
                    tenant_id=tenant.id,
                    module_crm="module_crm" in request.form,
                    module_partenaires="module_partenaires" in request.form,
                    module_cpf="module_cpf" in request.form,
                )
                db.session.add_all([user, access])
                db.session.commit()
                flash("Centre de formation créé avec succès. Le compte client peut se connecter immédiatement.", "success")
                return redirect(url_for("tenants"))
        return render_template("super_admin/create_tenant.html")

    @app.route("/super-admin/tenants/<int:tenant_id>/edit", methods=["GET", "POST"])
    @login_required
    @role_required("super_admin")
    def edit_tenant(tenant_id):
        tenant = db.session.get(Tenant, tenant_id) or abort(404)
        user = get_client_user(tenant)
        access = ensure_module_access(tenant)
        if request.method == "POST":
            siret = request.form.get("siret", "").strip()
            username = request.form.get("username", "").strip()
            if not all([request.form.get("company_name", "").strip(), siret, request.form.get("contact_name", "").strip(), username]):
                flash("Tous les champs sont obligatoires.", "error")
            elif not validate_siret(siret):
                flash("Le SIRET doit contenir exactement 14 chiffres.", "error")
            elif User.query.filter(User.username == username, User.id != (user.id if user else 0)).first():
                flash("Ce nom utilisateur existe déjà.", "error")
            elif Tenant.query.filter(Tenant.siret == siret, Tenant.id != tenant.id).first():
                flash("Ce SIRET existe déjà.", "error")
            else:
                tenant.company_name = request.form.get("company_name", "").strip()
                tenant.siret = siret
                tenant.contact_name = request.form.get("contact_name", "").strip()
                tenant.is_active = request.form.get("is_active") == "on"
                if not user:
                    user = User(tenant_id=tenant.id, role="client_admin", password_hash=generate_password_hash(os.environ.get("DEFAULT_CLIENT_PASSWORD", "ChangeMe123!")))
                    db.session.add(user)
                user.username = username
                user.is_active = tenant.is_active
                access.module_crm = "module_crm" in request.form
                access.module_partenaires = "module_partenaires" in request.form
                access.module_cpf = "module_cpf" in request.form
                db.session.commit()
                flash("Centre mis à jour avec succès. Les droits sont appliqués sur le compte client.", "success")
                return redirect(url_for("tenants"))
        return render_template("super_admin/edit_tenant.html", tenant=tenant, user=user, access=access)

    @app.post("/super-admin/tenants/<int:tenant_id>/toggle")
    @login_required
    @role_required("super_admin")
    def toggle_tenant(tenant_id):
        tenant = db.session.get(Tenant, tenant_id) or abort(404)
        tenant.is_active = not tenant.is_active
        for user in tenant.users:
            user.is_active = tenant.is_active
        db.session.commit()
        flash("Statut du centre mis à jour.", "success")
        return redirect(url_for("tenants"))

    @app.post("/super-admin/tenants/<int:tenant_id>/reset-password")
    @login_required
    @role_required("super_admin")
    def reset_password(tenant_id):
        tenant = db.session.get(Tenant, tenant_id) or abort(404)
        user = get_client_user(tenant)
        new_password = request.form.get("new_password", "")
        if not user:
            flash("Aucun compte client n’est rattaché à ce centre.", "error")
        elif not new_password:
            flash("Veuillez saisir un nouveau mot de passe.", "error")
        else:
            user.password_hash = generate_password_hash(new_password)
            db.session.commit()
            flash("Mot de passe réinitialisé avec succès.", "success")
        return redirect(url_for("tenants"))

    @app.route("/dashboard")
    @login_required
    @role_required("client_admin")
    def client_dashboard():
        access = current_user.tenant.module_access if current_user.tenant else None
        enabled_modules = [key for key, meta in MODULES.items() if access and getattr(access, meta["field"])]
        requested_module = request.args.get("module")
        active_module = requested_module if requested_module in enabled_modules else (enabled_modules[0] if enabled_modules else None)
        return render_template("client/dashboard.html", access=access, active_module=active_module, enabled_modules=enabled_modules)

    @app.route("/modules/<module_key>")
    @login_required
    @role_required("client_admin")
    def module_placeholder(module_key):
        if module_key not in MODULES:
            abort(404)
        access = current_user.tenant.module_access
        meta = MODULES[module_key]
        if not access or not getattr(access, meta["field"]):
            flash("Module non activé. Contactez votre administrateur Intégrale Connect pour activer ce module.", "error")
            return redirect(url_for("client_dashboard"))
        return render_template("modules/module_placeholder.html", module_name=meta["label"])

    return app


def init_db():
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(role="super_admin").first():
            username = os.environ.get("SUPER_ADMIN_USERNAME") or "admin"
            password = os.environ.get("SUPER_ADMIN_PASSWORD") or "admin123"
            db.session.add(User(username=username, password_hash=generate_password_hash(password), role="super_admin"))
            db.session.commit()
            if not os.environ.get("SUPER_ADMIN_USERNAME") or not os.environ.get("SUPER_ADMIN_PASSWORD"):
                print("[SECURITE] Super admin local créé : admin / admin123. Changez ce mot de passe en production.")


app = create_app()
init_db()

if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG", "1") == "1")
