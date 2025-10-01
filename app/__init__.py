from flask import Flask
import os
import secrets

from .extensions import db, csrf


def create_app(config_object: str | None = None) -> Flask:
    """Application factory that initializes extensions and registers blueprints.

    Behavior intentionally mirrors the previous single-file app.
    """
    # Point to project-level templates/static directories to preserve current layout
    app = Flask(
        __name__,
        instance_relative_config=True,
        template_folder="../templates",
        static_folder="../static",
    )

    # Ensure instance folder exists for database and configs
    os.makedirs(app.instance_path, exist_ok=True)

    # Core configuration
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(app.instance_path, 'users.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Session cookie security
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'

    # CSRF
    app.config['WTF_CSRF_ENABLED'] = True

    # Init extensions
    db.init_app(app)
    csrf.init_app(app)

    # Register blueprints
    from .auth import bp as auth_bp
    from .main import bp as main_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)

    # Ensure tables exist when app starts (use migrations later in prod)
    with app.app_context():
        from . import models  # noqa: F401
        db.create_all()

    # Security headers
    @app.after_request
    def set_security_headers(response):
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
        response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
        return response

    return app


