"""
IDE Viewer Portal - Flask Application Factory.
"""

import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from flask_cors import CORS
from flask_migrate import Migrate
from authlib.integrations.flask_client import OAuth

from config import config

# Extensions
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
csrf = CSRFProtect()
oauth = OAuth()

login_manager.login_view = 'auth.login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'


def create_app(config_name=None):
    """Application factory."""
    
    if config_name is None:
        config_name = os.environ.get('FLASK_CONFIG', 'default')
    
    app = Flask(__name__, 
                template_folder='templates',
                static_folder='static')
    
    app.config.from_object(config[config_name])

    # Validate production config
    if config_name == 'production':
        if not app.config.get('SECRET_KEY'):
            raise ValueError("SECRET_KEY environment variable is required in production")
        if not app.config.get('SQLALCHEMY_DATABASE_URI'):
            raise ValueError("DATABASE_URL environment variable is required in production")

    # Ensure instance folder exists
    instance_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'instance')
    os.makedirs(instance_path, exist_ok=True)
    
    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    csrf.init_app(app)
    oauth.init_app(app)
    
    # Register Google OAuth if configured
    if app.config.get('GOOGLE_CLIENT_ID') and app.config.get('GOOGLE_CLIENT_SECRET'):
        oauth.register(
            name='google',
            client_id=app.config['GOOGLE_CLIENT_ID'],
            client_secret=app.config['GOOGLE_CLIENT_SECRET'],
            server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
            client_kwargs={
                'scope': 'openid email profile'
            }
        )
    
    # Enable CORS for API endpoints
    CORS(app, resources={r"/api/*": {"origins": "*"}})
    
    # Register blueprints
    from app.auth.routes import auth_bp
    from app.main.routes import main_bp
    from app.api.routes import api_bp
    
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp, url_prefix='/api')
    
    # Exempt API blueprint from CSRF (uses API keys instead)
    csrf.exempt(api_bp)
    
    # Create database tables
    with app.app_context():
        db.create_all()
    
    # Context processor to make config available in templates
    @app.context_processor
    def inject_config():
        """Inject configuration into templates."""
        class TemplateConfig:
            GOOGLE_OAUTH_ENABLED = bool(
                app.config.get('GOOGLE_CLIENT_ID') and 
                app.config.get('GOOGLE_CLIENT_SECRET')
            )
            PORTAL_NAME = app.config.get('PORTAL_NAME', 'IDE Viewer')
        
        return {'config': TemplateConfig}
    
    return app


@login_manager.user_loader
def load_user(user_id):
    """Load user for Flask-Login."""
    from app.models import User
    return User.query.get(int(user_id))
