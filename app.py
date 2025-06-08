import os
from flask import Flask

class SecurityHeadersMiddleware:
    """WSGI middleware that adds security headers to responses"""
    
    def __init__(self, app):
        self.app = app
    
    def __call__(self, environ, start_response):
        def custom_start_response(status, headers, exc_info=None):
            # Add security headers
            headers.extend([
                ('Content-Security-Policy', "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; style-src 'self' https://cdn.jsdelivr.net https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:;"),
                ('X-Content-Type-Options', 'nosniff'),
                ('X-Frame-Options', 'DENY'),
                ('X-XSS-Protection', '1; mode=block'),
                ('Referrer-Policy', 'strict-origin-when-cross-origin'),
                ('Permissions-Policy', 'camera=(), microphone=(), geolocation=()'),
            ])
            return start_response(status, headers, exc_info)
        
        return self.app(environ, custom_start_response)

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

def create_app(config_name=None):
    """Application factory function"""
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'default')
    
    app = Flask(__name__)
    
    # Load config
    from config import config
    app.config.from_object(config[config_name])
    
    # Ensure upload folder exists
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # Initialize extensions
    from flask_login import LoginManager
    login_manager = LoginManager()
    login_manager.login_view = 'login'
    login_manager.init_app(app)
    
    # Register blueprints
    from .views.auth import auth as auth_blueprint
    from .views.main import main as main_blueprint
    app.register_blueprint(auth_blueprint)
    app.register_blueprint(main_blueprint)
    
    # Setup database
    @app.teardown_appcontext
    def close_connection(exception):
        db = getattr(g, '_database', None)
        if db is not None:
            db.close()
    
    # User loader for Flask-Login
    from .models import User
    @login_manager.user_loader
    def load_user(user_id):
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        if user is None:
            return None
        return User(user['id'], user['username'], user['password'])
    
    # Template filters
    from datetime import datetime
    @app.template_filter('format_datetime')
    def format_datetime(value):
        if isinstance(value, str):
            try:
                value = datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
            except ValueError:
                return value
        return value.strftime('%b %d, %Y at %I:%M %p')
    
    # Setup rate limiting
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["200 per day", "50 per hour"]
    )
    
    # Apply specific rate limits
    @auth_blueprint.route('/login', methods=['POST'])
    @limiter.limit("10 per minute")
    def login_post():
        # ... login logic ...
    
    @auth_blueprint.route('/register', methods=['POST'])
    @limiter.limit("5 per hour")
    def register_post():
        # ... register logic ...
    
    # Register error handlers
    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('errors/404.html'), 404
    
    @app.errorhandler(500)
    def internal_server_error(e):
        return render_template('errors/500.html'), 500
    
    @app.errorhandler(413)
    def request_entity_too_large(e):
        flash('The file is too large. Maximum size is 5MB.')
        return redirect(url_for('upload_image')), 413
    
    return app


