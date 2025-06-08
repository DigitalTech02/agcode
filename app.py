from flask import Flask, g, render_template, flash, redirect, url_for, request
import os
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import secrets
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from datetime import datetime

# Configuration
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
DATABASE = os.environ.get('DATABASE_PATH', 'image_portal.db')

# Create Flask app
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB max upload
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Security settings
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=False  # Set to True in production with HTTPS
)

# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# Add template filter for formatting dates
@app.template_filter('format_datetime')
def format_datetime(value):
    if isinstance(value, str):
        try:
            value = datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            return value
    return value.strftime('%b %d, %Y at %I:%M %p')

# Database functions
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(
            DATABASE,
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        db.row_factory = sqlite3.Row
        # Enable foreign key constraints
        db.execute('PRAGMA foreign_keys = ON')
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

# File upload helper
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# User class for Flask-Login
class User:
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password
        
    def is_authenticated(self):
        return True
        
    def is_active(self):
        return True
        
    def is_anonymous(self):
        return False
        
    def get_id(self):
        return str(self.id)

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if user is None:
        return None
    return User(user['id'], user['username'], user['password'])

# Routes
@app.route('/')
def index():
    db = get_db()
    try:
        images = db.execute('''
            SELECT i.id, i.filename, i.caption, i.upload_date, i.user_id, u.username
            FROM images i JOIN users u ON i.user_id = u.id
            ORDER BY i.upload_date DESC
        ''').fetchall()
    except sqlite3.Error:
        # Handle case where tables don't exist yet
        images = []
    return render_template('index.html', images=images)

@app.route('/user/<int:user_id>')
def user_profile(user_id):
    db = get_db()
    user = db.execute('SELECT id, username FROM users WHERE id = ?', (user_id,)).fetchone()
    if user is None:
        flash('User not found')
        return redirect(url_for('index'))
    
    images = db.execute('''
        SELECT id, filename, caption, upload_date
        FROM images
        WHERE user_id = ?
        ORDER BY upload_date DESC
    ''', (user_id,)).fetchall()
    
    return render_template('user_profile.html', user=user, images=images)

@app.route('/users')
def users():
    db = get_db()
    users = db.execute('SELECT id, username FROM users ORDER BY username').fetchall()
    return render_template('users.html', users=users)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Please enter both username and password')
            return render_template('login.html')
            
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        
        if user is None or not check_password_hash(user['password'], password):
            flash('Invalid username or password')
            return render_template('login.html')
            
        user_obj = User(user['id'], user['username'], user['password'])
        login_user(user_obj)
        
        next_page = request.args.get('next')
        if not next_page or not next_page.startswith('/'):
            next_page = url_for('index')
            
        flash('You have been logged in successfully!')
        return redirect(next_page)
        
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out')
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not username or not password:
            flash('Please enter both username and password')
            return render_template('register.html')
            
        if password != confirm_password:
            flash('Passwords do not match')
            return render_template('register.html')
            
        db = get_db()
        existing_user = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
        
        if existing_user:
            flash('Username already exists')
            return render_template('register.html')
            
        hashed_password = generate_password_hash(password)
        db.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
        db.commit()
        
        flash('Account created successfully! You can now log in.')
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_image():
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'image' not in request.files:
            flash('No file part')
            return redirect(request.url)
            
        file = request.files['image']
        
        # If user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
            
        if file and allowed_file(file.filename):
            # Secure the filename to prevent directory traversal attacks
            filename = secure_filename(file.filename)
            
            # Add a timestamp to make filename unique
            filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}"
            
            # Save the file
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            
            # Save file info to database
            caption = request.form.get('caption', '')
            db = get_db()
            db.execute(
                'INSERT INTO images (filename, caption, user_id) VALUES (?, ?, ?)',
                (filename, caption, current_user.id)
            )
            db.commit()
            
            flash('Image uploaded successfully!')
            return redirect(url_for('index'))
            
    return render_template('upload.html')

# Simple error handler
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

# Health check endpoint
@app.route('/health')
def health_check():
    return "OK", 200

if __name__ == '__main__':
    app.run(debug=True)


