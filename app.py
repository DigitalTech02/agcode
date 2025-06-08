import os
from flask import Flask, flash, request, redirect, url_for, render_template, session, g
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from functools import wraps
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from datetime import datetime

UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
DATABASE = 'image_portal.db'

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

# Create upload folder if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password

# Database setup
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
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

@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if user is None:
        return None
    return User(user['id'], user['username'], user['password'])

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    db = get_db()
    images = db.execute('''
        SELECT images.id, images.filename, images.caption, images.upload_date, 
               images.user_id, users.username 
        FROM images JOIN users ON images.user_id = users.id
        ORDER BY images.upload_date DESC
    ''').fetchall()
    return render_template('index.html', images=images)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_image():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        
        file = request.files['file']
        caption = request.form.get('caption', '')
        
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
            
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            
            db = get_db()
            db.execute('INSERT INTO images (filename, caption, user_id) VALUES (?, ?, ?)',
                      [filename, caption, current_user.id])
            db.commit()
            
            flash('Image successfully uploaded')
            return redirect(url_for('index'))
        else:
            flash('Allowed file types are: png, jpg, jpeg, gif')
            return redirect(request.url)
            
    return render_template('upload.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        db = get_db()
        error = None
        
        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'
        elif db.execute('SELECT id FROM users WHERE username = ?', 
                      (username,)).fetchone() is not None:
            error = f"User {username} is already registered."
            
        if error is None:
            db.execute('INSERT INTO users (username, password) VALUES (?, ?)',
                      (username, generate_password_hash(password)))
            db.commit()
            flash('Registration successful! Please log in.')
            return redirect(url_for('login'))
            
        flash(error)
        
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        db = get_db()
        error = None
        user_data = db.execute('SELECT * FROM users WHERE username = ?', 
                        (username,)).fetchone()
        
        if user_data is None:
            error = 'Incorrect username.'
        elif not check_password_hash(user_data['password'], password):
            error = 'Incorrect password.'
            
        if error is None:
            user = User(user_data['id'], user_data['username'], user_data['password'])
            login_user(user)
            flash(f'Welcome back, {username}!')
            return redirect(url_for('index'))
            
        flash(error)
        
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('index'))

@app.route('/user/<int:user_id>')
def user_profile(user_id):
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    
    if user is None:
        flash('User not found')
        return redirect(url_for('index'))
        
    images = db.execute('''
        SELECT * FROM images WHERE user_id = ? ORDER BY upload_date DESC
    ''', (user_id,)).fetchall()
    
    return render_template('user_profile.html', user=user, images=images)

@app.route('/users')
def user_list():
    db = get_db()
    users = db.execute('SELECT id, username FROM users ORDER BY username').fetchall()
    return render_template('users.html', users=users)

def check_db_exists():
    return os.path.exists(DATABASE)

@app.cli.command('init-db')
def init_db_command():
    """Initialize the database."""
    init_db()
    print('Database initialized.')

# Format datetime for templates
@app.template_filter('format_datetime')
def format_datetime(value):
    if isinstance(value, str):
        try:
            value = datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            return value
    return value.strftime('%b %d, %Y at %I:%M %p')

if __name__ == '__main__':
    with app.app_context():
        if not check_db_exists():
            init_db()
            print("Database initialized!")
    app.run(debug=True)


