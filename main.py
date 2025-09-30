from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
import os
import secrets
import time

app = Flask(__name__)

# Ensure instance folder exists for database and configs
os.makedirs(app.instance_path, exist_ok=True)

# Secret key: use environment value in production, random fallback for dev
app.secret_key = os.environ.get('SECRET_KEY') or secrets.token_hex(32)

#configuring the database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(app.instance_path, 'users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'

# CSRF protection for all modifying requests
app.config['WTF_CSRF_ENABLED'] = True
csrf = CSRFProtect(app)
db = SQLAlchemy(app)

# Simple in-memory login rate limiting (per IP)
LOGIN_WINDOW_SECONDS = 900  # 15 minutes
LOGIN_MAX_ATTEMPTS = 5
_login_attempts = {}

def _prune_attempts(now_ts):
    cutoff = now_ts - LOGIN_WINDOW_SECONDS
    for ip, entries in list(_login_attempts.items()):
        _login_attempts[ip] = [t for t in entries if t >= cutoff]
        if not _login_attempts[ip]:
            _login_attempts.pop(ip, None)

def _is_rate_limited(ip_address: str) -> bool:
    now_ts = int(time.time())
    _prune_attempts(now_ts)
    attempts = _login_attempts.get(ip_address, [])
    return len(attempts) >= LOGIN_MAX_ATTEMPTS

def _record_attempt(ip_address: str) -> None:
    now_ts = int(time.time())
    _prune_attempts(now_ts)
    _login_attempts.setdefault(ip_address, []).append(now_ts)


@app.after_request
def set_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    # Allow inline scripts used in templates; tighten with nonces if you can remove inline JS
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    return response

#creating the database model
# a model represents a single row in the database
class User(db.Model):
    
    #Class variables
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(25), unique=True, nullable=False)
    password_hash = db.Column(db.String(100), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        pass

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
        pass





#Routes
@app.route('/')
def home():
    if "username" in session:
        return render_template('dashboard.html', username=session['username'])
    return render_template('index.html')


#login route
@app.route('/login', methods=["POST"])
def login():
    #collect info from the form
    client_ip = request.remote_addr or 'unknown'
    if _is_rate_limited(client_ip):
        return render_template('index.html', error="Too many login attempts. Try again later."), 429

    username = (request.form.get('username') or '').strip() #get the username from the form
    password = request.form.get('password') or '' #get the password from the form
    existing_user = User.query.filter_by(username=username).first()
    if existing_user and existing_user.check_password(password): #check if the password is correct
        session.clear()
        session['username'] = existing_user.username
        return redirect(url_for('dashboard'))
    else:
        _record_attempt(client_ip)
        return render_template('index.html', error="Invalid username or password"), 401







#register route

@app.route('/register', methods=["POST"])
def register():
    username = (request.form.get('username') or '').strip()
    password = request.form.get('password') or ''
    if not username or not password:
        return render_template('index.html', error="Username and password are required")
    if len(password) < 8:
        return render_template('index.html', error="Password must be at least 8 characters")
    existing_user = User.query.filter_by(username=username).first()
    if existing_user: # check if the username already exists in the database, this will evaluate to true if the username exists and render the index.html template with the error message
        return render_template('index.html', error="Username already exists")
    else:
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        session.clear()
        session['username'] = username
        return redirect(url_for('dashboard'))
# Dashboard route

# Simple dashboard route
@app.route('/dashboard')
def dashboard():
    if "username" in session:
        return render_template('dashboard.html', username=session['username'])
    return redirect(url_for('home'))

#logout route

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))





if __name__ == '__main__':
    # Create DB before running the server
    with app.app_context():
        db.create_all()
    debug_mode = os.environ.get('FLASK_DEBUG') == '1'
    app.run(debug=debug_mode)