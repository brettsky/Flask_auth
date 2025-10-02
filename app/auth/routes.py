from flask import render_template, request, redirect, url_for, session

from ..extensions import db, oauth
from ..models import User
from . import bp

# Simple in-memory login rate limiting (per IP) — preserved from original
import time

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


@bp.route('/login', methods=["POST"])
def login():
    client_ip = request.remote_addr or 'unknown'
    if _is_rate_limited(client_ip):
        return render_template('index.html', error="Too many login attempts. Try again later."), 429

    username = (request.form.get('username') or '').strip()
    password = request.form.get('password') or ''
    existing_user = User.query.filter_by(username=username).first()
    if existing_user and existing_user.check_password(password):
        session.clear()
        session['username'] = existing_user.username
        return redirect(url_for('main.dashboard'))
    else:
        _record_attempt(client_ip)
        return render_template('index.html', error="Invalid username or password"), 401


@bp.route('/register', methods=["POST"])
def register():
    username = (request.form.get('username') or '').strip()
    password = request.form.get('password') or ''
    if not username or not password:
        return render_template('index.html', error="Username and password are required")
    if len(password) < 8:
        return render_template('index.html', error="Password must be at least 8 characters")
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return render_template('index.html', error="Username already exists")
    new_user = User(username=username)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    session.clear()
    session['username'] = username
    return redirect(url_for('main.dashboard'))


@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('main.home'))


# Login with Google
@bp.route('/login/google')
def google_login():
    # Redirect user to Google's OAuth consent screen
    redirect_url = url_for('auth.google_authorize', _external=True)
    return oauth.google.authorize_redirect(redirect_url)


# Authorize Google
@bp.route('/authorize/google')
def google_authorize():
    token = oauth.google.authorize_access_token()
    userinfo_endpoint = oauth.google.load_server_metadata()['userinfo_endpoint']
    resp = oauth.google.get(userinfo_endpoint)
# inside google_authorize() after fetching userinfo
    userinfo = resp.json()
    if not userinfo.get('email_verified', False):
        return render_template('index.html', error="Google account email not verified"), 403

    google_sub = userinfo.get('sub')
    email = userinfo.get('email')
    
    # Lookup by sub first; fallback by email once, then bind sub
    user = User.query.filter_by(google_sub=google_sub).first()
    if not user:
        user = User.query.filter_by(username=email).first()
        if user and not user.google_sub:
            user.google_sub = google_sub
        elif not user:
            user = User(username=email, google_sub=google_sub, is_oauth_only=True)
            db.session.add(user)
        db.session.commit()

    session['username'] = user.username
    return redirect(url_for('main.dashboard'))