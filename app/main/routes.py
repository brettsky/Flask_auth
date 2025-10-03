from flask import render_template, redirect, url_for, session

from . import bp


@bp.route('/')
def home():
    if "username" in session:
        return render_template('dashboard.html', username=session['username'])
    return render_template('index.html')


@bp.route('/dashboard')
def dashboard():
    if "username" in session:
        return render_template('dashboard.html', username=session['username'])
    return redirect(url_for('auth.login_page'))



