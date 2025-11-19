from flask import Blueprint, render_template, redirect, url_for, session, flash, request, abort
from functools import wraps
import psycopg2
import psycopg2.extras
import subprocess
import os

internal_bp = Blueprint('internal', __name__, url_prefix='/internal')

ALLOWED_IPS = {'127.0.0.1', '::1'}

def get_db_connection():
    return psycopg2.connect(
        host=os.getenv('PG_HOST', 'db'),
        user=os.getenv('PG_USER', 'postgres'),
        password=os.getenv('PG_PASSWORD', 'postgres'),
        dbname=os.getenv('PG_DB', 'postgres'),
        cursor_factory=psycopg2.extras.DictCursor
    )

def ip_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        client_ip = request.remote_addr
        if client_ip not in ALLOWED_IPS:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

@internal_bp.route('/')
@ip_required
def home():
    if 'loggedin' in session:
        return render_template('home/home.html', username=session['username'], title="Home")
    return redirect(url_for('internal.login'))

@internal_bp.route('/login', methods=['GET', 'POST'])
@ip_required
def login():
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM accounts WHERE username = '" + username + "' AND password = '" + password + "';")
        account = cur.fetchone()
        cur.close()
        conn.close()

        if account:
            session['loggedin'] = True
            session['id'] = account['id']
            session['username'] = account['username']
            return redirect(url_for('internal.profile'))
        else:
            flash("Incorrect username/password!", "danger")

    return render_template('auth/login.html', title="Login")

@internal_bp.route('/profile')
@ip_required
def profile():
    if 'loggedin' in session:
        return render_template(
            'auth/profile.html',
            username=session['username'],
            title="Profile"
        )

    return redirect(url_for('internal.login'))

@internal_bp.route('/logout')
@ip_required
def logout():
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    return redirect(url_for('internal.login'))
