# app.py
# Flask application with Discord OAuth2 login and access control

import os
from flask import Flask, session, redirect, request, url_for, render_template_string, send_from_directory, abort
import requests
from urllib.parse import urlencode
from functools import wraps
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

app = Flask(__name__, static_folder='static', static_url_path='')
# Secret key for session encryption
app.secret_key = os.environ.get('FLASK_SECRET_KEY')

# Discord OAuth2 credentials
CLIENT_ID     = os.environ.get('DISCORD_CLIENT_ID')
CLIENT_SECRET = os.environ.get('DISCORD_CLIENT_SECRET')
REDIRECT_URI  = os.environ.get('DISCORD_REDIRECT_URI')  # e.g. http://localhost:5000/callback

# Whitelist of Discord user IDs allowed to access
ALLOWED_USERS = os.environ.get('DISCORD_WHITELIST', '').split(',')

# Discord endpoints
OAUTH_AUTHORIZE_URL = 'https://discord.com/api/oauth2/authorize'
OAUTH_TOKEN_URL     = 'https://discord.com/api/oauth2/token'
API_BASE_URL       = 'https://discord.com/api'

# Decorator to require login
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
@login_required
def serve_index():
    # Serve main index.html
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/editor.html')
@login_required
def serve_editor():
    return send_from_directory(app.static_folder, 'editor.html')

@app.route('/calculate.html')
@login_required
def serve_calculate():
    return send_from_directory(app.static_folder, 'calculate.html')

@app.route('/assets/<path:filename>')
@login_required
def serve_assets(filename):
    # Serve static assets (images, js, css)
    return send_from_directory(os.path.join(app.static_folder, 'assets'), filename)

@app.route('/login')
def login():
    # Redirect user to Discord OAuth2 authorize URL
    params = {
        'client_id': CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'response_type': 'code',
        'scope': 'identify'
    }
    return redirect(f"{OAUTH_AUTHORIZE_URL}?{urlencode(params)}")

@app.route('/callback')
def callback():
    code = request.args.get('code')
    if not code:
        return 'Error: No code provided', 400
    # Exchange code for access token
    data = {
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': REDIRECT_URI,
        'scope': 'identify'
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    token_resp = requests.post(OAUTH_TOKEN_URL, data=data, headers=headers)
    token_json = token_resp.json()
    access_token = token_json.get('access_token')
    if not access_token:
        return 'Error fetching access token', 400
    # Fetch user info
    user_resp = requests.get(f"{API_BASE_URL}/users/@me",
        headers={'Authorization': f"Bearer {access_token}"})
    user = user_resp.json()
    # Check whitelist
    if user.get('id') not in ALLOWED_USERS:
        abort(403)
    # Save in session
    session['user'] = user
    return redirect(url_for('serve_index'))

@app.errorhandler(403)
def access_forbidden(e):
    return render_template_string(
        """
        <!doctype html><html><head><title>Zugriff verweigert</title></head>
        <body style="color:white;background:#111;font-family:sans-serif;display:flex;flex-direction:column;align-items:center;justify-content:center;height:100vh;">
          <h1>Zugriff verweigert</h1>
          <p>Dein Discord-Account hat keine Berechtigung.</p>
          <a href="/logout" style="color:#007bff;">Logout</a>
        </body></html>
        """), 403

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, port=5000)
