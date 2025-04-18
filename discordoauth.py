# app.py
# Minimal Flask application implementing Discord OAuth2 login

import os
from flask import Flask, session, redirect, request, url_for, render_template_string
import requests
from urllib.parse import urlencode

app = Flask(__name__)
# Secret key for session encryption
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'change-this-secret')

# Discord OAuth2 credentials (set in environment)
CLIENT_ID = os.environ.get('DISCORD_CLIENT_ID')
CLIENT_SECRET = os.environ.get('DISCORD_CLIENT_SECRET')
REDIRECT_URI = os.environ.get('DISCORD_REDIRECT_URI')  # e.g. https://yourdomain.com/callback

# Whitelist of Discord user IDs allowed to access
ALLOWED_USERS = os.environ.get('DISCORD_WHITELIST', '').split(',')  # e.g. "123,456,789"

# Discord endpoints
OAUTH_AUTHORIZE_URL = 'https://discord.com/api/oauth2/authorize'
OAUTH_TOKEN_URL = 'https://discord.com/api/oauth2/token'
API_BASE_URL = 'https://discord.com/api'

@app.route('/')
def index():
    user = session.get('user')
    if not user:
        # Not logged in ➔ redirect to /login
        return redirect(url_for('login'))
    # Logged-in user
    return render_template_string(
        """
        <!doctype html>
        <html><head><title>Willkommen</title></head><body style="color:white;background:#111;font-family:sans-serif;">
          <h1>Hallo, {{ user.username }}#{{ user.discriminator }}!</h1>
          <p>Deine Discord-ID: {{ user.id }}</p>
          <a href="/logout" style="color:#007bff;">Logout</a>
        </body></html>
        """, user=user)

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
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
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
    if user['id'] not in ALLOWED_USERS:
        return 'Zugriff verweigert', 403
    # Save in session
    session['user'] = user
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    # Run locally for development
    app.run(debug=True, port=5000)
