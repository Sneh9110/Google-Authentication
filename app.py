from flask import Flask, redirect, url_for, session, render_template, request
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
import requests
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__, template_folder="templates")
app.secret_key = os.getenv("SECRET_KEY", "dev_secret_key")

# Flask-Login setup
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Mock User Model (Replace with DB in production)
class User(UserMixin):
    def __init__(self, id_, email, name):
        self.id = id_
        self.email = email
        self.name = name


# Google OAuth Config
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:5000/callback")



@login_manager.user_loader
def load_user(user_id):
    user_data = session.get("user")
    if user_data and user_data.get("id") == user_id:
        return User(user_data["id"], user_data["email"], user_data["name"])
    return None

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/login")
def login():
    flow = Flow.from_client_config(
        client_config={
            "web": {
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://accounts.google.com/o/oauth2/token",
                "redirect_uris": [GOOGLE_REDIRECT_URI],
            }
        },
        scopes=["openid", "https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"],
        redirect_uri=GOOGLE_REDIRECT_URI
    )
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)

@app.route("/callback")
def callback():
    flow = Flow.from_client_config(
        client_config={
            "web": {
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://accounts.google.com/o/oauth2/token",
                "redirect_uris": [GOOGLE_REDIRECT_URI],
            }
        },
        scopes=["openid", "https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"],
        redirect_uri=GOOGLE_REDIRECT_URI
    )
    # Restore state from session for security
    flow.state = session.get("state")
    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials
    id_info = id_token.verify_oauth2_token(credentials.id_token, requests.Request(), GOOGLE_CLIENT_ID)

    user = User(id_info["sub"], id_info["email"], id_info["name"])
    login_user(user)
    # Store user info as dict, not object
    session["user"] = {"id": user.id, "email": user.email, "name": user.name}
    return redirect(url_for("dashboard"))

@app.route("/dashboard")
@login_required
def dashboard():
    user = session.get("user")
    name = user["name"] if user else "User"
    return render_template("dashboard.html", name=name)

@app.route("/logout")
def logout():
    logout_user()
    session.clear()
    return redirect(url_for("home"))

if __name__ == "__main__":
    app.run(debug=True)