from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from ldap3 import Server, Connection, ALL
import os
import ssl

app = Flask(__name__)
app.secret_key = os.urandom(24)

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

# --- AD CONFIG ---
AD_SERVER = "ldap://your-ad-server.example.com"
BASE_DN = "DC=yourdomain,DC=com"
REQUIRED_GROUP_DN = "CN=MyAppUsers,OU=Groups,DC=yourdomain,DC=com"

# --- SSL CONFIG ---
CERT_FILE = "cert.pem"
KEY_FILE = "key.pem"

# --- USERS (Temporary in-memory store) ---
users = {}

class User(UserMixin):
    def __init__(self, username, dn, display_name):
        self.id = username
        self.dn = dn
        self.display_name = display_name

@login_manager.user_loader
def load_user(user_id):
    return users.get(user_id)

# --- ROUTES ---

@app.route("/")
@login_required
def index():
    return f"Welcome, {current_user.display_name}! <a href='/logout'>Logout</a>"

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = ldap_authenticate(username, password)

        if user:
            login_user(user)
            return redirect(url_for("index"))
        else:
            flash("Invalid credentials or unauthorized group membership.", "danger")

    return """
        <form method="post">
            <h2>Login</h2>
            <label>Username:</label><br>
            <input name="username"><br>
            <label>Password:</label><br>
            <input name="password" type="password"><br><br>
            <input type="submit" value="Login">
        </form>
    """

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

# --- LDAP AUTH ---

def ldap_authenticate(username, password):
    bind_user = os.getenv("LDAP_BIND_USER")
    bind_pass = os.getenv("LDAP_BIND_PASS")

    if not bind_user or not bind_pass:
        print("LDAP bind credentials not set in environment.")
        return None

    server = Server(AD_SERVER, get_info=ALL)

    # Step 1: Bind with service account
    try:
        conn = Connection(server, user=bind_user, password=bind_pass, auto_bind=True)
    except Exception as e:
        print("Service bind failed:", e)
        return None

    # Step 2: Search for user DN
    search_filter = f"(sAMAccountName={username})"
    if not conn.search(BASE_DN, search_filter, attributes=["distinguishedName", "displayName", "memberOf"]):
        print("User not found in AD")
        return None

    user_entry = conn.entries[0]
    user_dn = user_entry.distinguishedName.value
    display_name = user_entry.displayName.value or username
    groups = user_entry.memberOf.values if user_entry.memberOf else []

    # Step 3: Group membership check
    if REQUIRED_GROUP_DN not in groups:
        print("User is not in required group.")
        return None

    # Step 4: Try user bind
    try:
        user_conn = Connection(server, user=user_dn, password=password, auto_bind=True)
    except Exception as e:
        print("User bind failed:", e)
        return None

    user = User(username, user_dn, display_name)
    users[username] = user
    return user

# --- MAIN ---

if __name__ == "__main__":
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    app.run(host="0.0.0.0", port=443, ssl_context=context)
