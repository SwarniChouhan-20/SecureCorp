"""
SecureCorp Employee Portal -- INTENTIONALLY VULNERABLE Flask app
===================================================================
Built for local VAPT / pentest-lab practice ONLY.
Run it in an isolated VM or host-only network and attack it from Kali.
Do NOT deploy this anywhere reachable from the internet.

Storage: plain data.json (no database), see data.json next to this file.

10 intentional vulnerabilities, each marked "VULN #n" in the code below:
  1. Command Injection        -> /tools/ping
  2. Stored XSS                -> /notes
  3. IDOR                      -> /profile/<id>
  4. Broken Authentication     -> login + forgeable session cookie
  5. Path Traversal / LFI      -> /files/<filename>
  6. Insecure Deserialization  -> /settings/import  (pickle.loads on user input)
  7. Mass Assignment / Priv-Esc -> /profile/edit    (client sets its own "role")
  8. Open Redirect              -> /login?next=...
  9. SSRF (+ LFI via file://)   -> /tools/webhook
 10. CSRF (no anti-CSRF tokens anywhere) -> every POST form in the app

See README.md for exploitation walkthroughs using Kali tools.
"""

import os
import json
import base64
import pickle
import subprocess
import urllib.request
from flask import Flask, request, redirect, url_for, make_response, abort

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_FILE = os.path.join(BASE_DIR, "data.json")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")


# ---------------------------------------------------------------- storage --
def load_data():
    with open(DATA_FILE, "r") as f:
        return json.load(f)


def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=2)


def find_user(data, username):
    for u in data["users"]:
        if u["username"] == username:
            return u
    return None


# ------------------------------------------------------- VULN #4 : auth ---
# Broken Authentication:
#   - Passwords are stored and compared in PLAINTEXT (data.json).
#   - The "session" cookie is just base64(username) with no signature,
#     no expiry, and no server-side session store. Flask's signed
#     session (app.secret_key) is never used, so anyone can forge a
#     valid cookie for ANY user -- including admin -- without ever
#     knowing their password.
def current_user():
    token = request.cookies.get("session")
    if not token:
        return None
    try:
        username = base64.b64decode(token).decode()
    except Exception:
        return None
    return find_user(load_data(), username)


def login_required(view):
    def wrapped(*args, **kwargs):
        if current_user() is None:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    wrapped.__name__ = view.__name__
    return wrapped


# ------------------------------------------------------------- templates --
BASE_STYLE = """
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');
:root{
  --bg:#eef2fb; --card:#ffffff; --ink:#0f1b33; --muted:#64748b;
  --blue-900:#0a1f4d; --blue-800:#123a7a; --blue-700:#1947a3; --blue-600:#2563eb;
  --blue-500:#3b82f6; --blue-400:#60a5fa; --blue-100:#dbe8ff; --blue-50:#f0f6ff;
  --line:#e3e9f7; --danger:#dc2626; --ok:#16a34a; --warn:#d97706;
  --radius:14px; --shadow:0 1px 2px rgba(15,27,51,.04), 0 10px 24px -14px rgba(15,27,51,.12);
}
*{box-sizing:border-box}
html,body{height:100%}
body{
  font-family:"Inter","Segoe UI",-apple-system,Roboto,Arial,sans-serif;
  background:
    radial-gradient(900px 500px at 100% -10%, #e3ecff 0%, transparent 60%),
    radial-gradient(700px 400px at -10% 110%, #e8f0ff 0%, transparent 55%),
    var(--bg);
  color:var(--ink); margin:0; -webkit-font-smoothing:antialiased;
}
a{color:var(--blue-600); text-decoration:none}
a:hover{text-decoration:underline}
h1,h2,h3{margin-top:0; letter-spacing:-.015em; font-weight:700}
h3{font-size:15px; color:var(--blue-900); text-transform:uppercase; letter-spacing:.04em; font-size:12.5px; margin-bottom:14px}
.card{
  background:var(--card); border:1px solid var(--line); border-radius:var(--radius);
  padding:22px 24px; margin:16px 0; box-shadow:var(--shadow);
  transition:box-shadow .2s, transform .2s;
}
.card.hoverable:hover{box-shadow:0 1px 2px rgba(15,27,51,.06), 0 16px 30px -14px rgba(25,71,163,.22); transform:translateY(-1px)}
.field{margin-bottom:17px}
.field:last-of-type{margin-bottom:0}
label{font-size:12px; font-weight:700; color:var(--blue-700); display:block;
  margin:0 0 7px; text-transform:uppercase; letter-spacing:.05em}
input,textarea,select{
  width:100%; padding:12px 14px; border:1.5px solid var(--line);
  border-radius:10px; font-size:14px; background:#f8fafe; color:var(--ink);
  font-family:inherit; transition:border-color .15s, box-shadow .15s, background .15s;
}
textarea{resize:vertical}
input:focus,textarea:focus,select:focus{
  outline:none; border-color:var(--blue-600); background:#fff;
  box-shadow:0 0 0 4px var(--blue-100);
}
input::placeholder,textarea::placeholder{color:#9aa6bf}
button, .btn{
  background:linear-gradient(135deg,var(--blue-600),var(--blue-700));
  color:#fff; border:none; padding:12px 22px; border-radius:10px;
  font-size:14px; font-weight:700; cursor:pointer; letter-spacing:.2px;
  box-shadow:0 2px 6px rgba(25,71,163,.35); transition:filter .15s, transform .1s;
}
button:hover{filter:brightness(1.08)}
button:active{transform:translateY(1px)}
button.secondary,.btn.secondary{
  background:#fff; color:var(--blue-700); border:1.5px solid var(--blue-100);
  box-shadow:none; display:inline-block;
}
button.secondary:hover,.btn.secondary:hover{background:var(--blue-50)}
button.danger{background:linear-gradient(135deg,#ef4444,#b91c1c)}
.flag{color:#991b1b; font-size:13.5px; background:#fef2f2; border:1px solid #fecaca;
  padding:11px 14px; border-radius:10px; margin:0 0 16px; display:flex; gap:8px; align-items:center}
.warn-banner{
  background:linear-gradient(135deg,#fff7ed,#fef3c7); border:1px solid #fde68a;
  color:#92400e; font-size:12.5px; padding:10px 14px; border-radius:10px; margin:0 0 16px;
}
.hint{font-size:12.5px; color:var(--muted); margin-top:10px; line-height:1.5}
pre{
  background:#081021; color:#9fd4ff; padding:18px; border-radius:12px;
  overflow-x:auto; font-size:13px; line-height:1.6;
  border:1px solid #1b2b52; font-family:"JetBrains Mono",ui-monospace,Consolas,monospace;
}
.badge{
  display:inline-block; font-size:10.5px; font-weight:800; padding:4px 11px;
  border-radius:999px; background:var(--blue-100); color:var(--blue-700);
  text-transform:uppercase; letter-spacing:.06em;
}
.badge.admin{background:linear-gradient(135deg,#dcfce7,#bbf7d0); color:#15803d}
.badge.warn{background:#fef3c7; color:#92400e}
.divider{height:1px; background:var(--line); margin:18px 0}
.empty{color:var(--muted); font-size:13.5px; text-align:center; padding:24px 10px}
.section-label{font-size:11px; font-weight:700; color:var(--muted); text-transform:uppercase;
  letter-spacing:.07em; margin:0 0 10px}
"""

LOGIN_PAGE = """<!doctype html>
<html><head><title>Sign in · SecureCorp</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
{style}
body{{display:flex; min-height:100vh; background:var(--blue-900)}}
.side{{
  flex:1.15; position:relative; overflow:hidden;
  background:
    radial-gradient(600px 400px at 85% 10%, rgba(96,165,250,.35), transparent 60%),
    radial-gradient(500px 350px at 10% 90%, rgba(59,130,246,.25), transparent 55%),
    linear-gradient(160deg,var(--blue-900),#0e2d68 55%,var(--blue-700));
  color:#fff; padding:56px; display:flex; flex-direction:column;
  justify-content:space-between;
}}
.side::before{{
  content:""; position:absolute; inset:0; opacity:.5; pointer-events:none;
  background-image:
    linear-gradient(rgba(255,255,255,.045) 1px, transparent 1px),
    linear-gradient(90deg, rgba(255,255,255,.045) 1px, transparent 1px);
  background-size:42px 42px;
  -webkit-mask-image:radial-gradient(circle at 70% 20%, black, transparent 65%);
          mask-image:radial-gradient(circle at 70% 20%, black, transparent 65%);
}}
.side .logo{{font-size:20px; font-weight:800; display:flex; align-items:center; gap:10px; position:relative}}
.side .logo .mark{{
  width:34px; height:34px; border-radius:10px; display:flex; align-items:center; justify-content:center;
  background:linear-gradient(135deg,var(--blue-400),#93c5fd); font-size:17px; color:var(--blue-900);
}}
.side .pitch{{position:relative}}
.side h1{{font-size:36px; line-height:1.22; max-width:400px; margin-top:36px; font-weight:800}}
.side p{{color:#bcd3ff; max-width:380px; line-height:1.65; font-size:14.5px; margin-top:14px}}
.feature{{display:flex; align-items:center; gap:10px; color:#cfe0ff; font-size:13px; margin-top:12px}}
.feature .ic{{width:22px; height:22px; border-radius:7px; background:rgba(255,255,255,.12);
  display:flex; align-items:center; justify-content:center; font-size:12px; flex-shrink:0}}
.side .meta{{font-size:12px; color:#7fa0de; position:relative}}
.formside{{
  flex:1; display:flex; align-items:center; justify-content:center; padding:40px; background:var(--bg);
}}
.formcard{{width:100%; max-width:368px}}
.formcard .badge-top{{margin-bottom:14px}}
.formcard h2{{font-size:25px}}
.formcard .sub{{color:var(--muted); font-size:14px; margin-bottom:26px}}
.demo{{
  background:linear-gradient(135deg,var(--blue-50),#fff); border:1px solid var(--blue-100); border-radius:12px;
  padding:14px 16px; font-size:12.5px; color:var(--blue-700); margin-top:20px; line-height:1.8;
}}
.demo .ttl{{font-weight:800; color:var(--blue-900); text-transform:uppercase; font-size:10.5px; letter-spacing:.06em; margin-bottom:4px}}
.demo code{{background:#fff; border:1px solid var(--blue-100); padding:1px 6px; border-radius:5px; font-family:"JetBrains Mono",monospace}}
@media (max-width:860px){{ .side{{display:none}} }}
</style></head>
<body>
<div class="side">
  <div class="logo"><span class="mark">🛡️</span> SecureCorp</div>
  <div class="pitch">
    <h1>Welcome back to the employee portal.</h1>
    <p>Internal tools for diagnostics, team notes, file sharing, and account settings — all in one place.</p>
    <div class="feature"><span class="ic">📡</span> Network diagnostics on demand</div>
    <div class="feature"><span class="ic">🗒️</span> Team notes, shared instantly</div>
    <div class="feature"><span class="ic">📁</span> Company file library</div>
  </div>
  <div class="meta">© SecureCorp · Internal use only · v1.0</div>
</div>
<div class="formside">
  <div class="formcard">
    <span class="badge badge-top">Employee access</span>
    <h2>Sign in to your account</h2>
    <div class="sub">Enter your credentials to continue</div>
    {error_html}
    <form method="post" action="/login{next_qs}">
      <div class="field">
        <label>Username</label>
        <input name="username" placeholder="e.g. jdoe" autofocus>
      </div>
      <div class="field">
        <label>Password</label>
        <input name="password" type="password" placeholder="••••••••">
      </div>
      <button type="submit" style="width:100%">Sign in →</button>
    </form>
    <div class="demo">
      <div class="ttl">Demo accounts</div>
      <code>admin / admin123</code><br><code>jdoe / password1</code><br><code>asmith / letmein99</code>
    </div>
  </div>
</div>
</body></html>"""

NAV_ITEMS = [
    ("dashboard", "/dashboard", "🏠", "Dashboard"),
    ("notes",     "/notes",     "🗒️", "Team Notes"),
    ("tools",     "/tools/ping", "📡", "Network Tool"),
    ("webhook",   "/tools/webhook", "🔗", "Webhook Tool"),
    ("files",     "/files/handbook.txt", "📁", "Files"),
    ("settings",  "/settings/import", "⚙️", "Settings"),
]

APP_SHELL = """<!doctype html>
<html><head><title>{title} · SecureCorp</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
{style}
body{{display:flex}}
.sidebar{{
  width:248px; flex-shrink:0; min-height:100vh;
  background:linear-gradient(185deg,var(--blue-900),var(--blue-800) 85%);
  color:#dfe9ff; padding:20px 14px; display:flex; flex-direction:column;
  box-shadow:4px 0 24px -12px rgba(0,0,0,.35);
}}
.sidebar .logo{{display:flex; align-items:center; gap:10px; font-weight:800; font-size:16.5px;
  color:#fff; padding:8px 10px 26px}}
.sidebar .logo .mark{{
  width:28px; height:28px; border-radius:8px; display:flex; align-items:center; justify-content:center;
  background:linear-gradient(135deg,var(--blue-400),#93c5fd); font-size:14px;
}}
.sidebar .section-tag{{font-size:10px; font-weight:700; color:#6f8dcb; text-transform:uppercase;
  letter-spacing:.09em; padding:0 12px 8px}}
.sidebar nav{{display:flex; flex-direction:column; gap:2px; flex:1}}
.sidebar nav a{{
  text-decoration:none; color:#c3d4f7; font-size:13.5px; padding:10px 12px;
  border-radius:9px; display:flex; align-items:center; gap:11px; transition:background .15s, color .15s;
  font-weight:500;
}}
.sidebar nav a span:first-child{{font-size:15px; width:18px; text-align:center}}
.sidebar nav a:hover{{background:rgba(255,255,255,.08); color:#fff; text-decoration:none}}
.sidebar nav a.active{{background:rgba(255,255,255,.16); color:#fff; font-weight:700;
  box-shadow:inset 3px 0 0 var(--blue-400)}}
.sidebar .userbox{{
  border-top:1px solid rgba(255,255,255,.12); padding-top:14px; margin-top:10px;
  display:flex; align-items:center; gap:10px; font-size:13px;
}}
.avatar{{
  width:34px; height:34px; border-radius:50%; background:linear-gradient(135deg,var(--blue-500),var(--blue-700));
  color:#fff; display:flex; align-items:center; justify-content:center; font-weight:700; font-size:13px; flex-shrink:0;
  border:2px solid rgba(255,255,255,.25);
}}
.sidebar .userbox .name{{font-weight:700; color:#fff}}
.sidebar .userbox .role{{color:#9fb6e6; font-size:11px; text-transform:capitalize}}
.sidebar .logout{{color:#9fb6e6; font-size:11.5px; text-decoration:none; margin-left:auto; padding:4px 7px;
  border-radius:6px; transition:background .15s}}
.sidebar .logout:hover{{background:rgba(255,255,255,.1); color:#fff; text-decoration:none}}
.main{{flex:1; min-height:100vh}}
.header{{
  background:rgba(255,255,255,.85); backdrop-filter:blur(6px);
  border-bottom:1px solid var(--line); padding:20px 36px;
  display:flex; align-items:center; justify-content:space-between; position:sticky; top:0; z-index:5;
}}
.header h1{{font-size:20px; margin:0}}
.header .crumbs{{font-size:12px; color:var(--muted); margin-bottom:3px}}
.content{{max-width:860px; margin:0 auto; padding:30px 32px 70px}}
footer{{text-align:center; color:var(--muted); font-size:11.5px; padding:16px}}
</style></head>
<body>
<div class="sidebar">
  <div class="logo"><span class="mark">🛡️</span> SecureCorp</div>
  <div class="section-tag">Workspace</div>
  <nav>{nav_html}</nav>
  <div class="userbox">
    <div class="avatar">{initials}</div>
    <div>
      <div class="name">{username}</div>
      <div class="role">{role}</div>
    </div>
    <a class="logout" href="/logout">Log out</a>
  </div>
</div>
<div class="main">
  <div class="header">
    <div><div class="crumbs">SecureCorp / {title}</div><h1>{title}</h1></div>
  </div>
  <div class="content">@@BODY@@</div>
  <footer>SecureCorp Portal — internal use only (intentionally vulnerable lab build)</footer>
</div>
</body></html>"""


def render_page(title, body, active=None):
    user = current_user()
    nav_html = "".join(
        f'<a href="{href}" class="{"active" if key == active else ""}">'
        f'<span>{icon}</span><span>{label}</span></a>'
        for key, href, icon, label in NAV_ITEMS
    )
    initials = (user["username"][:2].upper() if user else "??")
    html = APP_SHELL.format(
        title=title, style=BASE_STYLE, nav_html=nav_html,
        initials=initials,
        username=user["username"] if user else "",
        role=user["role"] if user else "",
    )
    return html.replace("@@BODY@@", body)


# ---------------------------------------------------------------- routes --
@app.route("/")
def index():
    return redirect(url_for("dashboard") if current_user() else url_for("login"))


# ------------------------------------------------------------ VULN #8 ----
# Open Redirect:
#   The "next" parameter is trusted completely. After a successful login
#   the app redirects straight to whatever URL the client supplied, with
#   no check that it's a local/relative path. Attackers send victims a
#   link like /login?next=https://evil-phish.example and, after the
#   victim logs in on the REAL site, they land on the attacker's page --
#   great for credential-harvesting follow-up or OAuth-token theft.
@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    next_url = request.values.get("next", "")
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        data = load_data()
        user = find_user(data, username)
        # VULN #4 (cont.): plaintext comparison, no hashing, no lockout/rate-limit
        if user and user["password"] == password:
            destination = next_url if next_url else url_for("dashboard")
            resp = make_response(redirect(destination))  # VULN #8: unvalidated redirect
            token = base64.b64encode(username.encode()).decode()
            resp.set_cookie("session", token)  # unsigned, forgeable
            return resp
        error = "Invalid credentials."
    error_html = f'<div class="flag">⚠ {error}</div>' if error else ""
    next_qs = f"?next={next_url}" if next_url else ""
    return LOGIN_PAGE.format(style=BASE_STYLE, error_html=error_html, next_qs=next_qs)


@app.route("/logout")
def logout():
    resp = make_response(redirect(url_for("login")))
    resp.delete_cookie("session")
    return resp


@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    data = load_data()
    note_count = len(data["notes"])
    user_count = len(data["users"])
    badge_cls = "badge admin" if user["role"] == "admin" else "badge"
    body = f"""
    <div class="card hoverable" style="background:linear-gradient(135deg,var(--blue-700),var(--blue-600) 70%);
         color:#fff; border:none; position:relative; overflow:hidden">
      <div style="font-size:13px;color:#cfe0ff">Good to see you</div>
      <h2 style="color:#fff; font-size:26px; margin-top:2px">{user['username']}</h2>
      <span class="{badge_cls}" style="background:rgba(255,255,255,.2);color:#fff;margin-top:6px;display:inline-block">{user['role']}</span>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
      <div class="card hoverable">
        <div class="section-label" style="margin:0">Colleagues</div>
        <div style="font-size:28px;font-weight:800;margin-top:6px;color:var(--blue-900)">{user_count}</div>
      </div>
      <div class="card hoverable">
        <div class="section-label" style="margin:0">Notes posted</div>
        <div style="font-size:28px;font-weight:800;margin-top:6px;color:var(--blue-900)">{note_count}</div>
      </div>
    </div>
    <div class="card hoverable">
      <h3>Your profile</h3>
      <p style="margin:0 0 4px">View or edit your details at <a href="/profile/{user['id']}">/profile/{user['id']}</a></p>
      <p class="hint" style="margin-top:4px">Try changing the number in that URL...</p>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
      <a class="card hoverable" style="text-decoration:none;display:block" href="/tools/webhook">
        <div style="font-size:20px">🔗</div>
        <h3 style="margin-top:10px">Webhook Tool</h3>
        <p class="hint" style="margin:0">Preview a URL's response before sharing it</p>
      </a>
      <a class="card hoverable" style="text-decoration:none;display:block" href="/settings/import">
        <div style="font-size:20px">⚙️</div>
        <h3 style="margin-top:10px">Settings</h3>
        <p class="hint" style="margin:0">Import a saved workspace backup</p>
      </a>
    </div>
    """
    return render_page("Dashboard", body, active="dashboard")


# ------------------------------------------------------------ VULN #3 ----
# IDOR (Insecure Direct Object Reference):
#   Any logged-in user can view ANY other user's full record -- including
#   their plaintext password and secret_note -- just by changing the id
#   in the URL. There is no check that the requested id belongs to the
#   caller (or that the caller is an admin).
@app.route("/profile/<int:user_id>")
@login_required
def profile(user_id):
    data = load_data()
    target = next((u for u in data["users"] if u["id"] == user_id), None)
    if not target:
        abort(404)
    badge_cls = "badge admin" if target["role"] == "admin" else "badge"
    initials = target["username"][:2].upper()
    me = current_user()
    edit_btn = (
        f'<a class="btn secondary" style="margin-left:auto" href="/profile/edit">Edit profile ✎</a>'
        if me and me["id"] == target["id"] else ""
    )
    body = f"""
    <div class="card hoverable" style="display:flex;align-items:center;gap:18px">
      <div class="avatar" style="width:60px;height:60px;font-size:20px">{initials}</div>
      <div>
        <h2 style="margin:0">{target['username']}</h2>
        <span class="{badge_cls}" style="margin-top:4px;display:inline-block">{target['role']}</span>
      </div>
      {edit_btn}
    </div>
    <div class="card">
      <h3>Account details</h3>
      <table style="width:100%;border-collapse:collapse;font-size:14px">
        <tr><td style="padding:11px 0;color:var(--muted);width:160px">User ID</td><td>{target['id']}</td></tr>
        <tr style="border-top:1px solid var(--line)"><td style="padding:11px 0;color:var(--muted)">Email</td><td>{target['email']}</td></tr>
        <tr style="border-top:1px solid var(--line)"><td style="padding:11px 0;color:var(--muted)">Password</td><td>{target['password']}</td></tr>
        <tr style="border-top:1px solid var(--line)"><td style="padding:11px 0;color:var(--muted)">Private note</td><td>{target['secret_note']}</td></tr>
      </table>
    </div>
    """
    return render_page(f"Profile · {target['username']}", body, active="dashboard")


# ------------------------------------------------------------ VULN #7 ----
# Mass Assignment / Privilege Escalation:
#   The edit-profile form blindly applies every field the client sends
#   (including "role") onto the current user's record. There is no
#   allow-list of editable fields, so a normal employee can simply add a
#   hidden "role=admin" field to the POST and promote themselves.
@app.route("/profile/edit", methods=["GET", "POST"])
@login_required
def profile_edit():
    user = current_user()
    data = load_data()
    target = next(u for u in data["users"] if u["id"] == user["id"])
    saved = False
    if request.method == "POST":
        for field, value in request.form.items():  # VULN #7: no allow-list
            if field in target:
                target[field] = value
        save_data(data)
        saved = True
    saved_html = '<div class="warn-banner">✓ Profile updated.</div>' if saved else ""
    body = f"""
    {saved_html}
    <div class="card">
      <h3>Edit your profile</h3>
      <form method="post">
        <div class="field"><label>Email</label><input name="email" value="{target['email']}"></div>
        <div class="field"><label>Password</label><input name="password" value="{target['password']}"></div>
        <div class="field"><label>Private note</label><input name="secret_note" value="{target['secret_note']}"></div>
        <input type="hidden" name="role" value="{target['role']}">
        <button type="submit">Save changes</button>
      </form>
      <p class="hint">The role field is sent as a hidden input — the server trusts whatever
      value arrives for it, not just email/password/secret_note.</p>
    </div>
    """
    return render_page("Edit Profile", body, active="dashboard")


# ------------------------------------------------------------ VULN #2 ----
# Stored XSS:
#   Note bodies are written straight into the HTML response with no
#   escaping and no sanitization. A note containing <script> or an
#   <img onerror=...> tag executes in every other user's browser who
#   views /notes.
@app.route("/notes", methods=["GET", "POST"])
@login_required
def notes():
    data = load_data()
    if request.method == "POST":
        body_text = request.form.get("body", "")
        new_id = (max((n["id"] for n in data["notes"]), default=0)) + 1
        data["notes"].append({
            "id": new_id,
            "author": current_user()["username"],
            "body": body_text,  # stored as-is, no sanitization
        })
        save_data(data)
        return redirect(url_for("notes"))

    if data["notes"]:
        items = ""
        for n in reversed(data["notes"]):
            initials = n["author"][:2].upper()
            # VULN #2 (cont.): n["body"] inserted unescaped -> stored XSS
            items += f"""
            <div class="card hoverable" style="display:flex;gap:13px;align-items:flex-start">
              <div class="avatar" style="width:34px;height:34px;font-size:12px;flex-shrink:0">{initials}</div>
              <div style="flex:1">
                <div style="font-weight:700;color:var(--blue-700);font-size:13.5px">{n['author']}</div>
                <div style="margin-top:5px;line-height:1.55">{n['body']}</div>
              </div>
            </div>"""
    else:
        items = '<div class="empty">No notes yet — be the first to post one.</div>'

    body = f"""
    <div class="card">
      <h3>Post a note</h3>
      <form method="post">
        <div class="field">
          <textarea name="body" rows="3" placeholder="Share something with the team..."></textarea>
        </div>
        <button type="submit">Post note</button>
      </form>
    </div>
    <div class="section-label">Recent activity</div>
    {items}
    """
    return render_page("Team Notes", body, active="notes")


# ------------------------------------------------------------ VULN #1 ----
# Command Injection:
#   The "host" field is concatenated straight into a shell command.
#   Anything after the host (e.g. `; whoami` or `$(id)` or `&& nc ...`)
#   is executed by the shell with the privileges of the Flask process.
@app.route("/tools/ping", methods=["GET", "POST"])
@login_required
def ping_tool():
    output = ""
    if request.method == "POST":
        host = request.form.get("host", "")
        cmd = "ping -c 1 " + host  # VULN #1: unsanitized, shell=True
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True,
                                     text=True, timeout=5)
            output = (result.stdout or "") + (result.stderr or "")
        except Exception as e:
            output = str(e)

    output_html = (
        f'<div style="margin-top:6px"><div class="section-label">Output</div><pre>{output}</pre></div>'
        if output else ""
    )
    body = f"""
    <div class="card">
      <p class="hint" style="margin-top:0">Sends one ICMP ping to the host you enter.</p>
      <form method="post">
        <div class="field"><label>Host</label><input name="host" placeholder="e.g. 127.0.0.1"></div>
        <button type="submit">Run ping ▶</button>
      </form>
      {output_html}
    </div>
    """
    return render_page("Network Diagnostic Tool", body, active="tools")


# ------------------------------------------------------------ VULN #9 ----
# SSRF (Server-Side Request Forgery) -- with a bonus file:// LFI path:
#   The server fetches whatever URL the client supplies with no
#   allow-list, no scheme restriction, and no block on internal/loopback
#   addresses. An attacker can make the SERVER itself issue requests to
#   internal-only services (e.g. http://127.0.0.1:5000/profile/1, or any
#   other host the server can reach but the attacker normally can't), or
#   even read local files via a file:// URL, since urllib happily
#   follows that scheme too.
@app.route("/tools/webhook", methods=["GET", "POST"])
@login_required
def webhook_tool():
    output = ""
    url = ""
    if request.method == "POST":
        url = request.form.get("url", "")
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:  # VULN #9: unsanitized
                output = resp.read(4000).decode(errors="replace")
        except Exception as e:
            output = f"Error: {e}"
    output_html = (
        f'<div style="margin-top:6px"><div class="section-label">Response</div><pre>{output}</pre></div>'
        if output else ""
    )
    body = f"""
    <div class="card">
      <p class="hint" style="margin-top:0">Fetches a URL server-side and previews the response — handy for checking a webhook endpoint before you save it.</p>
      <form method="post">
        <div class="field"><label>URL</label><input name="url" value="{url}" placeholder="https://example.com/webhook"></div>
        <button type="submit">Fetch ▶</button>
      </form>
      {output_html}
    </div>
    """
    return render_page("Webhook Tool", body, active="webhook")


# ------------------------------------------------------------ VULN #6 ----
# Insecure Deserialization:
#   "Import backup" takes a base64 blob and feeds it straight into
#   pickle.loads(). Pickle can execute arbitrary code during
#   deserialization via a crafted __reduce__ method, so this one upload
#   box is a full remote-code-execution primitive -- no login bypass
#   needed beyond having *a* valid session.
@app.route("/settings/import", methods=["GET", "POST"])
@login_required
def settings_import():
    result = ""
    if request.method == "POST":
        blob = request.form.get("data", "")
        try:
            raw = base64.b64decode(blob)
            obj = pickle.loads(raw)  # VULN #6: deserializing untrusted input
            result = f"Imported object: {obj!r}"
        except Exception as e:
            result = f"Error: {e}"
    result_html = f'<div class="warn-banner">{result}</div>' if result else ""
    body = f"""
    <div class="card">
      <h3>Import workspace backup</h3>
      <p class="hint" style="margin-top:0">Paste a base64-encoded backup blob exported from another SecureCorp workspace.</p>
      {result_html}
      <form method="post">
        <div class="field"><label>Backup data (base64)</label><textarea name="data" rows="4" placeholder="gASVKwAAAAAAAACMCHBvc2l4lIwGc3lzdGVtlJOUjAJpZJSFlFKULg=="></textarea></div>
        <button type="submit">Import</button>
      </form>
    </div>
    """
    return render_page("Settings", body, active="settings")


# ------------------------------------------------------------ VULN #5 ----
# Path Traversal / LFI:
#   The filename from the URL is joined onto UPLOAD_DIR with no
#   sanitization (no os.path.basename, no check that the resolved path
#   stays inside UPLOAD_DIR), so "../../../../etc/passwd" escapes the
#   uploads folder entirely.
@app.route("/files/<path:filename>")
@login_required
def files(filename):
    target = os.path.join(UPLOAD_DIR, filename)  # VULN #5: no sanitization
    try:
        with open(target, "r", errors="replace") as f:
            content = f.read()
    except Exception as e:
        content = f"Error: {e}"
    body = f"""
    <div class="card">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:12px">
        <span style="font-size:20px">📄</span>
        <span style="font-weight:600">{filename}</span>
      </div>
      <pre>{content}</pre>
    </div>
    <p class="hint">Browse another file by editing the path in the URL, e.g. /files/handbook.txt</p>
    """
    return render_page("File Viewer", body, active="files")


if __name__ == "__main__":
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    app.run(host="0.0.0.0", port=5001, debug=True)