import os, re, socket, ipaddress, secrets, smtplib, subprocess, platform, threading, time, json, sys, shutil, ctypes
from email.message import EmailMessage
from urllib.parse import urlparse
from functools import wraps
import pyodbc, nmap
try:
    import pyperclip
    CLIP_OK = True
except Exception:
    pyperclip, CLIP_OK = None, False
from flask import Flask, request, session, redirect, render_template, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from config import *

app = Flask(__name__)
app.secret_key = SECRET_KEY

# ======================= DATABASE =======================
def pick_driver():
    have = pyodbc.drivers()
    if SQL_DRIVER in have:
        return SQL_DRIVER
    odbc = sorted([d for d in have if d.startswith("ODBC Driver") and "SQL Server" in d], reverse=True)
    if odbc:
        return odbc[0]
    legacy = [d for d in have if "SQL Server" in d]
    return legacy[0] if legacy else SQL_DRIVER

DRIVER = pick_driver()

SERVER = SQL_SERVER

def conn_str(db, server=None):
    auth = f"UID={SQL_USER};PWD={SQL_PASSWORD};" if SQL_USER else "Trusted_Connection=yes;"
    return f"DRIVER={{{DRIVER}}};SERVER={server or SERVER};DATABASE={db};{auth}TrustServerCertificate=yes;"

def resolve_server():
    """If SQL_SERVER is AUTO (or still the placeholder), try the usual local SQL Server names."""
    global SERVER
    want = str(SQL_SERVER).strip()
    if want and want.upper() != "AUTO" and not want.upper().startswith("YOUR_"):
        SERVER = want
        return
    host = socket.gethostname()
    tries = [r".\SQLEXPRESS", r"localhost\SQLEXPRESS", host + r"\SQLEXPRESS", "localhost", ".", host,
             r"(local)\SQLEXPRESS", "127.0.0.1"]
    for cand in dict.fromkeys(tries):
        try:
            pyodbc.connect(conn_str("master", cand), timeout=4).close()
            SERVER = cand
            print(f"[PhishNet] SQL Server found automatically: {cand}")
            return
        except Exception:
            continue
    raise RuntimeError("No SQL Server was found automatically. Open config.py and set SQL_SERVER to the name "
                       "shown in the SSMS login window, for example DESKTOP-ABC123\\SQLEXPRESS")

def q(sql, args=(), fetch=False, one=False):
    conn = pyodbc.connect(conn_str(SQL_DATABASE))
    try:
        cur = conn.cursor()
        cur.execute(sql, args)
        if fetch:
            cols = [c[0] for c in cur.description]
            rows = [dict(zip(cols, r)) for r in cur.fetchall()]
            return (rows[0] if rows else None) if one else rows
        conn.commit()
    finally:
        conn.close()

def init_db():
    c = pyodbc.connect(conn_str("master"), autocommit=True)
    c.cursor().execute(f"IF DB_ID('{SQL_DATABASE}') IS NULL CREATE DATABASE [{SQL_DATABASE}]")
    c.close()
    tables = [
        """IF OBJECT_ID('users') IS NULL CREATE TABLE users(
           id INT IDENTITY PRIMARY KEY, username NVARCHAR(50) UNIQUE NOT NULL,
           email NVARCHAR(120) NOT NULL, password_hash NVARCHAR(255) NOT NULL,
           api_key NVARCHAR(64), auto_scan BIT DEFAULT 0, created_at DATETIME DEFAULT GETDATE())""",
        """IF OBJECT_ID('scans') IS NULL CREATE TABLE scans(
           id INT IDENTITY PRIMARY KEY, user_id INT, target NVARCHAR(500), kind NVARCHAR(20),
           score INT, level NVARCHAR(10), reasons NVARCHAR(MAX), created_at DATETIME DEFAULT GETDATE())""",
        """IF OBJECT_ID('alerts') IS NULL CREATE TABLE alerts(
           id INT IDENTITY PRIMARY KEY, user_id INT, message NVARCHAR(1000),
           seen BIT DEFAULT 0, created_at DATETIME DEFAULT GETDATE())""",
        """IF OBJECT_ID('blocked') IS NULL CREATE TABLE blocked(
           id INT IDENTITY PRIMARY KEY, user_id INT, kind NVARCHAR(10), value NVARCHAR(200),
           created_at DATETIME DEFAULT GETDATE())""",
        """IF OBJECT_ID('net_scans') IS NULL CREATE TABLE net_scans(
           id INT IDENTITY PRIMARY KEY, user_id INT, scan_id BIGINT, host NVARCHAR(50),
           ports NVARCHAR(MAX), created_at DATETIME DEFAULT GETDATE())""",
    ]
    for t in tables:
        q(t)
    # upgrades for existing databases
    q("IF COL_LENGTH('users','live_protect') IS NULL ALTER TABLE users ADD live_protect BIT NULL")
    for name, tbl, cols in [("ix_scans_user", "scans", "user_id, id"), ("ix_alerts_user", "alerts", "user_id, id"),
                            ("ix_net_user", "net_scans", "user_id, scan_id"), ("ix_blocked_user", "blocked", "user_id, kind")]:
        q(f"IF NOT EXISTS(SELECT 1 FROM sys.indexes WHERE name='{name}') CREATE INDEX {name} ON {tbl}({cols})")

# ======================= EMAIL + ALERTS =======================
_recent = {}

MAIL_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mail_settings.json")   # optional, older versions
mail_status = {"ok": None, "msg": "No email sent yet.", "at": ""}

def mail_cfg():
    """Sender settings come from config.py (an old mail_settings.json, if present, is still honoured)."""
    c = {"host": SMTP_HOST, "port": SMTP_PORT, "user": SMTP_USER, "pw": SMTP_PASS}
    try:
        with open(MAIL_FILE, encoding="utf-8") as f:
            c.update({k: v for k, v in json.load(f).items() if v not in ("", None)})
    except Exception:
        pass
    c["pw"] = str(c["pw"]).replace(" ", "")      # Google shows app passwords with spaces
    c["port"] = int(c["port"])
    return c

def _send_mail(to, subject, body):
    """Send one email right now. Returns (ok, message) and remembers the result for the dashboard."""
    global mail_status
    def done(ok, msg):
        mail_status = {"ok": ok, "msg": msg, "at": time.strftime("%H:%M:%S")}
        if not ok:
            print("[PhishNet] Email problem:", msg)
        return ok, msg
    c = mail_cfg()
    if not (c["user"] and c["pw"]):
        print(f"\n[EMAIL not set up - printed instead]\nTo: {to}\nSubject: {subject}\n{body}\n")
        return done(False, "Sender email is not set up. Open config.py, fill SMTP_USER and SMTP_PASS "
                           "(Gmail address + App Password) and restart PhishNet.")
    last = ""
    for attempt in range(3):                       # a quick retry covers a short network hiccup
        try:
            m = EmailMessage()
            m["From"], m["To"], m["Subject"] = c["user"], to, subject
            m.set_content(body)
            if c["port"] == 465:
                srv = smtplib.SMTP_SSL(c["host"], 465, timeout=20)
            else:
                srv = smtplib.SMTP(c["host"], c["port"], timeout=20)
                srv.ehlo()
                srv.starttls()
                srv.ehlo()
            with srv:
                srv.login(c["user"], c["pw"])
                srv.send_message(m)
            return done(True, f"Email sent to {to}")
        except smtplib.SMTPAuthenticationError:
            return done(False, "Gmail rejected the login. Use a 16-character App Password (not your normal "
                               "password) in config.py and make sure 2-Step Verification is on.")
        except Exception as e:
            last = str(e)
            time.sleep(1)
    return done(False, f"Could not send the email: {last}")

def _mail_job(user, subject, message):
    ok, msg = _send_mail(user["email"], subject, message)
    k = (user["id"], "mailfail")
    if not ok and time.time() - _recent.get(k, 0) > 600:      # tell the user once in a while, inside the dashboard
        _recent[k] = time.time()
        try:
            q("INSERT INTO alerts(user_id,message) VALUES(?,?)", (user["id"], ("Email alert could not be sent. " + msg)[:1000]))
        except Exception:
            pass

def alert_user(user, subject, message, email_body=None, dedupe_key=None, dedupe_secs=0):
    """Email goes out immediately (own thread, started BEFORE the database write).
    Every alert is sent; dedupe_secs is only used to stop the browser extension re-reporting the very same page."""
    if dedupe_key and dedupe_secs:
        k = (user["id"], dedupe_key)
        if time.time() - _recent.get(k, 0) < dedupe_secs:
            return
        _recent[k] = time.time()
    threading.Thread(target=_mail_job, args=(user, f"[PhishNet] {subject}", email_body or message), daemon=True).start()
    try:
        q("INSERT INTO alerts(user_id,message) VALUES(?,?)", (user["id"], message[:1000]))
    except Exception as e:
        print("[PhishNet] Could not store alert:", e)

KIND_LABEL = {"url": "Link scanner", "message": "Message scanner", "clipboard": "Live protection (copied text)",
              "auto": "Browser extension (page you opened)"}
WEB_PORTS = {80: "HTTP", 443: "HTTPS", 8080: "HTTP alternate", 8443: "HTTPS alternate"}

def port_name(p):
    if p in RISKY_PORTS:
        return RISKY_PORTS[p]
    if p in WEB_PORTS:
        return WEB_PORTS[p]
    try:
        return socket.getservbyport(int(p), "tcp").upper()
    except Exception:
        return "unknown service"

def url_port(u):
    """Port a link will connect to: the one written in the link, otherwise 443 for https and 80 for http."""
    u = (u or "").strip()
    if not re.match(r'^[a-z]+://', u, re.I):
        u = "http://" + u
    try:
        p = urlparse(u)
        return p.port or (443 if p.scheme.lower() == "https" else 80)
    except Exception:
        return None

def now_str():
    return time.strftime("%Y-%m-%d %H:%M:%S")

def risk_email(kind, target, score, reasons, hits, bp):
    L = ["PHISHNET SECURITY ALERT", "=" * 44,
         "A HIGH-RISK link or message was detected and PhishNet has BLOCKED it.", "",
         f"Risk level   : HIGH ({score}/100)",
         f"Detected by  : {KIND_LABEL.get(kind, kind)}",
         f"Time         : {now_str()}", "",
         "WHAT WAS BLOCKED", "-" * 44]
    if hits:
        for h in hits[:6]:
            port = h["port"]
            L += [f"Domain       : {h['host']}",
                  f"Link         : {h['url'][:200]}",
                  f"Port         : {port} ({port_name(port)})" if port else "Port         : unknown",
                  "Blocked how  : domain is on your PhishNet block list (the browser extension stops the page)"
                  + (" - newly added now" if h.get("new") else " - was already on the list"),
                  ("Firewall     : this port is also blocked in your firewall" if port and str(port) in bp
                   else "Firewall     : web ports 80/443 are only reported, not firewalled, so your internet keeps working"
                   if port in (80, 443) else "Firewall     : port is not firewalled (you can block it from the Firewall tab)"),
                  ""]
        if len(hits) > 6:
            L += [f"...and {len(hits) - 6} more blocked link(s).", ""]
    else:
        L += [f"Message      : {target[:300]}", ""]
    L += ["WHY IT IS DANGEROUS", "-" * 44] + [f"- {x}" for x in reasons[:10]] + [""]
    L += ["WHAT TO DO", "-" * 44, "- Do not open the link or enter any details.", "- Never share OTPs or passwords.",
          "- Report it at cybercrime.gov.in.", "", "This alert was sent automatically by PhishNet."]
    return "\n".join(L)

def ports_email(host, own, network, blocked):
    L = ["PHISHNET SECURITY ALERT", "=" * 44,
         "Risky open port(s) were found by the network scan and PhishNet BLOCKED them.", "",
         f"Network      : {network}",
         f"Device       : {host}{' (this PC)' if own else ''}",
         f"Time         : {now_str()}", "",
         "WHAT WAS BLOCKED", "-" * 44]
    for b in blocked:
        L += [f"Port         : {b['port']} ({b['service']})",
              "Rule         : inbound traffic to this port on THIS PC is blocked" if own
              else f"Rule         : outbound traffic from this PC to {host} on this port is blocked",
              f"Firewall     : {'rule applied' if b['ok'] else 'FAILED - ' + b['msg']}", ""]
    if not all(b["ok"] for b in blocked):
        L += ["Tip: close PhishNet and start it again with START_PhishNet.bat (it asks for Administrator rights).", ""]
    L += ["This alert was sent automatically by PhishNet."]
    return "\n".join(L)

# ======================= FIREWALL =======================
RISKY_PORTS = {21: "FTP", 23: "Telnet", 135: "RPC", 139: "NetBIOS", 445: "SMB", 3389: "RDP", 5900: "VNC"}
PROTECTED_PORTS = {5000, 1433}

def firewall(action, port, ip=None, direction="in"):
    port = int(port)
    if not 1 <= port <= 65535:
        return False, "Invalid port"
    if ip:
        ipaddress.ip_address(ip)
    try:
        if platform.system() == "Windows":
            name = f"PhishNet {direction} {ip or 'any'} {port}"
            if action == "block":
                cmd = ["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}", f"dir={direction}",
                       "action=block", "protocol=TCP",
                       f"{'localport' if direction == 'in' else 'remoteport'}={port}"]
                if ip:
                    cmd.append(f"remoteip={ip}")
            else:
                cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"]
        else:
            chain = "INPUT" if direction == "in" else "OUTPUT"
            flag = "-A" if action == "block" else "-D"
            cmd = ["iptables", flag, chain] + (["-s" if direction == "in" else "-d", ip] if ip else []) + \
                  ["-p", "tcp", "--dport", str(port), "-j", "DROP"]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        if r.returncode == 0:
            return True, "Firewall rule applied"
        return False, "Firewall rule failed - run PhishNet as Administrator/root. " + (r.stdout + r.stderr).strip()[:120]
    except Exception as e:
        return False, f"Firewall error: {e}"

def add_block(uid, kind, value):
    q("IF NOT EXISTS(SELECT 1 FROM blocked WHERE user_id=? AND kind=? AND value=?) "
      "INSERT INTO blocked(user_id,kind,value) VALUES(?,?,?)", (uid, kind, value, uid, kind, value))

def get_blocked(uid):
    rows = q("SELECT kind,value FROM blocked WHERE user_id=?", (uid,), True)
    return {x["value"] for x in rows if x["kind"] == "domain"}, {x["value"] for x in rows if x["kind"] == "port"}

# ======================= DETECTION =======================
URL_RE = re.compile(r'(?:https?://|www\.)[^\s<>"\']+', re.I)
URL_WORDS = ["login", "verify", "secure", "account", "update", "bank", "signin", "confirm", "password",
             "wallet", "free", "bonus", "prize", "claim", "suspend", "unlock"]
TEXT_WORDS = ["urgent", "verify your account", "suspended", "click here", "password", "otp", "winner",
              "lottery", "prize", "gift card", "bank details", "act now", "limited time", "confirm your",
              "unusual activity", "kyc", "refund", "cvv", "pin number", "congratulations"]
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "cutt.ly", "rebrand.ly"}
BAD_TLDS = {"xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "work", "zip", "loan", "support"}
BRANDS = ["paypal", "google", "amazon", "facebook", "microsoft", "apple", "netflix", "sbi", "hdfc", "icici", "paytm"]

def level_of(s):
    return "High" if s >= 60 else "Medium" if s >= 30 else "Low"

def analyze_url(u, bd=(), bp=()):
    u = u.strip()
    if not re.match(r'^[a-z]+://', u, re.I):
        u = "http://" + u
    try:
        p = urlparse(u)
        host = (p.hostname or "").lower()
        port = p.port
    except Exception:
        return 40, ["Malformed URL"], ""
    s, r = 0, []
    if host in bd:
        s += 100; r.append("Domain is on your block list")
    if port and str(port) in bp:
        s += 100; r.append(f"Uses firewall-blocked port {port}")
    elif port and port not in (80, 443):
        s += 25; r.append(f"Non-standard port {port}")
    if re.fullmatch(r'\d{1,3}(\.\d{1,3}){3}', host):
        s += 30; r.append("IP address used instead of a domain name")
    if p.scheme == "http":
        s += 10; r.append("Not using HTTPS")
    if "@" in u:
        s += 25; r.append("'@' symbol hides the real destination")
    if len(u) > 75:
        s += 10; r.append("Very long URL")
    if host.count(".") >= 4:
        s += 15; r.append("Too many subdomains")
    if host.count("-") >= 3:
        s += 10; r.append("Many hyphens in the domain")
    if "xn--" in host:
        s += 20; r.append("Punycode (lookalike characters)")
    if host in SHORTENERS:
        s += 15; r.append("URL shortener hides the destination")
    if host.rsplit(".", 1)[-1] in BAD_TLDS:
        s += 15; r.append("Risky domain extension")
    hits = [w for w in URL_WORDS if w in u.lower()]
    if hits:
        s += min(24, 8 * len(hits)); r.append("Suspicious words in URL: " + ", ".join(hits[:4]))
    for b in BRANDS:
        if b in host and not (host == b + ".com" or host.endswith("." + b + ".com") or host.endswith("." + b + ".in")):
            s += 30; r.append(f"Possible '{b}' brand impersonation"); break
    return min(s, 100), r, host

def full_scan(user, text="", urls=None, kind="url", save=True):
    urls = list(dict.fromkeys((urls or []) + URL_RE.findall(text or "")))[:40]
    urls = [u for u in urls if u]
    bd, bp = get_blocked(user["id"])
    best, reasons, auto_blocked, hits = 0, [], [], []
    best_u = best_host = None

    def block_domain(u, s, host):
        new = host not in bd
        if new:
            add_block(user["id"], "domain", host)
            bd.add(host)
            auto_blocked.append(host)
        hits.append({"host": host, "url": u, "port": url_port(u), "score": s, "new": new})

    for u in urls:
        s, r, host = analyze_url(u, bd, bp)
        if s >= 60 and host:
            block_domain(u, s, host)
        if s > best:
            best, reasons, best_u, best_host = s, [f"{host or u}: {x}" for x in r], u, host
    low = (text or "").lower()
    th = [w for w in TEXT_WORDS if w in low]
    ts = min(40, 8 * len(th))
    if th:
        reasons.append("Suspicious wording: " + ", ".join(th[:5]))
    score = min(100, best + ts)
    level = level_of(score)
    if level == "High" and not hits and best_host:       # High only because link + wording add up: still block the link
        block_domain(best_u, best, best_host)
    tips = {"High": ["Do not click the link or enter any details.", "Never share OTPs or passwords.",
                     "Report it at cybercrime.gov.in."],
            "Medium": ["Check the sender through an official channel.", "Avoid entering personal data."],
            "Low": ["No major warning signs, but stay careful."]}[level]
    target = (urls[0] if urls and kind in ("url", "auto", "clipboard") else (text or "")[:200])
    if level == "High":
        # email first, so nothing (not even a slow database write) can delay it
        what = ", ".join(f"{h['host']}:{h['port']}" for h in hits[:3]) if hits else "message"
        alert_user(user, f"HIGH RISK blocked: {hits[0]['host'] if hits else 'message'}",
                   f"HIGH RISK ({score}/100): {target[:120]} | Blocked: {what}\nReasons: {'; '.join(reasons)[:500]}",
                   email_body=risk_email(kind, target, score, reasons, hits, bp),
                   dedupe_key="scan" + target[:100] if kind == "auto" else None, dedupe_secs=30)
    if save and (kind != "auto" or level != "Low"):
        q("INSERT INTO scans(user_id,target,kind,score,level,reasons) VALUES(?,?,?,?,?,?)",
          (user["id"], target[:500], kind, score, level, "; ".join(reasons)[:4000]))
    return {"score": score, "level": level, "reasons": reasons, "tips": tips, "auto_blocked": auto_blocked,
            "blocked": [{"host": h["host"], "port": h["port"]} for h in hits]}

# ======================= NMAP NETWORK SCAN =======================
scanning = set()
net_status = {}          # per user: what the scan is doing right now / last error

def set_ns(uid, **kw):
    net_status.setdefault(uid, {}).update(kw)

def local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"

def local_net():
    """(my IP, the network I am connected to). Uses the real subnet mask; never larger than a /24."""
    me = local_ip()
    if me.startswith("127."):
        raise RuntimeError("This PC is not connected to a network (Wi-Fi or Ethernet).")
    prefix = 24
    try:
        import psutil
        for addrs in psutil.net_if_addrs().values():
            for a in addrs:
                if a.family == socket.AF_INET and a.address == me and a.netmask:
                    prefix = ipaddress.IPv4Network("0.0.0.0/" + a.netmask).prefixlen
    except Exception:
        pass
    if prefix < 24 or prefix > 30:
        prefix = 24
    return me, ipaddress.ip_network(f"{me}/{prefix}", strict=False)

def find_nmap():
    p = shutil.which("nmap")
    if p:
        return p
    for c in (r"C:\Program Files (x86)\Nmap\nmap.exe", r"C:\Program Files\Nmap\nmap.exe",
              "/usr/bin/nmap", "/usr/local/bin/nmap", "/opt/homebrew/bin/nmap"):
        if os.path.exists(c):
            return c
    return None

def scan_host_ports(path, host, own):
    """Nmap port scan of ONE device (top 1000 ports, open ports only)."""
    nm = nmap.PortScanner(nmap_search_path=(path,))
    args = "-T4 --top-ports 1000 --open -Pn --host-timeout 120s" + (" -sT" if own else "")
    nm.scan(hosts=host, arguments=args)
    ports = []
    if host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for p, d in nm[host][proto].items():
                if d["state"] == "open":
                    ports.append({"port": int(p), "service": d.get("name", "") or port_name(int(p)).lower()})
    return sorted(ports, key=lambda x: x["port"])

def run_net_scan(user):
    uid = user["id"]
    if uid in scanning:
        return
    scanning.add(uid)
    set_ns(uid, running=True, error="", phase="Starting...", done=0, total=0)
    try:
        path = find_nmap()
        if not path:
            raise RuntimeError("Nmap is not installed. Install it from https://nmap.org/download (default options), "
                               "then restart PhishNet.")
        me, net = local_net()
        set_ns(uid, network=str(net), phase=f"Looking for devices on {net} ...")
        disc = nmap.PortScanner(nmap_search_path=(path,))
        disc.scan(hosts=str(net), arguments="-sn -T4 -PE -PS21,22,23,80,135,139,443,445,3389,5900 -PA80,443")
        hosts = [h for h in disc.all_hosts() if disc[h].state() == "up"]
        if me not in hosts:
            hosts.append(me)
        hosts.sort(key=lambda h: ipaddress.ip_address(h))
        sid = int(time.time())
        set_ns(uid, total=len(hosts), phase=f"Found {len(hosts)} device(s). Checking open ports ...")
        for i, host in enumerate(hosts, 1):
            own = host == me
            set_ns(uid, done=i - 1, phase=f"Checking open ports on {host} ({i} of {len(hosts)}) ...")
            try:
                ports = scan_host_ports(path, host, own)
            except Exception as e:
                print(f"[PhishNet] Port scan of {host} failed: {e}")
                continue
            q("INSERT INTO net_scans(user_id,scan_id,host,ports) VALUES(?,?,?,?)", (uid, sid, host, json.dumps(ports)))
            _, bp = get_blocked(uid)
            blocked = []
            for pt in ports:
                p = pt["port"]
                if p in RISKY_PORTS and p not in PROTECTED_PORTS:
                    key = str(p) if own else f"{host}:{p}"
                    if key in bp:                    # already blocked on an earlier scan: no second email
                        continue
                    ok, msg = firewall("block", p, None if own else host, "in" if own else "out")
                    add_block(uid, "port", key)
                    blocked.append({"port": p, "service": RISKY_PORTS[p], "ok": ok, "msg": msg})
            if blocked:
                names = ", ".join(f"{b['port']} ({b['service']})" for b in blocked)
                alert_user(user, f"Risky port blocked: {blocked[0]['port']} on {host}",
                           f"Risky open port(s) {names} found on {host}{' (this PC)' if own else ''} and blocked.",
                           email_body=ports_email(host, own, str(net), blocked))
        set_ns(uid, done=len(hosts), phase="Scan finished", last=time.strftime("%H:%M:%S"), found=len(hosts))
    except Exception as e:
        print("[PhishNet] Network scan error:", e)
        set_ns(uid, error=str(e)[:300], phase="Scan failed")
    finally:
        set_ns(uid, running=False)
        scanning.discard(uid)

def auto_scan_loop():
    while True:
        time.sleep(AUTO_SCAN_SECONDS)
        try:
            for u in q("SELECT * FROM users WHERE auto_scan=1", fetch=True):
                run_net_scan(u)
        except Exception as e:
            print("Auto scan error:", e)

# ======================= LIVE PROTECTION (clipboard) =======================
live_feed, live_count = {}, {}
_feed_id = 0

def live_check(u, txt):
    """Scan one copied text for one user. Plain text with no link and no scam wording is ignored and never stored."""
    global _feed_id
    uid = u["id"]
    has_url = bool(URL_RE.findall(txt))
    r = full_scan(u, text=txt, kind="clipboard", save=False)
    live_count[uid] = live_count.get(uid, 0) + 1
    if not (has_url or r["reasons"]):
        return
    if r["level"] != "Low":
        q("INSERT INTO scans(user_id,target,kind,score,level,reasons) VALUES(?,?,?,?,?,?)",
          (uid, txt[:500], "clipboard", r["score"], r["level"], "; ".join(r["reasons"])[:4000]))
    _feed_id += 1
    feed = live_feed.setdefault(uid, [])
    feed.insert(0, {"id": _feed_id, "ts": int(time.time()), "at": time.strftime("%H:%M:%S"),
                    "preview": txt[:90].replace("\n", " "), "level": r["level"], "score": r["score"],
                    "reasons": "; ".join(r["reasons"])[:200], "blocked": r["auto_blocked"]})
    del feed[40:]

def clip_seq():
    """Windows counts every copy, so copying the SAME text again is still noticed."""
    if platform.system() == "Windows":
        try:
            return ctypes.windll.user32.GetClipboardSequenceNumber()
        except Exception:
            return None
    return None

def clipboard_loop():
    if not CLIP_OK:
        print("[PhishNet] Live protection unavailable: run  pip install pyperclip")
        return
    last_seq = clip_seq()
    try:
        last = pyperclip.paste()          # ignore whatever was copied before PhishNet started
    except Exception:
        last = ""
    while True:
        time.sleep(0.5)
        seq = clip_seq()
        if seq is not None:
            if seq == last_seq:
                continue
            last_seq = seq
        try:
            txt = pyperclip.paste() or ""
        except Exception:
            continue                      # image / file on the clipboard
        if seq is None:
            if txt == last:
                continue
            last = txt
        txt = txt.strip()
        if len(txt) < 4 or len(txt) > 8000:
            continue
        try:
            for u in q("SELECT * FROM users WHERE live_protect=1", fetch=True):
                live_check(u, txt)
        except Exception as e:
            print("Live protection error:", e)

def live_state(u):
    uid = u["id"]
    feed = live_feed.get(uid, [])
    return {"on": bool(u.get("live_protect")), "supported": CLIP_OK, "checked": live_count.get(uid, 0),
            "suspicious": sum(1 for f in feed if f["level"] != "Low"),
            "threats": sum(1 for f in feed if f["level"] == "High"),
            "now": int(time.time()), "feed": feed[:15]}

# ======================= AUTH =======================
def cur_user():
    if "uid" not in session:
        return None
    return q("SELECT * FROM users WHERE id=?", (session["uid"],), True, True)

def login_required(f):
    @wraps(f)
    def w(*a, **k):
        u = cur_user()
        if not u:
            return (jsonify(error="login required"), 401) if request.path.startswith("/api") else redirect("/login")
        return f(u, *a, **k)
    return w

@app.route("/")
def home():
    return redirect("/dashboard" if "uid" in session else "/login")

@app.route("/register", methods=["GET", "POST"])
def register():
    err = None
    if request.method == "POST":
        un, em, pw = request.form["username"].strip(), request.form["email"].strip(), request.form["password"]
        if len(un) < 3 or len(pw) < 6 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", em):
            err = "Use a username of 3+ characters, a valid email, and a password of 6+ characters."
        else:
            try:
                q("INSERT INTO users(username,email,password_hash,api_key) VALUES(?,?,?,?)",
                  (un, em, generate_password_hash(pw), secrets.token_hex(24)))
                return redirect("/login")
            except pyodbc.IntegrityError:
                err = "That username is taken. Try another one."
    return render_template("auth.html", mode="register", err=err)

@app.route("/login", methods=["GET", "POST"])
def login():
    err = None
    if request.method == "POST":
        u = q("SELECT * FROM users WHERE username=?", (request.form["username"].strip(),), True, True)
        if u and check_password_hash(u["password_hash"], request.form["password"]):
            session["uid"] = u["id"]
            return redirect("/dashboard")
        err = "Wrong username or password."
    return render_template("auth.html", mode="login", err=err)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

@app.route("/dashboard")
@login_required
def dashboard(u):
    return render_template("dashboard.html", user=u)

# ======================= API =======================
@app.route("/api/scan", methods=["POST"])
@login_required
def api_scan(u):
    d = request.get_json(force=True)
    kind = d.get("kind", "url")
    t = (d.get("text") or "").strip()
    if not t:
        return jsonify(error="Nothing to scan"), 400
    return jsonify(full_scan(u, text="" if kind == "url" else t, urls=[t] if kind == "url" else [], kind=kind))

@app.route("/api/ext_scan", methods=["POST"])
def api_ext_scan():
    u = q("SELECT * FROM users WHERE api_key=?", (request.headers.get("X-API-Key", ""),), True, True)
    if not u:
        return jsonify(error="bad key"), 401
    d = request.get_json(force=True)
    page = full_scan(u, text=(d.get("text") or "")[:6000], urls=[d.get("url", "")], kind="auto")
    bd, bp = get_blocked(u["id"])
    flagged, fl_hits = [], []
    for l in (d.get("links") or [])[:40]:
        s, r, h = analyze_url(l, bd, bp)
        if s >= 60:
            flagged.append(l)
            new = bool(h and h not in bd)
            if new:
                add_block(u["id"], "domain", h)
                bd.add(h)
            fl_hits.append({"host": h, "url": l, "port": url_port(l), "score": s, "new": new})
    if flagged:
        reasons = [f"A link on {d.get('url', '')[:100]} points to a dangerous address (risk {x['score']}/100)" for x in fl_hits[:3]]
        alert_user(u, "Dangerous links on a page you opened",
                   f"Dangerous links found on {d.get('url', '')[:100]}: " + ", ".join(f"{x['host']}:{x['port']}" for x in fl_hits[:3]),
                   email_body=risk_email("auto", d.get("url", ""), max(x["score"] for x in fl_hits), reasons, fl_hits, bp),
                   dedupe_key="links" + d.get("url", "")[:80], dedupe_secs=30)
    page["flagged_links"] = flagged
    return jsonify(page)

@app.route("/api/alerts")
@login_required
def api_alerts(u):
    rows = q("SELECT id,message FROM alerts WHERE user_id=? AND seen=0", (u["id"],), True)
    if rows:
        q("UPDATE alerts SET seen=1 WHERE user_id=?", (u["id"],))
    return jsonify(email=u["email"], alerts=rows, mail_ok=mail_status["ok"], mail_msg=mail_status["msg"])

@app.route("/api/test_alert", methods=["POST"])
@login_required
def api_test_alert(u):
    msg = "This is a test alert from PhishNet. Your email alerts are working."
    q("INSERT INTO alerts(user_id,message) VALUES(?,?)", (u["id"], msg))
    ok, info = _send_mail(u["email"], "[PhishNet] Test alert", msg)
    return jsonify(ok=ok, msg=info, email=u["email"])

@app.route("/api/block", methods=["POST"])
@login_required
def api_block(u):
    d = request.get_json(force=True)
    kind, val = d.get("kind"), str(d.get("value", "")).strip().lower()
    if kind == "port":
        if not val.isdigit() or not 1 <= int(val) <= 65535:
            return jsonify(error="Enter a port number between 1 and 65535."), 400
        if int(val) in PROTECTED_PORTS:
            return jsonify(error="This port is protected because PhishNet and the database use it."), 400
        ip = (d.get("ip") or "").strip()
        if ip:
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                return jsonify(error="Invalid IP address."), 400
            ok, msg = firewall("block", val, ip, "out")
            add_block(u["id"], "port", f"{ip}:{val}")
        else:
            ok, msg = firewall("block", val)
            add_block(u["id"], "port", val)
        pn = port_name(int(val))
        body = "\n".join(["PHISHNET SECURITY ALERT", "=" * 44, "A port was blocked.", "",
                          f"Port         : {val} ({pn})",
                          (f"Rule         : outbound traffic from this PC to {ip} on this port is blocked" if ip
                           else "Rule         : inbound traffic to this port on THIS PC is blocked"),
                          f"Firewall     : {'rule applied' if ok else 'FAILED - ' + msg}",
                          f"Time         : {now_str()}", "", "Sent automatically by PhishNet."])
        alert_user(u, f"Port blocked: {val}", f"Port {val} ({pn}) blocked{' for ' + ip if ip else ''}. {msg}", email_body=body)
        return jsonify(ok=ok, msg=msg)
    if kind == "domain" and val:
        add_block(u["id"], "domain", val)
        return jsonify(ok=True, msg=f"{val} is now blocked.")
    return jsonify(error="Bad request"), 400

@app.route("/api/unblock", methods=["POST"])
@login_required
def api_unblock(u):
    d = request.get_json(force=True)
    kind, val = d.get("kind"), str(d.get("value", ""))
    msg = "Removed from the block list."
    if kind == "port":
        if ":" in val:
            ip, port = val.split(":")
            _, msg = firewall("unblock", port, ip, "out")
        else:
            _, msg = firewall("unblock", val)
    q("DELETE FROM blocked WHERE user_id=? AND kind=? AND value=?", (u["id"], kind, val))
    return jsonify(ok=True, msg=msg)

@app.route("/api/netscan", methods=["POST"])
@login_required
def api_netscan(u):
    threading.Thread(target=run_net_scan, args=(u,), daemon=True).start()
    return jsonify(ok=True)

@app.route("/api/autoscan", methods=["POST"])
@login_required
def api_autoscan(u):
    on = 1 if request.get_json(force=True).get("on") else 0
    q("UPDATE users SET auto_scan=? WHERE id=?", (on, u["id"]))
    if on:
        threading.Thread(target=run_net_scan, args=(u,), daemon=True).start()
    return jsonify(ok=True)

@app.route("/api/liveprotect", methods=["POST"])
@login_required
def api_liveprotect(u):
    on = 1 if request.get_json(force=True).get("on") else 0
    q("UPDATE users SET live_protect=? WHERE id=?", (on, u["id"]))
    return jsonify(ok=True, on=bool(on), supported=CLIP_OK)

@app.route("/api/live")
@login_required
def api_live(u):
    return jsonify(live_state(u))

def batch_delete(table, where, args):
    """Delete in chunks of 5000 rows so a huge history never locks the database."""
    q(f"SET NOCOUNT ON; WHILE 1=1 BEGIN DELETE TOP (5000) FROM {table} WHERE {where}; IF @@ROWCOUNT=0 BREAK END", args)

@app.route("/api/clear_history", methods=["POST"])
@login_required
def api_clear_history(u):
    d = request.get_json(force=True)
    uid, done = u["id"], {}
    if d.get("scans"):
        done["scans"] = q("SELECT COUNT(*) AS n FROM scans WHERE user_id=?", (uid,), True, True)["n"]
        batch_delete("scans", "user_id=?", (uid,))
        live_feed.pop(uid, None)
        live_count.pop(uid, None)
    if d.get("alerts"):
        done["alerts"] = q("SELECT COUNT(*) AS n FROM alerts WHERE user_id=?", (uid,), True, True)["n"]
        batch_delete("alerts", "user_id=?", (uid,))
    if d.get("net"):
        w = "user_id=? AND scan_id < (SELECT MAX(scan_id) FROM net_scans WHERE user_id=?)"
        done["net"] = q("SELECT COUNT(*) AS n FROM net_scans WHERE " + w, (uid, uid), True, True)["n"]
        batch_delete("net_scans", w, (uid, uid))
    return jsonify(ok=True, cleared=done)

@app.route("/api/state")
@login_required
def api_state(u):
    uid = u["id"]
    try:
        me, net = local_net()
        network = str(net)
    except Exception as e:
        me, network = local_ip(), "not connected"
    st = q("""SELECT COUNT(*) AS total,
              ISNULL(SUM(CASE WHEN level='High' THEN 1 ELSE 0 END),0) AS high,
              ISNULL(SUM(CASE WHEN level='Medium' THEN 1 ELSE 0 END),0) AS medium
              FROM scans WHERE user_id=?""", (uid,), True, True)
    blocked = q("SELECT kind,value FROM blocked WHERE user_id=? ORDER BY id DESC", (uid,), True)
    hosts = q("SELECT host,ports FROM net_scans WHERE user_id=? AND "
              "scan_id=(SELECT MAX(scan_id) FROM net_scans WHERE user_id=?)", (uid, uid), True)
    timeline = [r["score"] for r in q("SELECT TOP 24 score FROM scans WHERE user_id=? ORDER BY id DESC", (uid,), True)][::-1]
    cnt = q("SELECT (SELECT COUNT(*) FROM scans WHERE user_id=?) AS scans, (SELECT COUNT(*) FROM alerts WHERE user_id=?) AS alerts, "
            "(SELECT COUNT(*) FROM net_scans WHERE user_id=?) AS net", (uid, uid, uid), True, True)
    return jsonify(
        live=live_state(u), counts=cnt,
        mail=dict(configured=bool(mail_cfg()["user"] and mail_cfg()["pw"]), user=mail_cfg()["user"], **mail_status),
        scanning=uid in scanning, auto_scan=bool(u["auto_scan"]), me_ip=me,
        network=network, net=net_status.get(uid, {}),
        email=u["email"], api_key=u["api_key"], blocked=blocked, hosts=hosts, timeline=timeline,
        stats={"total": st["total"], "high": st["high"], "medium": st["medium"],
               "blocked": len(blocked), "hosts": len(hosts)},
        scans=q("SELECT TOP 50 target,kind,score,level,reasons,CONVERT(VARCHAR(19),created_at,120) AS at "
                "FROM scans WHERE user_id=? ORDER BY id DESC", (uid,), True),
        alerts=q("SELECT TOP 8 message,CONVERT(VARCHAR(19),created_at,120) AS at "
                 "FROM alerts WHERE user_id=? ORDER BY id DESC", (uid,), True))

if __name__ == "__main__":
    try:
        resolve_server()
        init_db()
    except Exception as e:
        print("\n[PhishNet] Could not connect to SQL Server.")
        print("Open config.py and set SQL_SERVER to your server name (for example DESKTOP-ABC\\SQLEXPRESS).")
        print("Details:", e)
        sys.exit(1)
    _c = mail_cfg()
    print("[PhishNet] Alert emails:", "sender is set up (" + _c["user"] + ")" if _c["user"] and _c["pw"]
          else "NOT SET UP - fill SMTP_USER and SMTP_PASS in config.py, otherwise alerts only print in this window")
    print("[PhishNet] Nmap:", find_nmap() or "NOT FOUND - install it from https://nmap.org/download")
    threading.Thread(target=auto_scan_loop, daemon=True).start()
    threading.Thread(target=clipboard_loop, daemon=True).start()
    print("\n[PhishNet] Running at http://127.0.0.1:5000  (driver:", DRIVER + ")")
    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)
