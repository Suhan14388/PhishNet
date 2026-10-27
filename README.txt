PHISHNET - QUICK START
======================

BEFORE FIRST RUN (install once)
  1. Python 3        https://www.python.org/downloads/   (tick "Add Python to PATH")
  2. Nmap            https://nmap.org/download            (keep the default install, it adds itself to PATH)
  3. ODBC Driver 17 or 18 for SQL Server (Microsoft download)
  4. SQL Server (Express is fine) running on this PC

RUN
  1. Open config.py in Notepad and fill the sender email (see EMAIL ALERTS below). Once.
     SQL Server is found automatically. Only if PhishNet says it cannot find it, set
     SQL_SERVER = r"DESKTOP-ABC123\SQLEXPRESS" (the name from the SSMS login window).
  2. Double-click START_PhishNet.bat  (it asks for Administrator rights so the firewall can work)
  3. Your browser opens http://127.0.0.1:5000
  4. Click "Create an account": username, email, password. Then log in.
     The database and all tables are created automatically.

EMAIL ALERTS (automatic, instant)
  Every time a HIGH-RISK link or message is found (Scanner, copied text, or the browser extension)
  PhishNet blocks it and emails the address you typed when you created your account, immediately.
  Every detection is emailed, not just the first one. The email lists what was blocked: the domain,
  the link, the port it uses and why it is dangerous. Risky ports closed by the network scan
  (for example 445 SMB or 3389 RDP) are emailed too, with the port number and the device.
  There is no email settings page. A program needs one SENDER mailbox, so in config.py fill:
         SMTP_USER = "yoursender@gmail.com"
         SMTP_PASS = "16-letter app password"
  (Gmail: Google Account > Security > turn on 2-Step Verification > App passwords > create one.)
  Overview > "Send test alert" sends a test email. If it fails, the reason is shown on screen.

NETWORK TAB
  Press "Scan network now" (or switch on auto-scan). PhishNet uses Nmap to find the devices on the
  network you are connected to, then lists the open ports of each device. Progress and any problem
  are shown at the top of the tab. Risky ports (21, 23, 135, 139, 445, 3389, 5900) are blocked
  automatically and emailed to you once. Nmap must be installed (step 2 above).

LIVE PROTECTION (new)
  Dashboard > Live protection > switch on "Scan everything I copy" (also on the Overview page).
  Copy any link or message in any app and PhishNet checks it within a second. Risky results
  pop up on screen, are emailed to you instantly, and dangerous domains are added to the block list.
  Needs the pyperclip package (START_PhishNet.bat installs it). Plain text with no link and no
  scam wording is ignored and never stored.

CLEAR HISTORY (new)
  Dashboard > History > Clear history. Choose scan history, alerts and old network scan data.
  Your block list and account stay. The first start after this update also adds database
  indexes so the dashboard loads faster.

BROWSER AUTO-SCAN
  1. Chrome/Edge > chrome://extensions > turn on Developer mode > Load unpacked > pick the "extension" folder.
  2. Dashboard > Browser protection > copy your API key.
  3. Click the PhishNet toolbar icon, paste the key, Save.
  Every page you open is checked (address, links, text). High-risk pages are blocked.

NOTES
  - Only scan networks you own or have permission to scan.
  - Ports 5000 and 1433 can never be blocked (the app and database need them).
  - Blocking ports such as 445 or 3389 turns off file sharing / remote desktop on that PC.
