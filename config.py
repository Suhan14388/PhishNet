# =====================================================================
#  PhishNet settings.
#  The ONLY thing you fill in is the SENDER email (section 2). Everything else works as it is.
# =====================================================================

# 1) SQL Server.  "AUTO" tries the usual names (.\SQLEXPRESS, localhost, this PC's name...).
#    Only if PhishNet says it cannot find SQL Server, type the name shown in the SSMS login
#    window here, e.g.  r"DESKTOP-ABC123\SQLEXPRESS"
SQL_SERVER = r"SK"

SQL_DATABASE = "PhishNet"      # created automatically
SQL_USER = ""                  # leave empty to use Windows login
SQL_PASSWORD = ""              # only needed when SQL_USER is filled
SQL_DRIVER = "ODBC Driver 17 for SQL Server"   # auto-switches if another driver is installed

# 2) Email alerts.  Every high-risk link/message and every blocked port is emailed INSTANTLY
#    to the address the user typed when creating their PhishNet account.
#    A program needs one "sender" mailbox to send those emails. Use a Gmail address with an
#    App Password:  Google Account > Security > 2-Step Verification (on) > App passwords.
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = "mrsk22786@gmail.com"                 # sender Gmail address, e.g. phishnet.alerts@gmail.com
SMTP_PASS = "mwfg eucj vszt krgv"                 # the 16-letter App Password (spaces are fine)

# 3) Network auto-scan interval (seconds)
AUTO_SCAN_SECONDS = 300

SECRET_KEY = "change-this-to-any-long-random-text"
