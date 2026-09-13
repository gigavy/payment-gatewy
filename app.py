import os
import re
import time
import uuid
import random
import email
import sqlite3
import imaplib
import threading
import json
import hmac
import hashlib
import secrets
import base64
import struct
import urllib.parse
from datetime import datetime, timedelta
from functools import wraps

import requests
import qrcode
from flask import Flask, request, jsonify, send_file, render_template, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

from cryptography.fernet import Fernet

# --- ENCRYPTION SETUP ---
KEY_FILE = 'secret.key'
if not os.path.exists(KEY_FILE):
    with open(KEY_FILE, 'wb') as key_file:
        key_file.write(Fernet.generate_key())

with open(KEY_FILE, 'rb') as key_file:
    ENCRYPTION_KEY = key_file.read()

cipher_suite = Fernet(ENCRYPTION_KEY)

def encrypt_pass(plain_text):
    if not plain_text: return None
    return cipher_suite.encrypt(plain_text.encode('utf-8')).decode('utf-8')

def decrypt_pass(cipher_text):
    if not cipher_text: return None
    try:
        return cipher_suite.decrypt(cipher_text.encode('utf-8')).decode('utf-8')
    except Exception:
        # Fallback for plain-text passwords saved before this update
        return cipher_text

# --- TWO-FACTOR AUTHENTICATION (RFC 6238 TOTP) ---
def generate_totp_secret():
    raw = secrets.token_bytes(20)
    return base64.b32encode(raw).decode('utf-8').replace('=', '')

def get_totp_token(secret, intervals_no=None):
    if intervals_no is None:
        intervals_no = int(time.time()) // 30
    cleaned = secret.strip().replace(' ', '').upper()
    missing_padding = len(cleaned) % 8
    if missing_padding != 0:
        cleaned += '=' * (8 - missing_padding)
    try:
        key = base64.b32decode(cleaned, casefold=True)
    except Exception:
        return None
    msg = struct.pack(">Q", intervals_no)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = h[19] & 15
    code = (struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 1000000
    return f"{code:06d}"

def verify_totp_token(secret, token, window=1):
    if not secret or not token:
        return False
    token = str(token).strip()
    current_interval = int(time.time()) // 30
    for i in range(-window, window + 1):
        expected = get_totp_token(secret, current_interval + i)
        if expected and hmac.compare_digest(expected, token):
            return True
    return False

# --- SAFE REDIRECT URL SANITIZATION ---
def is_safe_redirect_url(url, allowed_domains=None, fallback_domain=None):
    if not url: return False
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ('http', 'https'):
            return False
        hostname = (parsed.hostname or '').lower().strip()
        if not hostname:
            return False
        
        valid_domains = []
        if allowed_domains:
            for d in allowed_domains:
                d = d.strip().lower()
                if d:
                    if '://' in d:
                        d = urllib.parse.urlparse(d).hostname or d
                    valid_domains.append(d)
        if fallback_domain:
            fb = fallback_domain.strip().lower()
            if fb:
                if '://' in fb:
                    fb = urllib.parse.urlparse(fb).hostname or fb
                valid_domains.append(fb)
                
        if not valid_domains:
            return False
            
        for vd in valid_domains:
            if hostname == vd or hostname.endswith('.' + vd):
                return True
        return False
    except Exception:
        return False

# --- DEVICE DETECTION HELPER ---
def get_device_summary(user_agent_str):
    if not user_agent_str: return "Desktop Browser"
    ua = user_agent_str.lower()
    browser = "Browser"
    if "edg" in ua: browser = "Edge"
    elif "chrome" in ua and "opr" not in ua: browser = "Chrome"
    elif "safari" in ua and "chrome" not in ua: browser = "Safari"
    elif "firefox" in ua: browser = "Firefox"
    elif "opr" in ua or "opera" in ua: browser = "Opera"
    
    os_name = "Device"
    if "windows" in ua: os_name = "Windows"
    elif "macintosh" in ua or "mac os" in ua: os_name = "macOS"
    elif "android" in ua: os_name = "Android"
    elif "iphone" in ua: os_name = "iPhone"
    elif "ipad" in ua: os_name = "iPad"
    elif "linux" in ua: os_name = "Linux"
    
    return f"{browser} on {os_name}"

# ============================================
# SERVER CONFIGURATION
# ============================================
DB_FILE = "fampay_gateway.db"
PORT = int(os.environ.get("PORT", 5000))

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "fampay-super-secret-key")

# --- CSRF PROTECTION HELPER ---
def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf_token())

def verify_csrf():
    if request.method in ['POST', 'PUT', 'DELETE']:
        # Exempt public payment verification endpoints and checkout callbacks
        exempt_prefixes = ['/api/', '/pay', '/static']
        if any(request.path.startswith(p) for p in exempt_prefixes):
            return True
        if request.path in ['/login', '/register', '/admin/login']:
            return True
        token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
        expected = session.get('csrf_token')
        if not token or not expected or not hmac.compare_digest(token, expected):
            return False
    return True

# ============================================
# DATABASE INITIALIZATION
# ============================================

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # 1. Base table definitions with complete column definitions
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password_hash TEXT,
            upi_id TEXT,
            gmail TEXT,
            app_pass TEXT,
            api_key TEXT UNIQUE,
            created_at DATETIME,
            display_name TEXT DEFAULT 'Merchant',
            theme TEXT DEFAULT 'default',
            provider TEXT DEFAULT 'fampay',
            profile_pic TEXT,
            merchant_id TEXT,
            role TEXT DEFAULT 'merchant',
            plan_name TEXT DEFAULT 'Free',
            plan_expiry TEXT,
            email TEXT,
            mobile TEXT,
            business_name TEXT,
            business_website TEXT,
            business_logo TEXT,
            business_support_email TEXT,
            payment_expiry_minutes INTEGER DEFAULT 5,
            success_redirect_url TEXT,
            failed_redirect_url TEXT,
            allowed_redirect_domains TEXT,
            live_api_key_hash TEXT,
            live_api_key_hint TEXT,
            test_api_key_hash TEXT,
            test_api_key_hint TEXT,
            telegram_bot_token_enc TEXT,
            telegram_chat_id_enc TEXT,
            totp_secret_enc TEXT,
            totp_enabled INTEGER DEFAULT 0,
            accent_color TEXT DEFAULT '#4f46e5',
            layout_density TEXT DEFAULT 'comfortable',
            google_id TEXT UNIQUE,
            auth_provider TEXT DEFAULT 'local',
            links_used INTEGER DEFAULT 0,
            is_admin_bypass INTEGER DEFAULT 0,
            free_plan_reset_date TEXT
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS transactions (
            txn_id TEXT PRIMARY KEY,
            user_id INTEGER,
            amount REAL,
            utr TEXT,
            status TEXT DEFAULT 'pending',
            created_at DATETIME,
            expires_at DATETIME,
            paid_at DATETIME,
            merchant_order_id TEXT,
            customer_name TEXT,
            customer_email TEXT,
            callback_url TEXT
        )
    ''')

    c.execute("CREATE TABLE IF NOT EXISTS system_settings (key TEXT PRIMARY KEY, value TEXT)")

    c.execute("""CREATE TABLE IF NOT EXISTS payouts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT,
        amount REAL,
        status TEXT DEFAULT 'pending',
        upi_id TEXT,
        created_at TEXT,
        updated_at TEXT
    )""")

    c.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('maintenance_mode', 'false')")
    c.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('admin_password', 'admin123')")
    c.execute("CREATE TABLE IF NOT EXISTS admin_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT, message TEXT, created_at TEXT)")
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS webhook_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            txn_id TEXT,
            url TEXT,
            payload TEXT,
            response_code INTEGER,
            response_body TEXT,
            sent_at DATETIME
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS system_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            log_msg TEXT,
            log_time DATETIME
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS user_sessions (
            session_id TEXT PRIMARY KEY,
            user_id INTEGER,
            session_token TEXT UNIQUE,
            ip_address TEXT,
            user_agent TEXT,
            device_summary TEXT,
            created_at DATETIME,
            last_active_at DATETIME,
            is_active INTEGER DEFAULT 1
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS webhook_nonces (
            nonce TEXT PRIMARY KEY,
            created_at DATETIME
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS mobile_verification_otps (
            user_id INTEGER PRIMARY KEY,
            new_mobile TEXT,
            otp_code TEXT,
            expires_at DATETIME
        )
    ''')
    conn.commit()

    # 2. Dynamic column migrations for pre-existing databases
    c.execute("PRAGMA table_info(users)")
    existing_user_cols = {row[1] for row in c.fetchall()}
    user_migrations = [
        ('display_name', "TEXT DEFAULT 'Merchant'"),
        ('theme', "TEXT DEFAULT 'default'"),
        ('provider', "TEXT DEFAULT 'fampay'"),
        ('password_hash', "TEXT"),
        ('profile_pic', "TEXT"),
        ('merchant_id', "TEXT"),
        ('role', "TEXT DEFAULT 'merchant'"),
        ('plan_name', "TEXT DEFAULT 'Free'"),
        ('plan_expiry', "TEXT"),
        ('email', "TEXT"),
        ('mobile', "TEXT"),
        ('business_name', "TEXT"),
        ('business_website', "TEXT"),
        ('business_logo', "TEXT"),
        ('business_support_email', "TEXT"),
        ('payment_expiry_minutes', "INTEGER DEFAULT 5"),
        ('success_redirect_url', "TEXT"),
        ('failed_redirect_url', "TEXT"),
        ('allowed_redirect_domains', "TEXT"),
        ('live_api_key_hash', "TEXT"),
        ('live_api_key_hint', "TEXT"),
        ('test_api_key_hash', "TEXT"),
        ('test_api_key_hint', "TEXT"),
        ('telegram_bot_token_enc', "TEXT"),
        ('telegram_chat_id_enc', "TEXT"),
        ('totp_secret_enc', "TEXT"),
        ('totp_enabled', "INTEGER DEFAULT 0"),
        ('accent_color', "TEXT DEFAULT '#4f46e5'"),
        ('layout_density', "TEXT DEFAULT 'comfortable'"),
        ('google_id', "TEXT UNIQUE"),
        ('auth_provider', "TEXT DEFAULT 'local'"),
        ('links_used', "INTEGER DEFAULT 0"),
        ('is_admin_bypass', "INTEGER DEFAULT 0"),
        ('free_plan_reset_date', "TEXT")
    ]
    for col, col_def in user_migrations:
        if col not in existing_user_cols:
            try:
                c.execute(f"ALTER TABLE users ADD COLUMN {col} {col_def}")
                conn.commit()
            except Exception:
                pass

    c.execute("PRAGMA table_info(transactions)")
    existing_txn_cols = {row[1] for row in c.fetchall()}
    txn_migrations = [
        ('callback_url', "TEXT"),
        ('expires_at', "DATETIME"),
        ('customer_email', "TEXT"),
        ('merchant_order_id', "TEXT"),
        ('customer_name', "TEXT")
    ]
    for col, col_def in txn_migrations:
        if col not in existing_txn_cols:
            try:
                c.execute(f"ALTER TABLE transactions ADD COLUMN {col} {col_def}")
                conn.commit()
            except Exception:
                pass

    conn.commit()
    conn.close()

# Run database setup immediately on module load so all tables and migrations are present under WSGI/Render
init_db()

def get_user(user_id):
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
    row = c.fetchone()
    conn.close()
    if row:
        d = dict(row)
        api_k = d.get('api_key') or ''
        return {
            "user_id": d.get("user_id"),
            "username": d.get("username"),
            "upi_id": d.get("upi_id"),
            "gmail": d.get("gmail"),
            "app_pass": d.get("app_pass"),
            "api_key": api_k,
            "created_at": d.get("created_at"),
            "display_name": d.get("display_name") or "Merchant",
            "theme": d.get("theme") or "default",
            "provider": d.get("provider") or "fampay",
            "profile_pic": d.get("profile_pic"),
            "role": d.get("role") or "merchant",
            "plan_name": d.get("plan_name") or "Free",
            "plan_expiry": d.get("plan_expiry"),
            "email": d.get("email") or "",
            "mobile": d.get("mobile") or "",
            "business_name": d.get("business_name") or (d.get("display_name") or "Merchant"),
            "business_website": d.get("business_website") or "",
            "business_logo": d.get("business_logo") or d.get("profile_pic"),
            "business_support_email": d.get("business_support_email") or (d.get("email") or ""),
            "payment_expiry_minutes": int(d.get("payment_expiry_minutes") or 5),
            "success_redirect_url": d.get("success_redirect_url") or "",
            "failed_redirect_url": d.get("failed_redirect_url") or "",
            "allowed_redirect_domains": d.get("allowed_redirect_domains") or "",
            "live_api_key_hash": d.get("live_api_key_hash"),
            "live_api_key_hint": d.get("live_api_key_hint") or (api_k[-4:] if len(api_k) >= 4 else "none"),
            "test_api_key_hash": d.get("test_api_key_hash"),
            "test_api_key_hint": d.get("test_api_key_hint") or "none",
            "telegram_configured": bool(d.get("telegram_bot_token_enc") and d.get("telegram_chat_id_enc")),
            "telegram_chat_id": decrypt_pass(d.get("telegram_chat_id_enc")) if d.get("telegram_chat_id_enc") else "",
            "totp_enabled": bool(d.get("totp_enabled")),
            "accent_color": d.get("accent_color") or "#4f46e5",
            "layout_density": d.get("layout_density") or "comfortable",
            "password_hash": d.get("password_hash"),
            "google_id": d.get("google_id"),
            "auth_provider": d.get("auth_provider") or "local",
            "links_used": d.get("links_used") or 0,
            "links_limit": 31 if (d.get("plan_name") == "Basic") else (66 if d.get("plan_name") == "Pro" else 15)
        }
    return None

def save_user_account(user_id, upi_id, gmail, app_pass, provider='fampay'):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT api_key FROM users WHERE user_id = ?", (user_id,))
    row = c.fetchone()
    api_key = row[0] if row and row[0] else "FAM_" + uuid.uuid4().hex + uuid.uuid4().hex[:12]
    c.execute('''UPDATE users SET upi_id=?, gmail=?, app_pass=?, api_key=?, provider=? WHERE user_id=?''', 
              (upi_id, gmail, encrypt_pass(app_pass), api_key, provider, user_id))
    conn.commit()
    conn.close()
    return api_key

# ============================================
# AUTHENTICATION
# ============================================
from functools import wraps
from datetime import timedelta

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect('/admin/login')
        return f(*args, **kwargs)
    return decorated_function

def get_sys_setting(key, default=None):
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT value FROM system_settings WHERE key=?", (key,))
        row = c.fetchone()
        conn.close()
        return row[0] if row else default
    except:
        return default

def set_sys_setting(key, value):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("UPDATE system_settings SET value=? WHERE key=?", (value, key))
    conn.commit()
    conn.close()

def add_admin_log(type_str, msg):
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("INSERT INTO admin_logs (type, message, created_at) VALUES (?, ?, ?)", (type_str, msg, datetime.now().isoformat()))
        conn.commit()
        conn.close()
    except:
        pass

PLAN_LIMITS = {
    'Free': 10000,
    'Micro': 50000,
    'Starter': 100000,
    'Basic': 250000,
    'Growth': 500000,
    'Pro': 1000000,
    'Elite': 5000000
}

@app.before_request
def check_maintenance():
    if request.path.startswith('/admin') or request.path.startswith('/static') or request.path == '/api/create-order' or request.path.startswith('/pay'):
        return
    if get_sys_setting('maintenance_mode') == 'true':
        return "<h1>Platform Under Maintenance</h1><p>We are upgrading our systems. Please check back in a few minutes.</p>", 503

@app.before_request
def check_plan_expiry():
    if 'user_id' in session and not request.path.startswith('/admin') and not request.path.startswith('/static'):
        try:
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            c.execute("SELECT plan_name, plan_expiry, free_plan_reset_date, created_at FROM users WHERE user_id=?", (session['user_id'],))
            row = c.fetchone()
            if row:
                plan_name, plan_expiry_str, reset_date_str, created_at = row
                
                # Check Paid Plan Expiry
                if plan_expiry_str:
                    try:
                        expiry_date = datetime.fromisoformat(plan_expiry_str)
                        if datetime.now() > expiry_date + timedelta(days=3):
                            c.execute("UPDATE users SET plan_name='Free', plan_expiry=NULL WHERE user_id=?", (session['user_id'],))
                            conn.commit()
                            plan_name = 'Free'
                    except: pass
                
                # Free Plan Weekly Reset
                if plan_name == 'Free':
                    try:
                        base_date = datetime.fromisoformat(reset_date_str) if reset_date_str else (datetime.fromisoformat(created_at) if created_at else datetime.now())
                        if datetime.now() > base_date + timedelta(days=7):
                            new_reset_date = datetime.now().isoformat()
                            c.execute("UPDATE users SET links_used=0, free_plan_reset_date=? WHERE user_id=?", (new_reset_date, session['user_id']))
                            conn.commit()
                    except:
                        # Fallback if dates are unparseable
                        new_reset_date = datetime.now().isoformat()
                        c.execute("UPDATE users SET links_used=0, free_plan_reset_date=? WHERE user_id=?", (new_reset_date, session['user_id']))
                        conn.commit()
            conn.close()
        except Exception as e:
            pass

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    error = None
    if request.method == 'POST':
        pwd = request.form.get('password')
        actual_pwd = get_sys_setting('admin_password', 'admin123')
        if pwd == actual_pwd:
            session['admin_logged_in'] = True
            return redirect('/admin')
        else:
            error = "Invalid Password"
    return render_template('admin_login.html', error=error)

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect('/admin/login')

@app.route('/admin/settings', methods=['POST'])
@admin_required
def admin_settings():
    m_mode = request.form.get('maintenance_mode', 'false')
    new_pass = request.form.get('admin_password')
    smtp_email = request.form.get('admin_smtp_email')
    smtp_pass = request.form.get('admin_smtp_password')
    
    g_client_id = request.form.get('google_client_id')
    g_client_secret = request.form.get('google_client_secret')
    
    yt_link = request.form.get('youtube_link')
    wa_number = request.form.get('support_whatsapp')
    
    set_sys_setting('maintenance_mode', m_mode)
    if new_pass and len(new_pass) > 2:
        set_sys_setting('admin_password', new_pass)
    if smtp_email:
        set_sys_setting('admin_smtp_email', smtp_email)
    if smtp_pass:
        set_sys_setting('admin_smtp_password', encrypt_pass(smtp_pass))
        
    if g_client_id is not None: set_sys_setting('google_client_id', g_client_id)
    if g_client_secret is not None: set_sys_setting('google_client_secret', g_client_secret)
    if yt_link is not None: set_sys_setting('youtube_link', yt_link)
    if wa_number is not None: set_sys_setting('support_whatsapp', wa_number)
        
    return redirect('/admin/settings?success=Settings updated')

@app.route('/admin/settings', methods=['GET'])
@admin_required
def admin_settings_view():
    m_mode = get_sys_setting('maintenance_mode', 'false')
    smtp_email = get_sys_setting('admin_smtp_email', '')
    smtp_pass = decrypt_pass(get_sys_setting('admin_smtp_password', '')) or ''
    g_client_id = get_sys_setting('google_client_id', '')
    g_client_secret = get_sys_setting('google_client_secret', '')
    yt_link = get_sys_setting('youtube_link', '')
    wa_number = get_sys_setting('support_whatsapp', '')
    return render_template('admin_settings.html', maintenance_mode=m_mode, smtp_email=smtp_email, smtp_pass=smtp_pass, g_client_id=g_client_id, g_client_secret=g_client_secret, yt_link=yt_link, wa_number=wa_number)

@app.route('/admin/logs')
@admin_required
def admin_logs():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT type, message, created_at FROM admin_logs ORDER BY id DESC LIMIT 100")
    logs = c.fetchall()
    conn.close()
    return render_template('admin_logs.html', logs=logs)

@app.route('/admin/users')
@admin_required
def admin_users():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT user_id, username, display_name, plan_name, plan_expiry, role FROM users")
    all_users = c.fetchall()
    conn.close()
    return render_template('admin_users.html', all_users=all_users)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
            
        session_token = session.get('session_token')
        if session_token:
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            c.execute("SELECT is_active FROM user_sessions WHERE session_token=? AND user_id=?", (session_token, session['user_id']))
            row = c.fetchone()
            if not row or row[0] != 1:
                conn.close()
                session.clear()
                return redirect(url_for('login', error='Your session has expired or was revoked. Please sign in again.'))
            c.execute("UPDATE user_sessions SET last_active_at=? WHERE session_token=?", (datetime.now().isoformat(), session_token))
            conn.commit()
            conn.close()
        return f(*args, **kwargs)
    return decorated_function

def establish_user_session(user_id):
    session_token = secrets.token_hex(32)
    session_id = "sess_" + secrets.token_hex(12)
    ip = request.headers.get('X-Forwarded-For', request.remote_addr) or '127.0.0.1'
    if ',' in ip:
        ip = ip.split(',')[0].strip()
    ua = request.headers.get('User-Agent', '')
    summary = get_device_summary(ua)
    now_str = datetime.now().isoformat()
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""INSERT INTO user_sessions (session_id, user_id, session_token, ip_address, user_agent, device_summary, created_at, last_active_at, is_active)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)""", (session_id, user_id, session_token, ip, ua, summary, now_str, now_str))
    conn.commit()
    conn.close()
    
    session['user_id'] = user_id
    session['session_token'] = session_token
    session['session_id'] = session_id
    session['csrf_token'] = secrets.token_hex(32)

def get_google_oauth_credentials():
    client_id = get_sys_setting('google_client_id', '') or os.environ.get('GOOGLE_CLIENT_ID', '')
    client_secret = get_sys_setting('google_client_secret', '') or os.environ.get('GOOGLE_CLIENT_SECRET', '')
    return client_id.strip(), client_secret.strip()

def get_google_redirect_uri():
    host = request.headers.get('X-Forwarded-Host') or request.host
    proto = request.headers.get('X-Forwarded-Proto') or request.scheme
    if request.is_secure:
        proto = 'https'
    return f"{proto}://{host}/login/google/callback"

@app.route('/login/google')
def login_google():
    client_id, _ = get_google_oauth_credentials()
    if not client_id:
        error_msg = "Google Sign-In is not configured yet. Please enter Google Client ID and Secret in Admin Settings."
        return render_template('login.html', error=error_msg)
        
    state = secrets.token_urlsafe(32)
    session['oauth_state'] = state
    redirect_uri = get_google_redirect_uri()
    
    params = {
        'client_id': client_id,
        'redirect_uri': redirect_uri,
        'response_type': 'code',
        'scope': 'openid email profile',
        'state': state,
        'access_type': 'online',
        'prompt': 'select_account'
    }
    auth_url = 'https://accounts.google.com/o/oauth2/v2/auth?' + urllib.parse.urlencode(params)
    return redirect(auth_url)

@app.route('/login/google/callback')
def google_callback():
    error = request.args.get('error')
    if error:
        return render_template('login.html', error=f"Google authentication canceled: {error}")
        
    code = request.args.get('code')
    state = request.args.get('state')
    saved_state = session.pop('oauth_state', None)
    
    if not code or not state or not saved_state or not hmac.compare_digest(state, saved_state):
        return render_template('login.html', error="Invalid or expired authentication session. Please try again.")
        
    client_id, client_secret = get_google_oauth_credentials()
    if not client_id or not client_secret:
        return render_template('login.html', error="Google OAuth credentials are not properly configured.")
        
    redirect_uri = get_google_redirect_uri()
    
    # 1. Exchange code for access token
    token_url = "https://oauth2.googleapis.com/token"
    token_payload = {
        'code': code,
        'client_id': client_id,
        'client_secret': client_secret,
        'redirect_uri': redirect_uri,
        'grant_type': 'authorization_code'
    }
    
    try:
        token_resp = requests.post(token_url, data=token_payload, timeout=10)
        token_data = token_resp.json()
    except Exception as e:
        return render_template('login.html', error="Network error communicating with Google authentication servers.")
        
    access_token = token_data.get('access_token')
    if not access_token:
        err_desc = token_data.get('error_description') or token_data.get('error') or "Failed to exchange token with Google"
        return render_template('login.html', error=f"Google authentication error: {err_desc}")
        
    # 2. Fetch user profile from Google UserInfo endpoint
    userinfo_url = "https://www.googleapis.com/oauth2/v2/userinfo"
    try:
        userinfo_resp = requests.get(userinfo_url, headers={'Authorization': f"Bearer {access_token}"}, timeout=10)
        user_info = userinfo_resp.json()
    except Exception as e:
        return render_template('login.html', error="Network error fetching verified profile from Google.")
        
    google_id = str(user_info.get('id', '')).strip()
    google_email = str(user_info.get('email', '')).strip().lower()
    display_name = user_info.get('name') or user_info.get('given_name') or 'Merchant'
    profile_pic = user_info.get('picture') or ''
    
    if not google_email:
        return render_template('login.html', error="Unable to obtain verified email address from your Google account.")
        
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # 3. Check for existing user by google_id or verified email
    c.execute("SELECT user_id, password_hash, google_id FROM users WHERE (google_id IS NOT NULL AND google_id = ?) OR LOWER(email) = ? OR LOWER(username) = ?", 
              (google_id, google_email, google_email))
    row = c.fetchone()
    
    if row:
        user_id = row[0]
        # Link google_id if not already set, update avatar if empty
        if not row[2]:
            c.execute("UPDATE users SET google_id = ?, auth_provider = 'google' WHERE user_id = ?", (google_id, user_id))
        if profile_pic:
            c.execute("UPDATE users SET profile_pic = ? WHERE user_id = ? AND (profile_pic IS NULL OR profile_pic = '')", (profile_pic, user_id))
        conn.commit()
        conn.close()
        add_sys_log(user_id, "Logged in via Google Account.")
    else:
        # 4. Create new user account - verified strictly through Google
        now_str = datetime.now().isoformat()
        username = google_email
        c.execute("""INSERT INTO users (username, email, google_id, display_name, profile_pic, auth_provider, created_at, role, plan_name)
                     VALUES (?, ?, ?, ?, ?, 'google', ?, 'merchant', 'Free')""",
                  (username, google_email, google_id, display_name, profile_pic, now_str))
        user_id = c.lastrowid
        conn.commit()
        conn.close()
        add_sys_log(user_id, f"Registered new merchant account via Google ({google_email}).")
        
    establish_user_session(user_id)
    return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        return render_template('login.html', error='Manual credentials are disabled. Please sign in using your verified Google Account.')
    return render_template('login.html')

@app.route('/login/2fa', methods=['GET', 'POST'])
def login_2fa():
    user_id = session.get('pending_2fa_user_id')
    if not user_id:
        return redirect(url_for('login'))
        
    error = None
    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT totp_secret_enc FROM users WHERE user_id=?", (user_id,))
        row = c.fetchone()
        conn.close()
        
        if row and row[0]:
            secret = decrypt_pass(row[0])
            if verify_totp_token(secret, code):
                session.pop('pending_2fa_user_id', None)
                establish_user_session(user_id)
                return redirect(url_for('dashboard'))
        error = "Invalid 2FA code. Please check your authenticator app and try again."
        
    return render_template('login_2fa.html', error=error)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        return render_template('register.html', error='Direct manual account creation is disabled. Please create your account with a verified Google Account.')
    return render_template('register.html')






@app.route('/admin')
@admin_required
def admin_panel():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    c.execute("SELECT user_id, username, display_name, plan_name, plan_expiry, role FROM users LIMIT 10")
    all_users = c.fetchall()
    
    c.execute("SELECT COUNT(*) FROM users")
    total_users = c.fetchone()[0] or 0
    c.execute("SELECT COUNT(*) FROM transactions")
    total_orders = c.fetchone()[0] or 0
    c.execute("SELECT COUNT(*) FROM transactions WHERE status='completed'")
    successful_orders = c.fetchone()[0] or 0
    c.execute("SELECT COUNT(*) FROM transactions WHERE status='pending'")
    pending_orders = c.fetchone()[0] or 0
    c.execute("SELECT COUNT(*) FROM transactions WHERE status IN ('failed', 'expired')")
    failed_orders = c.fetchone()[0] or 0
    c.execute("SELECT SUM(amount) FROM transactions WHERE status='completed'")
    total_revenue = c.fetchone()[0] or 0.0
    conn.close()
    
    stats = {
        "total_revenue": round(total_revenue, 2),
        "total_users": total_users,
        "total_orders": total_orders,
        "successful": successful_orders,
        "pending": pending_orders,
        "failed": failed_orders
    }
    
    m_mode = get_sys_setting('maintenance_mode', 'false')
    return render_template('admin.html', all_users=all_users, stats=stats, maintenance_mode=m_mode)


@app.route('/admin/transactions')
@admin_required
def admin_transactions():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        SELECT t.txn_id, t.amount, t.status, t.created_at, u.display_name, u.username, t.customer_name
        FROM transactions t
        LEFT JOIN users u ON t.user_id = u.user_id
        ORDER BY t.created_at DESC LIMIT 50
    """)
    recent_txns = c.fetchall()
    conn.close()
    return render_template('admin_transactions.html', txns=recent_txns)

@app.route('/admin/update_plan', methods=['POST'])
@admin_required
def admin_update_plan():
    target_user = request.form.get('target_user')
    new_plan = request.form.get('new_plan')
    expiry_days = int(request.form.get('expiry_days', 30))
    if expiry_days > 0:
        expiry_date = (datetime.now() + timedelta(days=expiry_days)).isoformat()
    else:
        expiry_date = None
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("UPDATE users SET plan_name=?, plan_expiry=?, links_used=0 WHERE user_id=?", (new_plan, expiry_date, target_user))
    conn.commit()
    conn.close()
    return redirect('/admin/users?success=Plan updated successfully')

@app.route('/admin/make_admin', methods=['POST'])
@login_required
def admin_make_admin():
    user_id = session['user_id']
    user_info = get_user(user_id)
    if user_info.get('role') != 'admin': return "Access Denied", 403
    
    target_user = request.form.get('target_user')
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("UPDATE users SET role='admin' WHERE user_id=?", (target_user,))
    conn.commit()
    conn.close()
    return redirect(url_for('admin_panel', success='User promoted to admin'))



@app.route('/logout')
def logout():
    session_token = session.get('session_token')
    if session_token:
        try:
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            c.execute("UPDATE user_sessions SET is_active=0 WHERE session_token=?", (session_token,))
            conn.commit()
            conn.close()
        except Exception:
            pass
    session.clear()
    return redirect(url_for('login'))

# ============================================
# FLASK WEB INTERFACE (DASHBOARD)
# ============================================

@app.route('/')
@app.route('/home')
@app.route('/landing')
def index():
    yt_link = get_sys_setting('youtube_link', '')
    wa_number = get_sys_setting('support_whatsapp', '')
    logged_in = 'user_id' in session
    return render_template('index.html', yt_link=yt_link, wa_number=wa_number, logged_in=logged_in)



@app.route('/mark_paid/<txn_id>', methods=['POST'])
@login_required
def mark_paid(txn_id):
    user_id = session['user_id']
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    c.execute("SELECT amount FROM transactions WHERE txn_id=? AND user_id=? AND status='pending'", (txn_id, user_id))
    txn = c.fetchone()
    
    if txn:
        amount = txn[0]
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute("UPDATE transactions SET status='completed', utr='MANUAL_VERIFY', paid_at=? WHERE txn_id=?", (now_str, txn_id))
        conn.commit()
        conn.close()
        
        # Send Notification to the Merchant
        threading.Thread(target=send_merchant_notification, args=(user_id, txn_id, amount, 'MANUAL_VERIFY', now_str)).start()
        
        return redirect('/dashboard?success=Transaction+manually+marked+as+paid')
        
    conn.close()
    return redirect('/dashboard?error=Transaction+not+found+or+already+processed')

@app.route('/dashboard')
@login_required
def dashboard():
    user_id = session['user_id']
    error = request.args.get('error')
    success = request.args.get('success')
    user_info = get_user(user_id)
    
    # Get stats
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT COUNT(*), SUM(amount) FROM transactions WHERE user_id=? AND status='completed'", (user_id,))
    total_count, total_amount = c.fetchone()
    
    # Recent transactions (all statuses)
    c.execute("SELECT txn_id, amount, utr, paid_at, status FROM transactions WHERE user_id=? ORDER BY created_at DESC LIMIT 15", (user_id,))
    txns = c.fetchall()
    
    # Chart Data: Revenue for last 7 days
    from datetime import datetime, timedelta
    chart_labels = []
    chart_data = []
    for i in range(6, -1, -1):
        dt = datetime.now() - timedelta(days=i)
        d_str = dt.strftime('%Y-%m-%d')
        c.execute("SELECT SUM(amount) FROM transactions WHERE user_id=? AND status='completed' AND paid_at LIKE ?", (user_id, f"{d_str}%"))
        daily_sum = c.fetchone()[0] or 0
        chart_labels.append(dt.strftime('%d %b'))
        chart_data.append(daily_sum)
  
    conn.close()
    
    return render_template('dashboard.html', 
                           user_info=user_info, 
                           total_count=total_count or 0, 
                           total_amount=f"{total_amount or 0:.2f}",
                           txns=txns,
                           chart_labels=chart_labels,
                           chart_data=chart_data,
                           error=error,
                           success=success)


@app.route('/update_credentials', methods=['POST'])
@login_required
def update_credentials():
    user_id = session['user_id']
    new_username = request.form.get('username')
    new_password = request.form.get('password')
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    try:
        if new_password:
            from werkzeug.security import generate_password_hash
            new_hash = generate_password_hash(new_password)
            c.execute("UPDATE users SET username=?, password_hash=? WHERE user_id=?", (new_username, new_hash, user_id))
        else:
            c.execute("UPDATE users SET username=? WHERE user_id=?", (new_username, user_id))
            
        conn.commit()
        success = 'Credentials updated successfully!'
    except sqlite3.IntegrityError:
        success = 'Error: Username already exists!'
    finally:
        conn.close()
        
    return redirect(url_for('settings', success=success))

@app.route('/connect')
@login_required
def connect_accounts():
    user_id = session['user_id']
    user_info = get_user(user_id)
    return render_template('connect.html', user_info=user_info)

@app.route('/save_account', methods=['POST'])
@login_required
def save_account():
    user_id = session['user_id']
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json
    
    if request.is_json:
        provider = request.json.get('provider', 'fampay')
        upi_id = request.json.get('upi_id')
        gmail = request.json.get('gmail')
        app_pass = request.json.get('app_pass')
    else:
        provider = request.form.get('provider', 'fampay')
        upi_id = request.form.get('upi_id')
        gmail = request.form.get('gmail')
        app_pass = request.form.get('app_pass')
    
    if upi_id and gmail and app_pass:
        if '@' not in upi_id:
            msg = 'Invalid UPI ID format! Must contain @'
            return jsonify({'status': 'error', 'message': msg}) if is_ajax else redirect(url_for('dashboard', error=msg))
            
        if '@' not in gmail or '.com' not in gmail:
            msg = 'Invalid Gmail Address!'
            return jsonify({'status': 'error', 'message': msg}) if is_ajax else redirect(url_for('dashboard', error=msg))
            
        # Verify the IMAP connection instantly
        try:
            import imaplib
            mail = imaplib.IMAP4_SSL('imap.gmail.com', timeout=15)
            mail.login(gmail, app_pass)
            mail.logout()
        except Exception as e:
            msg = 'Connection Failed! Please check your Gmail App Password.'
            return jsonify({'status': 'error', 'message': msg}) if is_ajax else redirect(url_for('dashboard', error=msg))
            
        save_user_account(user_id, upi_id, gmail, app_pass, provider)
        msg = 'Account Connected & Verified Perfectly!'
        return jsonify({'status': 'success', 'message': msg}) if is_ajax else redirect(url_for('dashboard', success=msg))
        
    return jsonify({'status': 'error', 'message': 'All fields are required.'}) if is_ajax else redirect(url_for('dashboard'))


@app.route('/preview_checkout')
@login_required
def preview_checkout():
    user_id = session['user_id']
    user_info = get_user(user_id)
    
    upi_id = user_info.get('upi_id') or "merchant@upi"
    display_name = user_info.get('business_name') or user_info.get('display_name') or "Merchant"
    theme = request.args.get('theme') or user_info.get('theme') or "default"
    accent_color = request.args.get('accent_color') or user_info.get('accent_color') or "#000000"
    if theme != 'custom':
        accent_color = "#000000"
    profile_pic = user_info.get('business_logo') or user_info.get('profile_pic')
    business_website = user_info.get('business_website') or ""
    
    return render_template('checkout.html',
                           txn_id="FAM12345678",
                           amount=499.00,
                           upi_id=upi_id,
                           display_name=display_name,
                           theme=theme,
                           accent_color=accent_color,
                           business_website=business_website,
                           api_key="preview",
                           callback_url="",
                           qr_url="https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=upi://pay?pa=merchant@upi&pn=Merchant&am=499",
                           payment_url="#",
                           profile_pic=profile_pic,
                           remaining_seconds=300)

@app.route('/settings')
@login_required
def settings():
    user_id = session['user_id']
    user_info = get_user(user_id)
    active_tab = request.args.get('tab', 'profile')
    if active_tab not in ('profile', 'security'):
        active_tab = 'profile'
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""SELECT session_id, ip_address, device_summary, created_at, last_active_at, session_token 
                 FROM user_sessions 
                 WHERE user_id=? AND is_active=1 
                 ORDER BY last_active_at DESC""", (user_id,))
    active_sessions = c.fetchall()
    conn.close()
    
    return render_template('settings.html', 
                           user_info=user_info, 
                           active_tab=active_tab,
                           active_sessions=active_sessions,
                           current_session_token=session.get('session_token'))

# 1. PROFILE - IDENTITY & ACCESS
@app.route('/settings/profile', methods=['POST'])
@login_required
def settings_profile():
    if not verify_csrf():
        return redirect(url_for('settings', tab='profile', error='Security check failed (invalid CSRF). Please try again.'))
        
    user_id = session['user_id']
    display_name = request.form.get('display_name', '').strip() or 'Merchant'
    username = request.form.get('username', '').strip()
    email_val = request.form.get('email', '').strip()
    
    if not username:
        return redirect(url_for('settings', tab='profile', error='Username cannot be empty.'))
        
    if email_val:
        if not re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', email_val):
            return redirect(url_for('settings', tab='profile', error='Invalid email format.'))
            
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT user_id FROM users WHERE username=? AND user_id != ?", (username, user_id))
    if c.fetchone():
        conn.close()
        return redirect(url_for('settings', tab='profile', error='Username is already taken by another account.'))
        
    if email_val:
        c.execute("SELECT user_id FROM users WHERE email=? AND user_id != ?", (email_val, user_id))
        if c.fetchone():
            conn.close()
            return redirect(url_for('settings', tab='profile', error='Email address is already in use.'))
            
    # Server-side 2MB file limit enforcement
    file = request.files.get('profile_pic')
    profile_pic_b64 = None
    if file and file.filename != '':
        file_data = file.read()
        if len(file_data) > 2 * 1024 * 1024:
            conn.close()
            return redirect(url_for('settings', tab='profile', error='Profile photo exceeds strict 2MB limit.'))
        c_type = file.content_type or 'image/jpeg'
        if not (c_type.startswith('image/jpeg') or c_type.startswith('image/png') or c_type.startswith('image/webp')):
            conn.close()
            return redirect(url_for('settings', tab='profile', error='Only JPG or PNG images are allowed.'))
        profile_pic_b64 = f"data:{c_type};base64," + base64.b64encode(file_data).decode('utf-8')
        
    if profile_pic_b64:
        c.execute("UPDATE users SET display_name=?, username=?, email=?, profile_pic=? WHERE user_id=?", 
                  (display_name, username, email_val, profile_pic_b64, user_id))
    else:
        c.execute("UPDATE users SET display_name=?, username=?, email=? WHERE user_id=?", 
                  (display_name, username, email_val, user_id))
    conn.commit()
    conn.close()
    
    return redirect(url_for('settings', tab='profile', success='Profile details updated successfully!'))

@app.route('/settings/request_mobile_otp', methods=['POST'])
@login_required
def settings_request_mobile_otp():
    if not verify_csrf():
        return jsonify({'status': 'error', 'message': 'CSRF verification failed'}), 403
        
    user_id = session['user_id']
    new_mobile = request.form.get('new_mobile', '').strip()
    if not re.match(r'^\+?[0-9]{10,13}$', new_mobile):
        return jsonify({'status': 'error', 'message': 'Invalid mobile number. Must be 10-13 digits.'}), 400
        
    otp = f"{secrets.randbelow(900000) + 100000}"
    expires = (datetime.now() + timedelta(minutes=5)).isoformat()
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO mobile_verification_otps (user_id, new_mobile, otp_code, expires_at) VALUES (?, ?, ?, ?)",
              (user_id, new_mobile, otp, expires))
    conn.commit()
    conn.close()
    
    add_sys_log(user_id, f"Mobile change OTP requested for {new_mobile}")
    return jsonify({
        'status': 'success',
        'message': f'OTP sent! (Verification Code: {otp})',
        'dev_otp': otp
    })

@app.route('/settings/verify_mobile_otp', methods=['POST'])
@login_required
def settings_verify_mobile_otp():
    if not verify_csrf():
        return jsonify({'status': 'error', 'message': 'CSRF verification failed'}), 403
        
    user_id = session['user_id']
    entered_otp = request.form.get('otp', '').strip()
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT new_mobile, otp_code, expires_at FROM mobile_verification_otps WHERE user_id=?", (user_id,))
    row = c.fetchone()
    
    if not row:
        conn.close()
        return jsonify({'status': 'error', 'message': 'No pending OTP verification request found.'}), 400
        
    new_mobile, otp_code, expires_at = row
    if datetime.now() > datetime.fromisoformat(expires_at):
        c.execute("DELETE FROM mobile_verification_otps WHERE user_id=?", (user_id,))
        conn.commit()
        conn.close()
        return jsonify({'status': 'error', 'message': 'OTP expired. Please request a new verification code.'}), 400
        
    if entered_otp != otp_code:
        conn.close()
        return jsonify({'status': 'error', 'message': 'Invalid verification code. Please check and retry.'}), 400
        
    c.execute("UPDATE users SET mobile=? WHERE user_id=?", (new_mobile, user_id))
    c.execute("DELETE FROM mobile_verification_otps WHERE user_id=?", (user_id,))
    conn.commit()
    conn.close()
    
    add_sys_log(user_id, f"Mobile verified & updated to {new_mobile}")
    return jsonify({'status': 'success', 'message': 'Mobile number verified and updated successfully!'})

@app.route('/settings/change_password', methods=['POST'])
@login_required
def settings_change_password():
    if not verify_csrf():
        return redirect(url_for('settings', tab='security', error='Security check failed (invalid CSRF).'))
        
    user_id = session['user_id']
    user_info = get_user(user_id)
    current_pass = request.form.get('current_password', '')
    new_pass = request.form.get('new_password', '')
    confirm_pass = request.form.get('confirm_password', '')
    logout_other = request.form.get('logout_other_devices')
    
    has_existing_pass = bool(user_info.get('password_hash'))
    if has_existing_pass:
        if not check_password_hash(user_info['password_hash'], current_pass):
            return redirect(url_for('settings', tab='security', error='Current password is incorrect.'))
        
    if len(new_pass) < 6:
        return redirect(url_for('settings', tab='security', error='New password must be at least 6 characters long.'))
        
    if new_pass != confirm_pass:
        return redirect(url_for('settings', tab='security', error='New password and confirmation do not match.'))
        
    new_hash = generate_password_hash(new_pass)
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("UPDATE users SET password_hash=? WHERE user_id=?", (new_hash, user_id))
    
    if logout_other:
        current_token = session.get('session_token')
        if current_token:
            c.execute("UPDATE user_sessions SET is_active=0 WHERE user_id=? AND session_token != ?", (user_id, current_token))
        else:
            c.execute("UPDATE user_sessions SET is_active=0 WHERE user_id=?", (user_id,))
            
    conn.commit()
    conn.close()
    
    action_text = "Account password updated." if has_existing_pass else "Account password created."
    add_sys_log(user_id, action_text)
    msg = 'Password saved successfully! You can now log in using your Gmail and password.' if not has_existing_pass else 'Password updated successfully!'
    if logout_other:
        msg += ' Other device sessions signed out.'
    return redirect(url_for('settings', tab='security', success=msg))

# 2. BUSINESS DETAILS - BRANDING
@app.route('/settings/business', methods=['POST'])
@login_required
def settings_business():
    if not verify_csrf():
        return redirect(url_for('settings', tab='business', error='Security check failed (invalid CSRF).'))
        
    user_id = session['user_id']
    business_name = request.form.get('business_name', '').strip()
    business_website = request.form.get('business_website', '').strip()
    business_support_email = request.form.get('business_support_email', '').strip()
    
    if business_website:
        if not (business_website.startswith('http://') or business_website.startswith('https://')):
            business_website = 'https://' + business_website
        try:
            parsed = urllib.parse.urlparse(business_website)
            if not parsed.netloc or '.' not in parsed.netloc:
                return redirect(url_for('settings', tab='business', error='Invalid website URL format.'))
            try:
                requests.head(business_website, timeout=2.5, allow_redirects=True)
            except Exception:
                add_sys_log(user_id, f"Website reachability notice for {business_website}")
        except Exception:
            return redirect(url_for('settings', tab='business', error='Invalid website URL format.'))
            
    file = request.files.get('business_logo')
    logo_b64 = None
    if file and file.filename != '':
        file_data = file.read()
        if len(file_data) > 2 * 1024 * 1024:
            return redirect(url_for('settings', tab='business', error='Business logo exceeds 2MB limit.'))
        c_type = file.content_type or 'image/png'
        if not (c_type.startswith('image/jpeg') or c_type.startswith('image/png') or c_type.startswith('image/webp')):
            return redirect(url_for('settings', tab='business', error='Only JPG or PNG images are allowed.'))
        logo_b64 = f"data:{c_type};base64," + base64.b64encode(file_data).decode('utf-8')
        
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    if logo_b64:
        c.execute("""UPDATE users SET business_name=?, business_website=?, business_support_email=?, business_logo=? 
                     WHERE user_id=?""", (business_name, business_website, business_support_email, logo_b64, user_id))
    else:
        c.execute("""UPDATE users SET business_name=?, business_website=?, business_support_email=? 
                     WHERE user_id=?""", (business_name, business_website, business_support_email, user_id))
    conn.commit()
    conn.close()
    
    return redirect(url_for('settings', tab='business', success='Business branding details saved!'))

# 3. PAYMENT SETTINGS - HARD GATE TTL & REDIRECT WHITELIST
@app.route('/settings/payment_rules', methods=['POST'])
@login_required
def settings_payment_rules():
    if not verify_csrf():
        return redirect(url_for('settings', tab='payment', error='Security check failed (invalid CSRF).'))
        
    user_id = session['user_id']
    user_info = get_user(user_id)
    expiry_mins_raw = request.form.get('payment_expiry_minutes', '5')
    success_url = request.form.get('success_redirect_url', '').strip()
    failed_url = request.form.get('failed_redirect_url', '').strip()
    allowed_domains = request.form.get('allowed_redirect_domains', '').strip()
    
    try:
        expiry_mins = int(expiry_mins_raw)
        if expiry_mins < 1 or expiry_mins > 1440:
            expiry_mins = 5
    except ValueError:
        expiry_mins = 5
        
    domain_list = [d.strip() for d in allowed_domains.split(',') if d.strip()]
    
    if success_url:
        if not is_safe_redirect_url(success_url, domain_list, user_info.get('business_website')):
            return redirect(url_for('settings', tab='payment', error='Success Redirect URL is not in your verified domains whitelist.'))
            
    if failed_url:
        if not is_safe_redirect_url(failed_url, domain_list, user_info.get('business_website')):
            return redirect(url_for('settings', tab='payment', error='Failed Redirect URL is not in your verified domains whitelist.'))
            
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""UPDATE users SET payment_expiry_minutes=?, success_redirect_url=?, failed_redirect_url=?, allowed_redirect_domains=? 
                 WHERE user_id=?""", (expiry_mins, success_url, failed_url, allowed_domains, user_id))
    conn.commit()
    conn.close()
    
    return redirect(url_for('settings', tab='payment', success='Payment rules saved! Expiry TTL is synchronized with payment verification.'))

# 4. API & WEBHOOK
@app.route('/settings/api_keys/regenerate', methods=['POST'])
@login_required
def settings_regenerate_keys():
    if not verify_csrf():
        return redirect(url_for('settings', tab='api', error='Security check failed (invalid CSRF).'))
        
    user_id = session['user_id']
    key_type = request.form.get('key_type', 'live').lower()
    
    raw_key = f"{key_type}_sk_" + secrets.token_hex(20)
    key_hash = hashlib.sha256(raw_key.encode('utf-8')).hexdigest()
    key_hint = "..." + raw_key[-4:]
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    if key_type == 'live':
        c.execute("UPDATE users SET live_api_key_hash=?, live_api_key_hint=?, api_key=? WHERE user_id=?", 
                  (key_hash, key_hint, raw_key, user_id))
    else:
        c.execute("UPDATE users SET test_api_key_hash=?, test_api_key_hint=? WHERE user_id=?", 
                  (key_hash, key_hint, user_id))
    conn.commit()
    conn.close()
    
    session['newly_generated_raw_key'] = {
        'key': raw_key,
        'type': key_type.upper()
    }
    
    add_sys_log(user_id, f"{key_type.upper()} API Key regenerated.")
    return redirect(url_for('settings', tab='api', success=f'{key_type.upper()} API Key generated! Please copy it now.'))

@app.route('/settings/notifications', methods=['POST'])
@login_required
def settings_notifications():
    if not verify_csrf():
        return redirect(url_for('settings', tab='api', error='Security check failed (invalid CSRF).'))
        
    user_id = session['user_id']
    bot_token = request.form.get('telegram_bot_token', '').strip()
    chat_id = request.form.get('telegram_chat_id', '').strip()
    
    token_enc = encrypt_pass(bot_token) if bot_token else None
    chat_enc = encrypt_pass(chat_id) if chat_id else None
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("UPDATE users SET telegram_bot_token_enc=?, telegram_chat_id_enc=? WHERE user_id=?", 
              (token_enc, chat_enc, user_id))
    conn.commit()
    conn.close()
    
    return redirect(url_for('settings', tab='api', success='Telegram notification credentials encrypted and saved!'))

@app.route('/settings/notifications/test', methods=['POST'])
@login_required
def settings_test_notifications():
    if not verify_csrf():
        return jsonify({'status': 'error', 'message': 'CSRF verification failed'}), 403
        
    user_id = session['user_id']
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT telegram_bot_token_enc, telegram_chat_id_enc, display_name FROM users WHERE user_id=?", (user_id,))
    row = c.fetchone()
    conn.close()
    
    if not row or not row[0] or not row[1]:
        return jsonify({'status': 'error', 'message': 'Please save your Telegram Bot Token and Chat ID first.'}), 400
        
    token = decrypt_pass(row[0])
    chat_id = decrypt_pass(row[1])
    name = row[2] or 'Merchant'
    
    try:
        res = requests.post(f"https://api.telegram.org/bot{token}/sendMessage", json={
            "chat_id": chat_id,
            "text": f"🚀 *NovaPay Test Alert*\n\nYour Telegram payment notifications are connected and working perfectly for *{name}*!",
            "parse_mode": "Markdown"
        }, timeout=5)
        data = res.json()
        if data.get('ok'):
            return jsonify({'status': 'success', 'message': 'Test notification successfully delivered to your Telegram!'})
        else:
            return jsonify({'status': 'error', 'message': data.get('description', 'Telegram API returned error.')}), 400
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Failed to connect to Telegram API: {str(e)}'}), 500

# 5. SECURITY - SESSIONS & 2FA
@app.route('/settings/revoke_session/<session_id>', methods=['POST'])
@login_required
def settings_revoke_session(session_id):
    if not verify_csrf():
        return redirect(url_for('settings', tab='security', error='Security check failed (invalid CSRF).'))
        
    user_id = session['user_id']
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("UPDATE user_sessions SET is_active=0 WHERE session_id=? AND user_id=?", (session_id, user_id))
    conn.commit()
    conn.close()
    return redirect(url_for('settings', tab='security', success='Session revoked successfully.'))

@app.route('/settings/logout_all_sessions', methods=['POST'])
@login_required
def settings_logout_all_sessions():
    if not verify_csrf():
        return redirect(url_for('settings', tab='security', error='Security check failed (invalid CSRF).'))
        
    user_id = session['user_id']
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("UPDATE user_sessions SET is_active=0 WHERE user_id=?", (user_id,))
    conn.commit()
    conn.close()
    session.clear()
    return redirect(url_for('login', success='You have been signed out from all devices.'))

@app.route('/settings/2fa/setup', methods=['POST'])
@login_required
def settings_setup_2fa():
    if not verify_csrf():
        return jsonify({'status': 'error', 'message': 'CSRF verification failed'}), 403
        
    user_id = session['user_id']
    user_info = get_user(user_id)
    secret = generate_totp_secret()
    session['pending_totp_secret'] = secret
    
    totp_uri = f"otpauth://totp/NovaPay:{user_info['username']}?secret={secret}&issuer=NovaPay"
    
    qr = qrcode.make(totp_uri)
    from io import BytesIO
    buffered = BytesIO()
    qr.save(buffered, format="PNG")
    qr_b64 = "data:image/png;base64," + base64.b64encode(buffered.getvalue()).decode("utf-8")
    
    return jsonify({
        "status": "success",
        "secret": secret,
        "qr_b64": qr_b64
    })

@app.route('/settings/2fa/verify', methods=['POST'])
@login_required
def settings_verify_2fa():
    if not verify_csrf():
        return redirect(url_for('settings', tab='security', error='Security check failed (invalid CSRF).'))
        
    user_id = session['user_id']
    code = request.form.get('code', '').strip()
    secret = session.get('pending_totp_secret')
    
    if not secret:
        return redirect(url_for('settings', tab='security', error='2FA setup expired. Please click Enable 2FA again.'))
        
    if verify_totp_token(secret, code):
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("UPDATE users SET totp_secret_enc=?, totp_enabled=1 WHERE user_id=?", 
                  (encrypt_pass(secret), user_id))
        conn.commit()
        conn.close()
        session.pop('pending_totp_secret', None)
        return redirect(url_for('settings', tab='security', success='Two-Factor Authentication successfully activated!'))
    else:
        return redirect(url_for('settings', tab='security', error='Invalid 6-digit authenticator code. Please try again.'))

@app.route('/settings/2fa/disable', methods=['POST'])
@login_required
def settings_disable_2fa():
    if not verify_csrf():
        return redirect(url_for('settings', tab='security', error='Security check failed (invalid CSRF).'))
        
    user_id = session['user_id']
    user_info = get_user(user_id)
    pwd = request.form.get('password', '')
    code = request.form.get('code', '').strip()
    
    if not check_password_hash(user_info['password_hash'], pwd):
        return redirect(url_for('settings', tab='security', error='Incorrect password.'))
        
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT totp_secret_enc FROM users WHERE user_id=?", (user_id,))
    row = c.fetchone()
    if row and row[0]:
        secret = decrypt_pass(row[0])
        if not verify_totp_token(secret, code):
            conn.close()
            return redirect(url_for('settings', tab='security', error='Invalid 2FA code.'))
            
    c.execute("UPDATE users SET totp_secret_enc=NULL, totp_enabled=0 WHERE user_id=?", (user_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('settings', tab='security', success='Two-Factor Authentication has been disabled.'))

# 6. APPEARANCE & CUSTOMIZATION
@app.route('/appearance', methods=['GET', 'POST'])
@app.route('/customize_appearance', methods=['GET', 'POST'])
@login_required
def appearance():
    user_id = session['user_id']
    user_info = get_user(user_id)
    
    if request.method == 'POST':
        if not verify_csrf():
            return redirect(url_for('appearance', error='Security check failed (invalid CSRF).'))
            
        theme = request.form.get('theme', 'default')
        if theme == 'custom':
            accent_color = request.form.get('accent_color', '#000000').strip()
            if not re.match(r'^#[0-9a-fA-F]{6}$', accent_color):
                accent_color = '#000000'
        else:
            accent_color = '#000000'
            
        layout_density = request.form.get('layout_density', 'comfortable')
            
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("UPDATE users SET theme=?, accent_color=?, layout_density=? WHERE user_id=?", 
                  (theme, accent_color, layout_density, user_id))
        conn.commit()
        conn.close()
        
        return redirect(url_for('appearance', success='Appearance settings updated successfully!'))
        
    return render_template('appearance.html', user_info=user_info)

@app.route('/settings/appearance', methods=['POST'])
@login_required
def settings_appearance():
    return appearance()

@app.route('/save_customize', methods=['POST'])
@login_required
def save_customize():
    return appearance()

@app.route('/delete_account')
@login_required
def delete_account():
    user_id = session['user_id']
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    # Just clear the payment details
    c.execute("UPDATE users SET upi_id=NULL, gmail=NULL, app_pass=NULL, api_key=NULL WHERE user_id=?", (user_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('connect_accounts', success='Account Connection Deleted!'))

@app.route('/payment_links')
@login_required
def payment_links():
    user_id = session['user_id']
    user_info = get_user(user_id)
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT txn_id, amount, status, created_at FROM transactions WHERE user_id=? ORDER BY created_at DESC", (user_id,))
    links = c.fetchall()
    conn.close()
    error = request.args.get('error')
    success = request.args.get('success')
    return render_template('payment_links.html', user_info=user_info, links=links, error=error, success=success)
    
@app.route('/transactions')
@login_required
def transactions():
    user_id = session['user_id']
    user_info = get_user(user_id)
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # Stats
    c.execute("SELECT SUM(amount), COUNT(*) FROM transactions WHERE user_id=? AND status='completed'", (user_id,))
    row = c.fetchone()
    collected_amount = row[0] or 0.0
    collected_count = row[1] or 0
    
    c.execute("SELECT COUNT(*) FROM transactions WHERE user_id=? AND status='pending'", (user_id,))
    pending_count = c.fetchone()[0] or 0
    
    c.execute("SELECT COUNT(*) FROM transactions WHERE user_id=? AND status='failed'", (user_id,))
    failed_count = c.fetchone()[0] or 0
    
    # Let's count expired (pending but past expires_at)
    now_iso = datetime.now().isoformat()
    c.execute("SELECT COUNT(*) FROM transactions WHERE user_id=? AND status='pending' AND expires_at < ?", (user_id, now_iso))
    expired_count = c.fetchone()[0] or 0
    
    # Fetch all transactions
    c.execute("SELECT txn_id, amount, status, created_at, utr FROM transactions WHERE user_id=? ORDER BY created_at DESC", (user_id,))
    txns = c.fetchall()
    conn.close()
    
    return render_template('transactions.html', 
                           user_info=user_info, 
                           collected_amount=collected_amount,
                           collected_count=collected_count,
                           pending_count=pending_count,
                           failed_count=failed_count,
                           expired_count=expired_count,
                           txns=txns)

@app.route('/generate_link', methods=['POST'])
@login_required
def generate_link():
    user_id = session['user_id']
    amount_raw = request.form.get('amount')
    expiry_mins_raw = request.form.get('expiry', '1440')
    customer_email = request.form.get('customer_email', '')
    user_info = get_user(user_id)
    
    if not user_info or not user_info.get('api_key'):
        return redirect(url_for('payment_links', error='Please connect account first'))

    try:
        amount = float(amount_raw)
        if amount <= 0: raise ValueError
        if amount == int(amount):
            amount += round(random.uniform(0.01, 0.99), 2)
        amount = round(amount, 2)
        expiry_mins = int(expiry_mins_raw)
    except Exception:
        return redirect(url_for('payment_links', error='Invalid amount or expiry'))

    txn_id = f"FAM{int(time.time())}{uuid.uuid4().hex[:4].upper()}"
    now = datetime.now()
    expires = now + timedelta(minutes=expiry_mins)

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # ATOMIC LIMIT CHECK
    c.execute('''
        UPDATE users 
        SET links_used = links_used + 1 
        WHERE user_id = ? AND (
            is_admin_bypass = 1 OR 
            links_used < (
                CASE plan_name 
                    WHEN 'Free' THEN 15 
                    WHEN 'Basic' THEN 31 
                    WHEN 'Pro' THEN 66 
                    ELSE 15 
                END
            )
        )
    ''', (user_id,))
    
    if c.rowcount == 0:
        conn.close()
        return redirect(url_for('payment_links', error='Your plan limit reached. Please upgrade to continue creating links.'))
    
    c.execute('''INSERT INTO transactions (txn_id, user_id, amount, status, created_at, expires_at, customer_email)
                 VALUES (?, ?, ?, 'pending', ?, ?, ?)''', 
              (txn_id, user_id, amount, now.isoformat(), expires.isoformat(), customer_email))
    
    c.execute("SELECT links_used, plan_name FROM users WHERE user_id = ?", (user_id,))
    usage_row = c.fetchone()
    if usage_row:
        l_used, p_name = usage_row
        limit = 15 if p_name == 'Free' else (31 if p_name == 'Basic' else (66 if p_name == 'Pro' else 15))
        if l_used == int(limit * 0.8) and limit > 1:
            threading.Thread(target=send_telegram_quota_alert, args=(user_id, l_used, limit, p_name)).start()

    conn.commit()
    conn.close()

    return redirect(url_for('payment_links', success='Payment link generated successfully!'))

# ============================================
# PAYMENT GATEWAY API & CHECKOUT
# ============================================


@app.route('/export/transactions')
def export_transactions():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    user_id = session['user_id']
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT txn_id, amount, utr, status, created_at, paid_at FROM transactions WHERE user_id=? ORDER BY created_at DESC", (user_id,))
    rows = c.fetchall()
    conn.close()
    
    import csv
    from io import StringIO
    from flask import Response
    
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['Transaction ID', 'Amount (INR)', 'UTR', 'Status', 'Created At', 'Paid At'])
    cw.writerows(rows)
    
    output = si.getvalue()
    return Response(output, mimetype="text/csv", headers={"Content-disposition": "attachment; filename=transactions.csv"})

@app.route('/api/create-order', methods=['POST'])
def api_create_order():
    api_key = request.headers.get('X-Fam-Key') or request.headers.get('Authorization') or (request.json.get('api_key') if request.is_json else None)
    if api_key and api_key.startswith('Bearer '):
        api_key = api_key[7:].strip()
    if not api_key:
        return jsonify({"status": "error", "message": "Missing API Key header (X-Fam-Key)"}), 401
        
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    key_hash = hashlib.sha256(api_key.strip().encode('utf-8')).hexdigest()
    c.execute("SELECT user_id, payment_expiry_minutes FROM users WHERE live_api_key_hash=? OR test_api_key_hash=? OR api_key=?", (key_hash, key_hash, api_key))
    user = c.fetchone()
    if not user:
        conn.close()
        return jsonify({"status": "error", "message": "Invalid API Key"}), 401
    
    user_id = user[0]
    merchant_ttl = int(user[1]) if len(user) > 1 and user[1] else 5
    data = request.json or {}
    
    amount_raw = data.get('amount')
    merchant_order_id = data.get('order_id')
    customer_name = data.get('customer_name')
    callback_url = data.get('callback_url')
    
    if not amount_raw:
        return jsonify({"status": "error", "message": "Missing amount"}), 400
        
    try:
        amount = float(amount_raw)
        if amount <= 0: raise ValueError
        # Dynamic Amount Logic
        if amount == int(amount):
            amount += round(random.uniform(0.01, 0.99), 2)
        amount = round(amount, 2)
    except ValueError:
        return jsonify({"status": "error", "message": "Invalid amount"}), 400

    txn_id = f"FAM{int(time.time())}{uuid.uuid4().hex[:4].upper()}"
    now = datetime.now()
    expires = now + timedelta(minutes=merchant_ttl)

    # ATOMIC LIMIT CHECK
    c.execute('''
        UPDATE users 
        SET links_used = links_used + 1 
        WHERE user_id = ? AND (
            is_admin_bypass = 1 OR 
            links_used < (
                CASE plan_name 
                    WHEN 'Free' THEN 15 
                    WHEN 'Basic' THEN 31 
                    WHEN 'Pro' THEN 66 
                    ELSE 15 
                END
            )
        )
    ''', (user_id,))
    
    if c.rowcount == 0:
        conn.close()
        return jsonify({"status": "error", "message": "Plan limit reached. Please upgrade to continue."}), 403
        
    c.execute('''INSERT INTO transactions (txn_id, user_id, amount, status, created_at, expires_at, merchant_order_id, customer_name, callback_url)
                 VALUES (?, ?, ?, 'pending', ?, ?, ?, ?, ?)''', 
              (txn_id, user_id, amount, now.isoformat(), expires.isoformat(), merchant_order_id, customer_name, callback_url))
              
    c.execute("SELECT links_used, plan_name FROM users WHERE user_id = ?", (user_id,))
    usage_row = c.fetchone()
    if usage_row:
        l_used, p_name = usage_row
        limit = 15 if p_name == 'Free' else (31 if p_name == 'Basic' else (66 if p_name == 'Pro' else 15))
        if l_used == int(limit * 0.8) and limit > 1:
            threading.Thread(target=send_telegram_quota_alert, args=(user_id, l_used, limit, p_name)).start()
            
    conn.commit()
    conn.close()
    
    payment_url = f"{request.host_url.rstrip('/')}/pay/{txn_id}"
    
    return jsonify({
        "status": "success",
        "payment_url": payment_url,
        "txn_id": txn_id,
        "expires_at": expires.isoformat()
    })

@app.route('/pay/<txn_id>', methods=['GET'])
def checkout_page_by_id(txn_id):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT user_id, amount, status, callback_url, expires_at FROM transactions WHERE txn_id = ?", (txn_id,))
    txn = c.fetchone()
    
    if not txn:
        conn.close()
        return "<h1>Error: Transaction not found</h1>", 404
        
    user_id, amount, status, callback_url, expires_at = txn
    
    conn.close()
    
    if status == 'completed':
        return f"""
        <html>
        <head>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Payment Completed</title>
        </head>
        <body style="font-family: Arial, sans-serif; background-color: #f8fafc; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; padding: 20px;">
            <div style="background-color: white; padding: 40px 20px; border-radius: 16px; box-shadow: 0 10px 25px rgba(0,0,0,0.05); text-align: center; max-width: 400px; width: 100%;">
                <div style="background-color: #ecfdf5; color: #10b981; width: 80px; height: 80px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 40px; margin: 0 auto 24px auto;">✓</div>
                <h2 style="color: #0f172a; margin: 0 0 12px 0; font-size: 24px;">Payment Completed</h2>
                <p style="color: #64748b; margin: 0; line-height: 1.5; font-size: 15px;">This payment link has already been paid successfully and is now closed.</p>
            </div>
        </body>
        </html>
        """
    
    user = get_user(user_id)
    if not user or not user.get('upi_id'):
        return "<h1>Error: Merchant account not configured properly</h1>", 400
        
    upi_id = user.get('upi_id')
    final_display_name = user.get('business_name') or user.get('display_name') or 'Merchant'
    final_logo = user.get('business_logo') or user.get('profile_pic')
    final_accent = user.get('accent_color') or '#4f46e5'
    final_callback = callback_url or user.get('success_redirect_url') or ''
    theme = user.get('theme') or 'premium'
    api_key = user.get('api_key') or ''
    provider = user.get('provider') or 'fampay'
    b_web = user.get('business_website') or ''
    fail_url = user.get('failed_redirect_url') or ''
    
    payment_url = f"upi://pay?pa={upi_id}&pn={urllib.parse.quote(final_display_name)}&tr={txn_id}&am={amount}&cu=INR"
    
    qr = qrcode.make(payment_url)
    qr_path = f"static/qr_{txn_id}.png"
    os.makedirs("static", exist_ok=True)
    qr.save(qr_path)
    
    remaining_seconds = 300
    if expires_at:
        try:
            exp_dt = datetime.fromisoformat(expires_at)
            diff = int((exp_dt - datetime.utcnow()).total_seconds())
            remaining_seconds = max(0, diff)
        except Exception:
            pass

    return render_template('checkout.html', 
                           amount=f"{amount:.2f}",
                           txn_id=txn_id,
                           api_key=api_key,
                           payment_url=payment_url,
                           qr_url=f"/qr/{txn_id}",
                           upi_id=upi_id,
                           display_name=final_display_name,
                           business_website=b_web or '',
                           accent_color=final_accent,
                           profile_pic=final_logo,
                           theme=theme or 'premium',
                           status=status,
                           callback_url=final_callback,
                           failed_redirect_url=fail_url or '',
                           expires_at=expires_at,
                           remaining_seconds=remaining_seconds,
                           provider=provider or 'fampay')

@app.route('/pay', methods=['GET'])
def checkout_page_legacy():
    api_key = request.args.get('api_key')
    amount_raw = request.args.get('amount')

    if not api_key or not amount_raw:
        return "<h1>Error: Missing api_key or amount</h1>", 400

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    key_hash = hashlib.sha256(api_key.strip().encode('utf-8')).hexdigest()
    c.execute("SELECT user_id, upi_id, display_name, theme, provider, payment_expiry_minutes FROM users WHERE live_api_key_hash = ? OR test_api_key_hash = ? OR api_key = ?", (key_hash, key_hash, api_key))
    user = c.fetchone()
    
    if not user or not user[1]:
        conn.close()
        return "<h1>Error: Invalid API Key or Not Configured</h1>", 401
    
    user_id, upi_id, display_name, theme, provider, merchant_ttl = user
    merchant_ttl = merchant_ttl if merchant_ttl else 5

    try:
        amount = float(amount_raw)
        if amount <= 0: raise ValueError
        # Dynamic Amount Logic
        if amount == int(amount):
            amount += round(random.uniform(0.01, 0.99), 2)
        amount = round(amount, 2)
    except ValueError:
        conn.close()
        return "<h1>Error: Invalid amount</h1>", 400

    expiry_mins = request.args.get('expiry')
    try:
        expiry_mins = int(expiry_mins) if expiry_mins else merchant_ttl
    except ValueError:
        expiry_mins = merchant_ttl

    txn_id = f"FAM{int(time.time())}{uuid.uuid4().hex[:4].upper()}"
    now = datetime.now()
    expires = now + timedelta(minutes=expiry_mins)

    c.execute('''INSERT INTO transactions (txn_id, user_id, amount, status, created_at, expires_at)
                 VALUES (?, ?, ?, 'pending', ?, ?)''', 
              (txn_id, user_id, amount, now.isoformat(), expires.isoformat()))
    conn.commit()
    conn.close()

    return redirect(url_for('checkout_page_by_id', txn_id=txn_id))


@app.route('/qr/<txn_id>')
def serve_qr(txn_id):
    qr_path = f"static/qr_{txn_id}.png"
    if os.path.exists(qr_path):
        return send_file(qr_path, mimetype='image/png')
    return jsonify({"error": "QR code not found"}), 404



@app.route('/api/cancel_txn', methods=['POST'])
def cancel_txn():
    txn_id = request.json.get('txn_id')
    if not txn_id:
        return jsonify({'status': 'error'}), 400
        
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("UPDATE transactions SET status='failed' WHERE txn_id=? AND status='pending'", (txn_id,))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success'})

@app.route('/api/submit_utr', methods=['POST'])
def submit_utr():
    txn_id = request.json.get('txn_id')
    utr = request.json.get('utr')
    if not txn_id or not utr:
        return jsonify({'status': 'error', 'message': 'Missing data'}), 400
        
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    # Only update if pending
    c.execute("UPDATE transactions SET utr=? WHERE txn_id=? AND status='pending'", (utr, txn_id))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success'})

@app.route('/api/verify', methods=['GET'])
def verify_api():
    api_key = request.args.get('api_key')
    txn_id = request.args.get('txn_id')

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    if api_key:
        key_hash = hashlib.sha256(api_key.strip().encode('utf-8')).hexdigest()
        c.execute("SELECT user_id FROM users WHERE live_api_key_hash=? OR test_api_key_hash=? OR api_key=?", (key_hash, key_hash, api_key))
        user = c.fetchone()
        if not user:
            conn.close()
            return jsonify({"status": "error", "message": "Invalid API Key"}), 401
        c.execute("SELECT status, amount, utr, paid_at FROM transactions WHERE txn_id = ? AND user_id = ?", (txn_id, user[0]))
    else:
        # Allow checking by txn_id alone for the checkout page polling
        c.execute("SELECT status, amount, utr, paid_at FROM transactions WHERE txn_id = ?", (txn_id,))
        
    row = c.fetchone()
    conn.close()

    if not row:
        return jsonify({"status": "error", "message": "Transaction not found"}), 404

    status, amount, utr, paid_at = row
    return jsonify({
        "status": status,
        "data": {
            "txn_id": txn_id,
            "amount": amount,
            "utr": utr if utr else "",
            "paid_at": paid_at if paid_at else ""
        }
    })

# ============================================
# GMAIL BACKGROUND READER & WEBHOOK DISPATCHER
# ============================================

def add_sys_log(user_id, msg):
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute("INSERT INTO system_logs (user_id, log_msg, log_time) VALUES (?, ?, ?)", (user_id, msg, now_str))
        # Keep only last 100 logs per user to avoid DB bloat
        c.execute("DELETE FROM system_logs WHERE id NOT IN (SELECT id FROM system_logs WHERE user_id=? ORDER BY id DESC LIMIT 100)", (user_id,))
        conn.commit()
        conn.close()
    except Exception as e:
        print("Log error:", e)

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

def send_email_receipt(user_id, customer_email, txn_id, amount, utr, date_str):
    try:
        if not customer_email or '@' not in customer_email: return
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT gmail, app_pass, display_name FROM users WHERE user_id=?", (user_id,))
        row = c.fetchone()
        conn.close()
        if not row: return
        
        gmail, app_pass_enc, display_name = row
        if not gmail or not app_pass_enc: return
        
        app_pass = decrypt_pass(app_pass_enc)
        display_name = display_name if display_name else "Merchant"
        
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f"Payment Receipt - {display_name}"
        msg['From'] = f"{display_name} <{gmail}>"
        msg['To'] = customer_email
        
        html = f'''
        <html>
        <body style="font-family: Arial, sans-serif; background-color: #f4f4f5; padding: 20px;">
            <div style="max-w-md mx-auto background-color: #ffffff; padding: 30px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); max-width: 400px; margin: 0 auto;">
                <div style="text-align: center; margin-bottom: 20px;">
                    <div style="background-color: #4f46e5; color: white; width: 60px; height: 60px; border-radius: 50%; display: inline-flex; align-items: center; justify-content: center; font-size: 24px; font-weight: bold; margin-bottom: 10px;">✓</div>
                    <h2 style="color: #1e293b; margin: 0;">Payment Successful</h2>
                    <p style="color: #64748b; margin-top: 5px; font-size: 14px;">Receipt from {display_name}</p>
                </div>
                <div style="text-align: center; margin-bottom: 30px;">
                    <h1 style="color: #0f172a; font-size: 36px; margin: 0;">₹{amount}</h1>
                </div>
                <div style="border-top: 1px solid #e2e8f0; padding-top: 20px;">
                    <div style="margin-bottom: 10px;">
                        <span style="color: #64748b; font-size: 12px; text-transform: uppercase;">Transaction ID</span><br>
                        <strong style="color: #1e293b; font-family: monospace;">{txn_id}</strong>
                    </div>
                    <div style="margin-bottom: 10px;">
                        <span style="color: #64748b; font-size: 12px; text-transform: uppercase;">Bank UTR / Ref No</span><br>
                        <strong style="color: #10b981; font-family: monospace;">{utr}</strong>
                    </div>
                    <div style="margin-bottom: 10px;">
                        <span style="color: #64748b; font-size: 12px; text-transform: uppercase;">Date</span><br>
                        <strong style="color: #1e293b;">{date_str}</strong>
                    </div>
                </div>
                <div style="text-align: center; margin-top: 30px; color: #94a3b8; font-size: 12px;">
                    Powered by NovaPay
                </div>
            </div>
        </body>
        </html>
        '''
        part = MIMEText(html, 'html')
        msg.attach(part)
        
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login(gmail, app_pass)
        server.sendmail(gmail, customer_email, msg.as_string())
        server.quit()
        add_sys_log(user_id, f"Email receipt sent to {customer_email}")
    except Exception as e:
        print(f"Email failed: {e}")

def send_merchant_notification(user_id, txn_id, amount, utr, date_str):
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT email, gmail, display_name FROM users WHERE user_id=?", (user_id,))
        row = c.fetchone()
        conn.close()
        
        if not row: return
        merchant_email, merchant_gmail, display_name = row
        
        final_email = merchant_email if merchant_email and '@' in merchant_email else merchant_gmail
        if not final_email or '@' not in final_email: return
        
        display_name = display_name if display_name else "Merchant"
        
        # Use provided credentials explicitly
        sender_email = "karanbhaiya699@gmail.com"
        sender_pass = "labgiftepzvdjazp"
        
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f"Success! New Payment Received: ₹{amount}"
        msg['From'] = f"NovaPay System <{sender_email}>"
        msg['To'] = final_email
        
        html = f'''
        <html>
        <body style="font-family: Arial, sans-serif; background-color: #f4f4f5; padding: 20px;">
            <div style="max-w-md mx-auto background-color: #ffffff; padding: 30px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); max-width: 400px; margin: 0 auto;">
                <div style="text-align: center; margin-bottom: 20px;">
                    <div style="background-color: #10b981; color: white; width: 60px; height: 60px; border-radius: 50%; display: inline-flex; align-items: center; justify-content: center; font-size: 24px; font-weight: bold; margin-bottom: 10px;">₹</div>
                    <h2 style="color: #1e293b; margin: 0;">Payment Received!</h2>
                    <p style="color: #64748b; margin-top: 5px; font-size: 14px;">Hello {display_name}, you just received a new payment.</p>
                </div>
                <div style="text-align: center; margin-bottom: 30px;">
                    <h1 style="color: #0f172a; font-size: 36px; margin: 0;">₹{amount}</h1>
                </div>
                <div style="border-top: 1px solid #e2e8f0; padding-top: 20px;">
                    <div style="margin-bottom: 10px;">
                        <span style="color: #64748b; font-size: 12px; text-transform: uppercase;">Transaction ID</span><br>
                        <strong style="color: #1e293b; font-family: monospace;">{txn_id}</strong>
                    </div>
                    <div style="margin-bottom: 10px;">
                        <span style="color: #64748b; font-size: 12px; text-transform: uppercase;">Bank UTR</span><br>
                        <strong style="color: #10b981; font-family: monospace;">{utr}</strong>
                    </div>
                    <div style="margin-bottom: 10px;">
                        <span style="color: #64748b; font-size: 12px; text-transform: uppercase;">Date</span><br>
                        <strong style="color: #1e293b;">{date_str}</strong>
                    </div>
                </div>
                <div style="text-align: center; margin-top: 30px; color: #94a3b8; font-size: 12px;">
                    Powered by NovaPay
                </div>
            </div>
        </body>
        </html>
        '''
        part = MIMEText(html, 'html')
        msg.attach(part)
        
        server = smtplib.SMTP_SSL("smtp.gmail.com", 465)
        server.login(sender_email, sender_pass)
        server.sendmail(sender_email, final_email, msg.as_string())
        server.quit()
    except Exception as e:
        print(f"Error sending merchant notification: {e}")
        
def send_telegram_alert(user_id, txn_id, amount, utr):
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT telegram_bot_token_enc, telegram_chat_id_enc, display_name FROM users WHERE user_id=?", (user_id,))
        row = c.fetchone()
        conn.close()
        if row and row[0] and row[1]:
            token = decrypt_pass(row[0])
            chat_id = decrypt_pass(row[1])
            name = row[2] or "Merchant"
            msg = (f"🔔 *Payment Received!*\n\n"
                   f"💰 *Amount:* ₹{amount:.2f}\n"
                   f"🔖 *Txn ID:* `{txn_id}`\n"
                   f"🏦 *Bank UTR:* `{utr}`\n"
                   f"🏪 *Store:* {name}\n"
                   f"⏰ *Date:* {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            requests.post(f"https://api.telegram.org/bot{token}/sendMessage", json={
                "chat_id": chat_id,
                "text": msg,
                "parse_mode": "Markdown"
            }, timeout=5)
    except Exception as e:
        print(f"Telegram alert error: {e}")

def send_telegram_quota_alert(user_id, l_used, limit, p_name):
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT telegram_bot_token_enc, telegram_chat_id_enc FROM users WHERE user_id=?", (user_id,))
        row = c.fetchone()
        conn.close()
        if row and row[0] and row[1]:
            token = decrypt_pass(row[0])
            chat_id = decrypt_pass(row[1])
            msg = (f"⚠️ *Low Quota Alert!*\n\n"
                   f"You have used *{l_used}/{limit}* payment links on your *{p_name}* plan.\n"
                   f"Please upgrade soon to avoid interruption.")
            requests.post(f"https://api.telegram.org/bot{token}/sendMessage", json={
                "chat_id": chat_id,
                "text": msg,
                "parse_mode": "Markdown"
            }, timeout=5)
    except Exception as e:
        print(f"Telegram quota alert error: {e}")

def send_webhook(user_id, callback_url, txn_id, merchant_order_id, amount, utr):
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT api_key, live_api_key_hash FROM users WHERE user_id=?", (user_id,))
        row = c.fetchone()
        api_key = row[0] if row and row[0] else "default_secret"
        
        timestamp = int(time.time())
        nonce = secrets.token_hex(16)
        
        payload = {
            "status": "success",
            "txn_id": txn_id,
            "merchant_order_id": merchant_order_id,
            "amount": amount,
            "utr": utr,
            "timestamp": timestamp,
            "nonce": nonce
        }
        payload_str = json.dumps(payload)
        
        # Pro Logic: HMAC-SHA256 Signature with Timestamp for Webhook Security & Anti-Replay
        sign_material = f"{timestamp}.{payload_str}"
        signature = hmac.new(api_key.encode('utf-8'), sign_material.encode('utf-8'), hashlib.sha256).hexdigest()
        legacy_sig = hmac.new(api_key.encode('utf-8'), payload_str.encode('utf-8'), hashlib.sha256).hexdigest()
        
        headers = {
            "Content-Type": "application/json",
            "X-NovaPay-Signature": signature,
            "X-NovaPay-Timestamp": str(timestamp),
            "X-NovaPay-Nonce": nonce,
            "X-FamGateway-Signature": legacy_sig # backward compatibility
        }
        
        # Record nonce in database
        try:
            c.execute("INSERT OR REPLACE INTO webhook_nonces (nonce, created_at) VALUES (?, ?)", (nonce, datetime.now().isoformat()))
            conn.commit()
        except Exception:
            pass
            
        response_code = 0
        response_body = ""
        try:
            resp = requests.post(callback_url, data=payload_str, headers=headers, timeout=5)
            response_code = resp.status_code
            response_body = resp.text[:500]
        except Exception as e:
            response_body = str(e)[:500]
            
        now_str = datetime.now().isoformat()
        c.execute('''INSERT INTO webhook_logs (user_id, txn_id, url, payload, response_code, response_body, sent_at)
                     VALUES (?, ?, ?, ?, ?, ?, ?)''',
                  (user_id, txn_id, callback_url, payload_str, response_code, response_body, now_str))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Webhook failed for {txn_id}: {e}")
# Global dict to hold persistent IMAP connections
imap_connections = {}

def monitor_gmails():
    processed_msg_ids = set()
    while True:
        try:
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            c.execute("SELECT user_id, gmail, app_pass FROM users WHERE gmail IS NOT NULL AND app_pass IS NOT NULL")
            users = c.fetchall()
            conn.close()

            # Optional: Cleanup removed users from connections
            valid_user_ids = [u[0] for u in users]
            for uid in list(imap_connections.keys()):
                if uid not in valid_user_ids:
                    try:
                        imap_connections[uid].logout()
                    except: pass
                    del imap_connections[uid]

            for user_id, gmail_user, app_pass in users:
                if not gmail_user or not app_pass: continue
                
                mail = imap_connections.get(user_id)
                try:
                    if not mail:
                        # Connect and login if no active connection
                        mail = imaplib.IMAP4_SSL("imap.gmail.com", timeout=10)
                        mail.login(gmail_user, decrypt_pass(app_pass))
                        imap_connections[user_id] = mail
                    
                    try:
                        mail.select("INBOX")
                    except:
                        # Connection might have died, reconnect
                        mail = imaplib.IMAP4_SSL("imap.gmail.com", timeout=10)
                        mail.login(gmail_user, decrypt_pass(app_pass))
                        mail.select("INBOX")
                        imap_connections[user_id] = mail

                    status, messages = mail.search(None, '(UNSEEN)')

                    if status == 'OK' and messages[0]:
                        msg_nums = messages[0].split()
                        
                        for num in msg_nums:
                            status, data = mail.fetch(num, '(RFC822)')
                            if status != 'OK': continue

                            msg = email.message_from_bytes(data[0][1])
                            
                            # --- ADVANCED SECURITY LOGIC ---
                            # 1. Message-ID Replay Guard (Prevents double verification)
                            msg_id = msg.get("Message-ID")
                            if msg_id:
                                if msg_id in processed_msg_ids:
                                    continue
                                processed_msg_ids.add(msg_id)
                                # Keep set size manageable
                                if len(processed_msg_ids) > 10000:
                                    processed_msg_ids.clear()
                                    
                            # 2. DKIM Anti-Fraud Check (Rejects spoofed fake emails)
                            auth_results = msg.get("Authentication-Results", "").lower()
                            if auth_results and ("dkim=fail" in auth_results or "spf=fail" in auth_results):
                                add_sys_log(user_id, "REJECTED: Spoofed/Fake Email detected (DKIM/SPF failed).")
                                continue # Reject forged emails completely
                            # --------------------------------
                            
                            body = ""
                            if msg.is_multipart():
                                for part in msg.walk():
                                    ctype = part.get_content_type()
                                    if ctype == "text/plain":
                                        body += part.get_payload(decode=True).decode('utf-8', errors='ignore') + " "
                                    elif ctype == "text/html":
                                        html = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                                        body += re.sub(r'<[^>]+>', ' ', html) + " "
                            else:
                                payload = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
                                if msg.get_content_type() == "text/html":
                                    body = re.sub(r'<[^>]+>', ' ', payload)
                                else:
                                    body = payload

                            text = str(msg.get("Subject", "")) + " " + body
                            amt_match = re.search(r'(?:Rs\.?|INR|\u20B9)\s*([\d,]+\.?\d*)', text, re.IGNORECASE)
                            utr_match = re.search(r'(?:UPI\s*Ref(?:erence)?\s*(?:No\.?)?|UTR|Txn\s*ID|Transaction\s*ID|RRN|Order\s*ID|Reference\s*ID)\s*[:.-]?\s*([A-Za-z0-9]{8,30})', text, re.IGNORECASE)

                            if amt_match and utr_match:
                                amount = float(amt_match.group(1).replace(',', ''))
                                utr = utr_match.group(1)
                                add_sys_log(user_id, f"Parsed Payment: â‚¹{amount} with UTR: {utr}")

                                conn_db = sqlite3.connect(DB_FILE)
                                c_db = conn_db.cursor()
                                now_str = datetime.now().isoformat()
                                
                                # Check if user manually submitted this UTR
                                c_db.execute("SELECT txn_id, status, callback_url, merchant_order_id, expires_at FROM transactions WHERE utr=?", (utr,))
                                row = c_db.fetchone()
                                txn_completed_now = False
                                
                                if row:
                                    t_id, t_status, t_cb, t_m_id, t_exp = row
                                    # Hard Gate: Expire order if time crossed
                                    if t_exp and now_str > t_exp:
                                        c_db.execute("UPDATE transactions SET status='expired' WHERE txn_id=?", (t_id,))
                                        conn_db.commit()
                                        add_sys_log(user_id, f"HARD REJECT: Payment with UTR {utr} arrived after expiry window ({t_exp}). Marked as expired.")
                                    elif t_status == 'pending':
                                        c_db.execute("UPDATE transactions SET status='completed', paid_at=? WHERE txn_id=?", (now_str, t_id))
                                        conn_db.commit()
                                        txn_completed_now = True
                                        completed_txn = (t_id, 'completed', t_cb, t_m_id)
                                else:
                                    # Amount-based fallback (if UTR not submitted by user yet)
                                    c_db.execute("""SELECT txn_id, callback_url, merchant_order_id, expires_at 
                                                    FROM transactions 
                                                    WHERE user_id=? AND status='pending' AND ABS(amount - ?) < 0.01 
                                                      AND (utr IS NULL OR utr='') 
                                                    ORDER BY created_at ASC LIMIT 1""", (user_id, amount))
                                    pending_txn = c_db.fetchone()
                                    if pending_txn:
                                        p_id, p_cb, p_m_id, p_exp = pending_txn
                                        if p_exp and now_str > p_exp:
                                            c_db.execute("UPDATE transactions SET status='expired' WHERE txn_id=?", (p_id,))
                                            conn_db.commit()
                                            add_sys_log(user_id, f"HARD REJECT: Amount match ₹{amount} arrived after order expiry ({p_exp}). Marked as expired.")
                                        else:
                                            c_db.execute("UPDATE transactions SET status='completed', utr=?, paid_at=? WHERE txn_id=?", (utr, now_str, p_id))
                                            conn_db.commit()
                                            txn_completed_now = True
                                            completed_txn = (p_id, 'completed', p_cb, p_m_id)
                                        
                                conn_db.close()
                                
                                # Fire webhook, Telegram alert and Email if completed now
                                if txn_completed_now:
                                    add_sys_log(user_id, f"Match Success! Verified Txn ID: {completed_txn[0]}")
                                    
                                    # Dispatch Instant Telegram Alert
                                    threading.Thread(target=send_telegram_alert, args=(user_id, completed_txn[0], amount, utr)).start()
                                    
                                    # Fetch email just in case
                                    conn_fetch = sqlite3.connect(DB_FILE)
                                    c_fetch = conn_fetch.cursor()
                                    c_fetch.execute("SELECT customer_email FROM transactions WHERE txn_id=?", (completed_txn[0],))
                                    email_row = c_fetch.fetchone()
                                    conn_fetch.close()
                                    
                                    if email_row and email_row[0]:
                                        threading.Thread(target=send_email_receipt, args=(user_id, email_row[0], completed_txn[0], amount, utr, now_str)).start()
                                    
                                    # Send Notification to the Merchant
                                    threading.Thread(target=send_merchant_notification, args=(user_id, completed_txn[0], amount, utr, now_str)).start()
                                    
                                    if completed_txn[2]:
                                        threading.Thread(target=send_webhook, args=(user_id, completed_txn[2], completed_txn[0], completed_txn[3], amount, utr)).start()
                                    
                except Exception as e:
                    # If any error (e.g. connection drop), remove from persistent dict to force reconnect next loop
                    if user_id in imap_connections:
                        del imap_connections[user_id]
        except Exception as e:
            pass
        time.sleep(1.5)

@app.route('/api_docs')
@login_required
def api_docs():
    user_id = session['user_id']
    user_info = get_user(user_id)
    return render_template('api_docs.html', user_info=user_info)

@app.route('/regenerate_key', methods=['POST'])
@login_required
def regenerate_key():
    user_id = session['user_id']
    new_api_key = 'FAM' + secrets.token_hex(16).upper()
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('UPDATE users SET api_key = ? WHERE user_id = ?', (new_api_key, user_id))
    conn.commit()
    conn.close()
    
    flash('API Key successfully regenerated! Update your webhook integrations.')
    return redirect(url_for('api_docs', success='API Key successfully regenerated!'))


# ============================================
# WEBHOOK LOGS & RETRY
# ============================================

@app.route('/api/retry-webhook/<int:log_id>', methods=['POST'])
def retry_webhook(log_id):
    if 'user_id' not in session: return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT url, payload FROM webhook_logs WHERE id = ? AND user_id = ?", (log_id, session['user_id']))
    log = c.fetchone()
    
    if not log:
        conn.close()
        return jsonify({'status': 'error', 'message': 'Log not found'}), 404
        
    url, payload = log
    import json
    status = "failed"
    try:
        res = requests.post(url, json=json.loads(payload), timeout=5)
        if res.status_code in [200, 201]:
            status = "success"
    except:
        pass
        
    c.execute("UPDATE webhook_logs SET status = ?, created_at = CURRENT_TIMESTAMP WHERE id = ?", (status, log_id))
    conn.commit()
    conn.close()
    
    return jsonify({'status': status})

# ============================================
# SUPER ADMIN PANEL
# ============================================

@app.route('/admin-karan', methods=['GET', 'POST'])
def super_admin():
    return redirect('/admin/login')

@app.route('/admin-karan/ban/<int:user_id>', methods=['POST'])
def admin_ban(user_id):
    if not session.get('is_admin'): return redirect(url_for('super_admin'))
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    # To ban, we just wipe their API key and credentials so they can't login or use the gateway
    c.execute("UPDATE users SET password_hash = 'BANNED', api_key = NULL, gmail = NULL, app_pass = NULL WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('super_admin'))

@app.route('/webhook_logs')
def webhook_logs():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT id, txn_id, url, payload, response_code, response_body, sent_at FROM webhook_logs WHERE user_id=? ORDER BY sent_at DESC LIMIT 50", (session['user_id'],))
    logs = c.fetchall()
    conn.close()
    
    return render_template('webhook_logs.html', logs=logs)

@app.route('/api/system_logs')
def system_logs_api():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT log_msg, log_time FROM system_logs WHERE user_id=? ORDER BY id DESC LIMIT 50", (session['user_id'],))
    logs = c.fetchall()
    conn.close()
    
    return jsonify([{"msg": log[0], "time": log[1]} for log in logs])

# ============================================
# SUBSCRIPTION PLAN SYSTEM
@app.route('/plans')
@login_required
def plans():
    user_info = get_user(session['user_id'])
    return render_template('subscription.html', user_info=user_info)

@app.route('/upgrade_plan', methods=['POST'])
@login_required
def upgrade_plan():
    target_user_id = session['user_id']
    plan_name = request.form.get('plan_name')
    if plan_name not in ['Basic', 'Pro']:
        return redirect(url_for('payment_links', error='Invalid plan selected.'))
        
    amount = 30.0 if plan_name == 'Basic' else 60.0
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    # Find the Admin user (assumed role='admin', or fallback to user_id=1)
    c.execute("SELECT user_id FROM users WHERE role='admin' ORDER BY user_id ASC LIMIT 1")
    admin_row = c.fetchone()
    if not admin_row:
        # Fallback if no admin is set, fallback to user_id 1
        admin_row = (1,)
        
    admin_user_id = admin_row[0]
    
    txn_id = f"SUB{int(time.time())}{uuid.uuid4().hex[:4].upper()}"
    now = datetime.now()
    expires = now + timedelta(minutes=15)
    merchant_order_id = f"sub_upgrade|{target_user_id}|{plan_name}"
    callback_url = f"{request.host_url.rstrip('/')}/api/subscription_webhook"
    
    c.execute('''INSERT INTO transactions (txn_id, user_id, amount, status, created_at, expires_at, merchant_order_id, callback_url)
                 VALUES (?, ?, ?, 'pending', ?, ?, ?, ?)''', 
              (txn_id, admin_user_id, amount, now.isoformat(), expires.isoformat(), merchant_order_id, callback_url))
    conn.commit()
    conn.close()
    
    return redirect(f"/pay/{txn_id}")

@app.route('/api/subscription_webhook', methods=['POST'])
def subscription_webhook():
    signature = request.headers.get('X-NovaPay-Signature')
    timestamp = request.headers.get('X-NovaPay-Timestamp')
    
    if not signature or not timestamp:
        return jsonify({'status': 'error', 'message': 'Missing signature'}), 401
        
    data = request.json
    if not data or data.get('status') != 'success':
        return jsonify({'status': 'ignored'}), 200
        
    merchant_order_id = data.get('merchant_order_id', '')
    if not merchant_order_id.startswith('sub_upgrade|'):
        return jsonify({'status': 'ignored'}), 200
        
    parts = merchant_order_id.split('|')
    if len(parts) != 3:
        return jsonify({'status': 'error', 'message': 'Invalid order ID'}), 400
        
    target_user_id = parts[1]
    plan_name = parts[2]
    
    # We must verify the signature using the Admin's API key
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    c.execute("SELECT user_id, api_key FROM users WHERE role='admin' ORDER BY user_id ASC LIMIT 1")
    admin_row = c.fetchone()
    if not admin_row:
        c.execute("SELECT user_id, api_key FROM users WHERE user_id=1")
        admin_row = c.fetchone()
        
    if not admin_row or not admin_row[1]:
        conn.close()
        return jsonify({'status': 'error', 'message': 'Admin API key missing'}), 500
        
    admin_api_key = admin_row[1]
    
    payload_str = request.get_data(as_text=True)
    sign_material = f"{timestamp}.{payload_str}"
    expected_sig = hmac.new(admin_api_key.encode('utf-8'), sign_material.encode('utf-8'), hashlib.sha256).hexdigest()
    
    if not hmac.compare_digest(signature, expected_sig):
        conn.close()
        return jsonify({'status': 'error', 'message': 'Invalid signature'}), 401
        
    # Upgrade User
    # 30 day expiry
    plan_expiry = (datetime.now() + timedelta(days=30)).isoformat()
    # RESET links_used to 0 to unlock fresh capacity!
    c.execute("UPDATE users SET plan_name=?, plan_expiry=?, links_used=0 WHERE user_id=?", (plan_name, plan_expiry, target_user_id))
    conn.commit()
    conn.close()
    
    return jsonify({'status': 'success'})

def start_background_workers():
    if not getattr(app, '_bg_workers_started', False):
        app._bg_workers_started = True
        t_gmail = threading.Thread(target=monitor_gmails, daemon=True)
        t_gmail.start()

# Start background monitor thread under both WSGI (Render/Gunicorn) and direct python
start_background_workers()

def main():
    init_db()
    start_background_workers()
    print(f"🚀 FamPay Web Gateway Running on Port {PORT}...")
    app.run(host='0.0.0.0', port=PORT, debug=False, use_reloader=False)

if __name__ == "__main__":
    main()













