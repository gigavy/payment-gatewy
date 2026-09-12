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

# ============================================
# SERVER CONFIGURATION
# ============================================
DB_FILE = "fampay_gateway.db"
PORT = int(os.environ.get("PORT", 5000))

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "fampay-super-secret-key")

# ============================================
# DATABASE INITIALIZATION
# ============================================

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # Run column migrations gracefully
    def add_col(table, col, def_type="TEXT"):
        try:
            c.execute(f"ALTER TABLE {table} ADD COLUMN {col} {def_type}")
        except:
            pass
            
    try:
        add_col('transactions', 'callback_url')
        add_col('transactions', 'expires_at')
        add_col('transactions', 'customer_email')
        add_col('transactions', 'merchant_order_id')
        add_col('transactions', 'customer_name')
        
        add_col('users', 'theme')
        add_col('users', 'profile_pic')
        add_col('users', 'merchant_id')
        add_col('users', 'provider')
        add_col('users', 'role')
        add_col('users', 'plan_name')
        add_col('users', 'plan_expiry')
    except:
        pass

    
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
            provider TEXT DEFAULT 'fampay'
        )
    ''')
    try: c.execute("ALTER TABLE users ADD COLUMN display_name TEXT DEFAULT 'Merchant'")
    except: pass
    try: c.execute("ALTER TABLE users ADD COLUMN theme TEXT DEFAULT 'default'")
    except: pass
    try: c.execute("ALTER TABLE users ADD COLUMN provider TEXT DEFAULT 'fampay'")
    except: pass
    try: c.execute("ALTER TABLE users ADD COLUMN username TEXT UNIQUE")
    except: pass
    try: c.execute("ALTER TABLE users ADD COLUMN password_hash TEXT")
    except: pass
    
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
            callback_url TEXT
        )
    ''')
    try: c.execute("ALTER TABLE transactions ADD COLUMN merchant_order_id TEXT")
    except: pass
    try: c.execute("ALTER TABLE transactions ADD COLUMN customer_name TEXT")
    except: pass
    try: c.execute("ALTER TABLE transactions ADD COLUMN callback_url TEXT")
    except: pass
    try: c.execute("ALTER TABLE transactions ADD COLUMN customer_email TEXT")
    except: pass
    try: c.execute("ALTER TABLE users ADD COLUMN profile_pic TEXT")
    except: pass
    try: c.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'merchant'")
    except: pass
    try: c.execute("ALTER TABLE users ADD COLUMN plan_name TEXT DEFAULT 'Free'")
    except: pass
    try: c.execute("ALTER TABLE users ADD COLUMN plan_expiry TEXT")
    except: pass

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
    conn.commit()
    conn.close()

def get_user(user_id):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT upi_id, gmail, app_pass, api_key, display_name, theme, username, provider, profile_pic, role, plan_name, plan_expiry FROM users WHERE user_id = ?", (user_id,))
    row = c.fetchone()
    conn.close()
    if row:
        return {
            "upi_id": row[0],
            "gmail": row[1],
            "app_pass": row[2],
            "api_key": row[3],
            "display_name": row[4] or "Merchant",
            "theme": row[5] or "default",
            "username": row[6],
            "provider": row[7] or "fampay",
            "profile_pic": row[8] if len(row) > 8 and row[8] else None,
            "role": row[9] if len(row) > 9 and row[9] else "merchant",
            "plan_name": row[10] if len(row) > 10 and row[10] else "Free",
            "plan_expiry": row[11] if len(row) > 11 and row[11] else None
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
            c.execute("SELECT plan_expiry FROM users WHERE user_id=?", (session['user_id'],))
            row = c.fetchone()
            if row and row[0]:
                expiry_date = datetime.fromisoformat(row[0])
                if datetime.now() > expiry_date:
                    c.execute("UPDATE users SET plan_name='Free', plan_expiry=NULL WHERE user_id=?", (session['user_id'],))
                    conn.commit()
            conn.close()
        except:
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
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT user_id, password_hash FROM users WHERE username=?", (username,))
        row = c.fetchone()
        conn.close()
        
        if row and check_password_hash(row[1], password):
            session['user_id'] = row[0]
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            return render_template('register.html', error='Username and password required')
            
        password_hash = generate_password_hash(password)
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)", (username, password_hash, datetime.now().isoformat()))
            user_id = c.lastrowid
            conn.commit()
            session['user_id'] = user_id
            return redirect(url_for('dashboard'))
        except sqlite3.IntegrityError:
            return render_template('register.html', error='Username already exists')
        finally:
            conn.close()
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
    c.execute("UPDATE users SET plan_name=?, plan_expiry=? WHERE user_id=?", (new_plan, expiry_date, target_user))
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
    session.pop('user_id', None)
    return redirect(url_for('login'))

# ============================================
# FLASK WEB INTERFACE (DASHBOARD)
# ============================================

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    yt_link = get_sys_setting('youtube_link', '')
    wa_number = get_sys_setting('support_whatsapp', '')
    return render_template('index.html', yt_link=yt_link, wa_number=wa_number)


@app.route('/mark_paid/<txn_id>', methods=['POST'])
@login_required
def mark_paid(txn_id):
    user_id = session['user_id']
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    c.execute("SELECT amount FROM transactions WHERE txn_id=? AND user_id=? AND status='pending'", (txn_id, user_id))
    txn = c.fetchone()
    
    if txn:
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute("UPDATE transactions SET status='completed', utr='MANUAL_VERIFY', paid_at=? WHERE txn_id=?", (now_str, txn_id))
        conn.commit()
        conn.close()
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
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT upi_id, display_name, theme, profile_pic FROM users WHERE user_id=?", (user_id,))
    row = c.fetchone()
    conn.close()
    
    upi_id = row[0] if row and row[0] else "merchant@upi"
    display_name = row[1] if row and row[1] else "Merchant"
    theme = request.args.get('theme') or (row[2] if row and row[2] else "default")
    profile_pic = row[3] if row and len(row)>3 and row[3] else None
    
    return render_template('checkout.html',
                           txn_id="FAM12345678",
                           amount=499.00,
                           upi_id=upi_id,
                           display_name=display_name,
                           theme=theme,
                           api_key="preview",
                           callback_url="",
                           qr_url="https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=upi://pay?pa=merchant@upi&pn=Merchant&am=499",
                           payment_url="#",
                           profile_pic=profile_pic)

@app.route('/settings')
@login_required
def settings():
    user_id = session['user_id']
    user_info = get_user(user_id)
    return render_template('settings.html', user_info=user_info)

@app.route('/api_docs')
@login_required
def api_docs():
    user_id = session['user_id']
    user_info = get_user(user_id)
    return render_template('api_docs.html', user_info=user_info)

@app.route('/save_customize', methods=['POST'])
@login_required
def save_customize():
    user_id = session['user_id']
    display_name = request.form.get('display_name', 'Merchant')
    theme = request.form.get('theme', 'default')
    
    file = request.files.get('profile_pic')
    profile_pic_b64 = None
    if file and file.filename != '':
        import base64
        profile_pic_b64 = "data:" + file.content_type + ";base64," + base64.b64encode(file.read()).decode('utf-8')
        
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    if profile_pic_b64:
        c.execute("UPDATE users SET display_name=?, theme=?, profile_pic=? WHERE user_id=?", (display_name, theme, profile_pic_b64, user_id))
    else:
        c.execute("UPDATE users SET display_name=?, theme=? WHERE user_id=?", (display_name, theme, user_id))
    conn.commit()
    conn.close()
    return redirect(url_for('settings', success='Customization Saved!'))

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
    
    return render_template('payment_links.html', user_info=user_info, links=links)
    
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
    c.execute('''INSERT INTO transactions (txn_id, user_id, amount, status, created_at, expires_at, customer_email)
                 VALUES (?, ?, ?, 'pending', ?, ?, ?)''', 
              (txn_id, user_id, amount, now.isoformat(), expires.isoformat(), customer_email))
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
    api_key = request.headers.get('X-Fam-Key') or request.json.get('api_key')
    if not api_key:
        return jsonify({"status": "error", "message": "Missing X-Fam-Key header"}), 401
        
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT user_id FROM users WHERE api_key = ?", (api_key,))
    user = c.fetchone()
    if not user:
        conn.close()
        return jsonify({"status": "error", "message": "Invalid API Key"}), 401
    
    user_id = user[0]
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
    expires = now + timedelta(minutes=5)

    c.execute('''INSERT INTO transactions (txn_id, user_id, amount, status, created_at, expires_at, merchant_order_id, customer_name, callback_url)
                 VALUES (?, ?, ?, 'pending', ?, ?, ?, ?, ?)''', 
              (txn_id, user_id, amount, now.isoformat(), expires.isoformat(), merchant_order_id, customer_name, callback_url))
    conn.commit()
    conn.close()
    
    payment_url = f"{request.host_url.rstrip('/')}/pay/{txn_id}"
    
    return jsonify({
        "status": "success",
        "payment_url": payment_url,
        "txn_id": txn_id
    })

@app.route('/pay/<txn_id>', methods=['GET'])
def checkout_page_by_id(txn_id):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT user_id, amount, status, callback_url FROM transactions WHERE txn_id = ?", (txn_id,))
    txn = c.fetchone()
    
    if not txn:
        conn.close()
        return "<h1>Error: Transaction not found</h1>", 404
        
    user_id, amount, status, callback_url = txn
    
    c.execute("SELECT upi_id, display_name, theme, api_key, provider FROM users WHERE user_id = ?", (user_id,))
    user = c.fetchone()
    conn.close()
    
    if not user or not user[0]:
        return "<h1>Error: Merchant account not configured properly</h1>", 400
        
    upi_id, display_name, theme, api_key, provider = user
    
    payment_url = f"upi://pay?pa={upi_id}&pn=Merchant&tr={txn_id}&am={amount}&cu=INR"
    
    qr = qrcode.make(payment_url)
    qr_path = f"static/qr_{txn_id}.png"
    os.makedirs("static", exist_ok=True)
    qr.save(qr_path)
    
    return render_template('checkout.html', 
                           amount=f"{amount:.2f}",
                           txn_id=txn_id,
                           api_key=api_key,
                           payment_url=payment_url,
                           qr_url=f"/qr/{txn_id}",
                           upi_id=upi_id,
                           display_name=display_name or 'Merchant',
                           theme=theme or 'premium',
                           status=status,
                           callback_url=callback_url,
                           provider=provider or 'fampay')

@app.route('/pay', methods=['GET'])
def checkout_page_legacy():
    api_key = request.args.get('api_key')
    amount_raw = request.args.get('amount')

    if not api_key or not amount_raw:
        return "<h1>Error: Missing api_key or amount</h1>", 400

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT user_id, upi_id, display_name, theme, provider FROM users WHERE api_key = ?", (api_key,))
    user = c.fetchone()
    
    if not user or not user[1]:
        return "<h1>Error: Invalid API Key or Not Configured</h1>", 401
    
    user_id, upi_id, display_name, theme, provider = user

    try:
        amount = float(amount_raw)
        if amount <= 0: raise ValueError
        # Dynamic Amount Logic
        if amount == int(amount):
            amount += round(random.uniform(0.01, 0.99), 2)
        amount = round(amount, 2)
    except ValueError:
        return "<h1>Error: Invalid amount</h1>", 400

    expiry_mins = request.args.get('expiry', '1440')
    try:
        expiry_mins = int(expiry_mins)
    except ValueError:
        expiry_mins = 1440

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
        c.execute("SELECT user_id FROM users WHERE api_key = ?", (api_key,))
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
        
def send_webhook(user_id, callback_url, txn_id, merchant_order_id, amount, utr):
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT api_key FROM users WHERE user_id=?", (user_id,))
        row = c.fetchone()
        api_key = row[0] if row and row[0] else "default_secret"
        
        payload = {
            "status": "success",
            "txn_id": txn_id,
            "merchant_order_id": merchant_order_id,
            "amount": amount,
            "utr": utr
        }
        payload_str = json.dumps(payload)
        
        # Pro Logic: HMAC-SHA256 Signature for Webhook Security
        signature = hmac.new(api_key.encode('utf-8'), payload_str.encode('utf-8'), hashlib.sha256).hexdigest()
        headers = {
            "Content-Type": "application/json",
            "X-FamGateway-Signature": signature
        }
        
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
                                c_db.execute("SELECT txn_id, status, callback_url, merchant_order_id FROM transactions WHERE utr=?", (utr,))
                                row = c_db.fetchone()
                                txn_completed_now = False
                                
                                if row:
                                    if row[1] == 'pending':
                                        c_db.execute("UPDATE transactions SET status='completed', paid_at=? WHERE txn_id=?", (now_str, row[0]))
                                        conn_db.commit()
                                        txn_completed_now = True
                                        completed_txn = row
                                else:
                                    # Amount-based fallback (if UTR not submitted by user yet)
                                    c_db.execute("SELECT txn_id, callback_url, merchant_order_id FROM transactions WHERE user_id=? AND status='pending' AND ABS(amount - ?) < 0.01 AND (utr IS NULL OR utr='') ORDER BY created_at ASC LIMIT 1", (user_id, amount))
                                    pending_txn = c_db.fetchone()
                                    if pending_txn:
                                        c_db.execute("UPDATE transactions SET status='completed', utr=?, paid_at=? WHERE txn_id=?", (utr, now_str, pending_txn[0]))
                                        conn_db.commit()
                                        txn_completed_now = True
                                        completed_txn = (pending_txn[0], 'pending', pending_txn[1], pending_txn[2])
                                        
                                conn_db.close()
                                
                                # Fire webhook and Email if completed now
                                if txn_completed_now:
                                    add_sys_log(user_id, f"Match Success! Verified Txn ID: {completed_txn[0]}")
                                    
                                    # Fetch email just in case
                                    conn_fetch = sqlite3.connect(DB_FILE)
                                    c_fetch = conn_fetch.cursor()
                                    c_fetch.execute("SELECT customer_email FROM transactions WHERE txn_id=?", (completed_txn[0],))
                                    email_row = c_fetch.fetchone()
                                    conn_fetch.close()
                                    
                                    if email_row and email_row[0]:
                                        threading.Thread(target=send_email_receipt, args=(user_id, email_row[0], completed_txn[0], amount, utr, now_str)).start()
                                    
                                    if completed_txn[2]:
                                        threading.Thread(target=send_webhook, args=(user_id, completed_txn[2], completed_txn[0], completed_txn[3], amount, utr)).start()
                                    
                except Exception as e:
                    # If any error (e.g. connection drop), remove from persistent dict to force reconnect next loop
                    if user_id in imap_connections:
                        del imap_connections[user_id]
        except Exception as e:
            pass
        time.sleep(1.5)

@app.route('/regenerate_key', methods=['POST'])
def regenerate_key():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    import secrets
    new_api_key = 'FAM' + secrets.token_hex(16).upper()
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('UPDATE users SET api_key = ? WHERE user_id = ?', (new_api_key, session['user_id']))
    conn.commit()
    conn.close()
    
    flash('API Key successfully regenerated! Update your webhook integrations.')
    return redirect(url_for('dashboard'))


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

def main():
    init_db()
    # Start background gmail reader
    t_gmail = threading.Thread(target=monitor_gmails, daemon=True)
    t_gmail.start()
    
    print(f"ðŸš€ FamPay Web Gateway Running on Port {PORT}...")
    app.run(host='0.0.0.0', port=PORT, debug=False, use_reloader=False)

if __name__ == "__main__":
    main()













