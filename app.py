from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from functools import wraps
import sqlite3
import hashlib
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'bizcore_secret_key_2025'
DB = 'database.db'

# ============================================
# DATABASE SETUP
# ============================================
def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()

    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        name      TEXT    NOT NULL,
        email     TEXT    UNIQUE NOT NULL,
        password  TEXT    NOT NULL,
        role      TEXT    DEFAULT 'viewer',
        status    TEXT    DEFAULT 'active',
        created   TEXT    DEFAULT CURRENT_TIMESTAMP
    )''')

    # Products table
    c.execute('''CREATE TABLE IF NOT EXISTS products (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        name      TEXT    NOT NULL,
        category  TEXT,
        price     REAL    DEFAULT 0,
        stock     INTEGER DEFAULT 0,
        status    TEXT    DEFAULT 'active',
        created   TEXT    DEFAULT CURRENT_TIMESTAMP
    )''')

    # Customers table
    c.execute('''CREATE TABLE IF NOT EXISTS customers (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        name      TEXT    NOT NULL,
        email     TEXT,
        phone     TEXT,
        city      TEXT,
        created   TEXT    DEFAULT CURRENT_TIMESTAMP
    )''')

    # Sales table
    c.execute('''CREATE TABLE IF NOT EXISTS sales (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        customer   TEXT,
        product    TEXT,
        amount     REAL    DEFAULT 0,
        status     TEXT    DEFAULT 'pending',
        created_by TEXT,
        created    TEXT    DEFAULT CURRENT_TIMESTAMP
    )''')

    # Audit log table
    c.execute('''CREATE TABLE IF NOT EXISTS audit_log (
        id      INTEGER PRIMARY KEY AUTOINCREMENT,
        user    TEXT,
        action  TEXT,
        detail  TEXT,
        created TEXT DEFAULT CURRENT_TIMESTAMP
    )''')

    # Default admin user
    admin_pw = hashlib.sha256('Admin@123'.encode()).hexdigest()
    c.execute("INSERT OR IGNORE INTO users (name,email,password,role) VALUES (?,?,?,?)",
              ('Admin User', 'admin@bizcore.com', admin_pw, 'admin'))

    # Sample data
    c.execute("INSERT OR IGNORE INTO products (name,category,price,stock) VALUES (?,?,?,?)",
              ('Laptop', 'Electronics', 45000, 10))
    c.execute("INSERT OR IGNORE INTO products (name,category,price,stock) VALUES (?,?,?,?)",
              ('Office Chair', 'Furniture', 8500, 25))
    c.execute("INSERT OR IGNORE INTO customers (name,email,phone,city) VALUES (?,?,?,?)",
              ('Rahul Sharma', 'rahul@email.com', '9876543210', 'Delhi'))

    conn.commit()
    conn.close()

# ============================================
# HELPERS
# ============================================
def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def log_action(user, action, detail=''):
    conn = get_db()
    conn.execute("INSERT INTO audit_log (user,action,detail) VALUES (?,?,?)",
                 (user, action, detail))
    conn.commit()
    conn.close()

# ============================================
# ROLE DECORATORS
# ============================================
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first!', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def roles_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))
            if session.get('role') not in roles:
                flash(f'Access Denied! Required role: {", ".join(roles)}', 'error')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated
    return decorator

# Role permissions
ROLE_PERMISSIONS = {
    'admin':    ['dashboard','products','customers','sales','users','reports','audit'],
    'manager':  ['dashboard','products','customers','sales','reports'],
    'sales':    ['dashboard','customers','sales'],
    'viewer':   ['dashboard','reports'],
}

def can_access(module):
    role = session.get('role', 'viewer')
    return module in ROLE_PERMISSIONS.get(role, [])

app.jinja_env.globals['can_access'] = can_access

# ============================================
# AUTH ROUTES
# ============================================
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email    = request.form.get('email','').strip()
        password = request.form.get('password','')

        if not email or not password:
            flash('Please enter email and password!', 'error')
            return render_template('login.html')

        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE email=? AND password=? AND status='active'",
            (email, hash_pw(password))
        ).fetchone()
        conn.close()

        if user:
            session['user_id']   = user['id']
            session['user_name'] = user['name']
            session['email']     = user['email']
            session['role']      = user['role']
            log_action(user['name'], 'LOGIN', f'Logged in from {request.remote_addr}')
            flash(f'Welcome back, {user["name"]}! 🎉', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password!', 'error')

    return render_template('login.html')

@app.route('/signup', methods=['GET','POST'])
def signup():
    if request.method == 'POST':
        name     = request.form.get('name','').strip()
        email    = request.form.get('email','').strip()
        password = request.form.get('password','')
        confirm  = request.form.get('confirm','')
        role     = request.form.get('role', 'viewer')

        # Validation
        if not all([name, email, password, confirm]):
            flash('All fields are required!', 'error')
            return render_template('signup.html')
        if password != confirm:
            flash('Passwords do not match!', 'error')
            return render_template('signup.html')
        if len(password) < 6:
            flash('Password must be at least 6 characters!', 'error')
            return render_template('signup.html')

        try:
            conn = get_db()
            conn.execute(
                "INSERT INTO users (name,email,password,role) VALUES (?,?,?,?)",
                (name, email, hash_pw(password), role)
            )
            conn.commit()
            conn.close()
            log_action(name, 'SIGNUP', f'New account created with role: {role}')
            flash('Account created successfully! Please login. ✅', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Email already exists! Try another.', 'error')

    return render_template('signup.html')

@app.route('/logout')
def logout():
    name = session.get('user_name', 'Unknown')
    log_action(name, 'LOGOUT', 'User logged out')
    session.clear()
    flash('Logged out successfully!', 'info')
    return redirect(url_for('login'))

# ============================================
# DASHBOARD
# ============================================
@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db()
    stats = {
        'products':  conn.execute("SELECT COUNT(*) FROM products").fetchone()[0],
        'customers': conn.execute("SELECT COUNT(*) FROM customers").fetchone()[0],
        'sales':     conn.execute("SELECT COUNT(*) FROM sales").fetchone()[0],
        'users':     conn.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        'revenue':   conn.execute("SELECT COALESCE(SUM(amount),0) FROM sales").fetchone()[0],
        'pending':   conn.execute("SELECT COUNT(*) FROM sales WHERE status='pending'").fetchone()[0],
    }
    recent_sales = conn.execute(
        "SELECT * FROM sales ORDER BY created DESC LIMIT 5"
    ).fetchall()
    conn.close()
    return render_template('dashboard.html', stats=stats, recent_sales=recent_sales)

# ============================================
# PRODUCTS CRUD
# ============================================
@app.route('/products')
@login_required
def products():
    if not can_access('products'):
        flash('Access Denied!', 'error')
        return redirect(url_for('dashboard'))
    conn = get_db()
    items = conn.execute("SELECT * FROM products ORDER BY id DESC").fetchall()
    conn.close()
    return render_template('products.html', items=items)

@app.route('/products/add', methods=['POST'])
@login_required
@roles_required('admin', 'manager')
def add_product():
    name     = request.form.get('name','').strip()
    category = request.form.get('category','').strip()
    price    = float(request.form.get('price', 0))
    stock    = int(request.form.get('stock', 0))
    if not name:
        flash('Product name required!', 'error')
        return redirect(url_for('products'))
    conn = get_db()
    conn.execute("INSERT INTO products (name,category,price,stock) VALUES (?,?,?,?)",
                 (name, category, price, stock))
    conn.commit()
    conn.close()
    log_action(session['user_name'], 'ADD_PRODUCT', f'Added: {name}')
    flash(f'Product "{name}" added! ✅', 'success')
    return redirect(url_for('products'))

@app.route('/products/edit/<int:pid>', methods=['POST'])
@login_required
@roles_required('admin', 'manager')
def edit_product(pid):
    name     = request.form.get('name','').strip()
    category = request.form.get('category','').strip()
    price    = float(request.form.get('price', 0))
    stock    = int(request.form.get('stock', 0))
    conn = get_db()
    conn.execute("UPDATE products SET name=?,category=?,price=?,stock=? WHERE id=?",
                 (name, category, price, stock, pid))
    conn.commit()
    conn.close()
    log_action(session['user_name'], 'EDIT_PRODUCT', f'Edited product ID: {pid}')
    flash('Product updated! ✅', 'success')
    return redirect(url_for('products'))

@app.route('/products/delete/<int:pid>')
@login_required
@roles_required('admin')
def delete_product(pid):
    conn = get_db()
    conn.execute("DELETE FROM products WHERE id=?", (pid,))
    conn.commit()
    conn.close()
    log_action(session['user_name'], 'DELETE_PRODUCT', f'Deleted product ID: {pid}')
    flash('Product deleted!', 'info')
    return redirect(url_for('products'))

@app.route('/products/get/<int:pid>')
@login_required
def get_product(pid):
    conn = get_db()
    p = conn.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
    conn.close()
    if p:
        return jsonify(dict(p))
    return jsonify({'error': 'Not found'}), 404

# ============================================
# CUSTOMERS CRUD
# ============================================
@app.route('/customers')
@login_required
def customers():
    if not can_access('customers'):
        flash('Access Denied!', 'error')
        return redirect(url_for('dashboard'))
    conn = get_db()
    items = conn.execute("SELECT * FROM customers ORDER BY id DESC").fetchall()
    conn.close()
    return render_template('customers.html', items=items)

@app.route('/customers/add', methods=['POST'])
@login_required
@roles_required('admin', 'manager', 'sales')
def add_customer():
    name  = request.form.get('name','').strip()
    email = request.form.get('email','').strip()
    phone = request.form.get('phone','').strip()
    city  = request.form.get('city','').strip()
    if not name:
        flash('Customer name required!', 'error')
        return redirect(url_for('customers'))
    conn = get_db()
    conn.execute("INSERT INTO customers (name,email,phone,city) VALUES (?,?,?,?)",
                 (name, email, phone, city))
    conn.commit()
    conn.close()
    log_action(session['user_name'], 'ADD_CUSTOMER', f'Added: {name}')
    flash(f'Customer "{name}" added! ✅', 'success')
    return redirect(url_for('customers'))

@app.route('/customers/edit/<int:cid>', methods=['POST'])
@login_required
@roles_required('admin', 'manager', 'sales')
def edit_customer(cid):
    name  = request.form.get('name','').strip()
    email = request.form.get('email','').strip()
    phone = request.form.get('phone','').strip()
    city  = request.form.get('city','').strip()
    conn = get_db()
    conn.execute("UPDATE customers SET name=?,email=?,phone=?,city=? WHERE id=?",
                 (name, email, phone, city, cid))
    conn.commit()
    conn.close()
    log_action(session['user_name'], 'EDIT_CUSTOMER', f'Edited customer ID: {cid}')
    flash('Customer updated! ✅', 'success')
    return redirect(url_for('customers'))

@app.route('/customers/delete/<int:cid>')
@login_required
@roles_required('admin', 'manager')
def delete_customer(cid):
    conn = get_db()
    conn.execute("DELETE FROM customers WHERE id=?", (cid,))
    conn.commit()
    conn.close()
    log_action(session['user_name'], 'DELETE_CUSTOMER', f'Deleted customer ID: {cid}')
    flash('Customer deleted!', 'info')
    return redirect(url_for('customers'))

@app.route('/customers/get/<int:cid>')
@login_required
def get_customer(cid):
    conn = get_db()
    c = conn.execute("SELECT * FROM customers WHERE id=?", (cid,)).fetchone()
    conn.close()
    if c:
        return jsonify(dict(c))
    return jsonify({'error': 'Not found'}), 404

# ============================================
# SALES CRUD
# ============================================
@app.route('/sales')
@login_required
def sales():
    if not can_access('sales'):
        flash('Access Denied!', 'error')
        return redirect(url_for('dashboard'))
    conn = get_db()
    items = conn.execute("SELECT * FROM sales ORDER BY id DESC").fetchall()
    customers_list = conn.execute("SELECT name FROM customers").fetchall()
    products_list  = conn.execute("SELECT name FROM products").fetchall()
    conn.close()
    return render_template('sales.html', items=items,
                           customers_list=customers_list,
                           products_list=products_list)

@app.route('/sales/add', methods=['POST'])
@login_required
@roles_required('admin', 'manager', 'sales')
def add_sale():
    customer = request.form.get('customer','').strip()
    product  = request.form.get('product','').strip()
    amount   = float(request.form.get('amount', 0))
    status   = request.form.get('status', 'pending')
    conn = get_db()
    conn.execute("INSERT INTO sales (customer,product,amount,status,created_by) VALUES (?,?,?,?,?)",
                 (customer, product, amount, status, session['user_name']))
    conn.commit()
    conn.close()
    log_action(session['user_name'], 'ADD_SALE', f'Sale: {customer} - ₹{amount}')
    flash('Sale added! ✅', 'success')
    return redirect(url_for('sales'))

@app.route('/sales/edit/<int:sid>', methods=['POST'])
@login_required
@roles_required('admin', 'manager')
def edit_sale(sid):
    customer = request.form.get('customer','').strip()
    product  = request.form.get('product','').strip()
    amount   = float(request.form.get('amount', 0))
    status   = request.form.get('status', 'pending')
    conn = get_db()
    conn.execute("UPDATE sales SET customer=?,product=?,amount=?,status=? WHERE id=?",
                 (customer, product, amount, status, sid))
    conn.commit()
    conn.close()
    log_action(session['user_name'], 'EDIT_SALE', f'Edited sale ID: {sid}')
    flash('Sale updated! ✅', 'success')
    return redirect(url_for('sales'))

@app.route('/sales/delete/<int:sid>')
@login_required
@roles_required('admin')
def delete_sale(sid):
    conn = get_db()
    conn.execute("DELETE FROM sales WHERE id=?", (sid,))
    conn.commit()
    conn.close()
    log_action(session['user_name'], 'DELETE_SALE', f'Deleted sale ID: {sid}')
    flash('Sale deleted!', 'info')
    return redirect(url_for('sales'))

@app.route('/sales/get/<int:sid>')
@login_required
def get_sale(sid):
    conn = get_db()
    s = conn.execute("SELECT * FROM sales WHERE id=?", (sid,)).fetchone()
    conn.close()
    if s:
        return jsonify(dict(s))
    return jsonify({'error': 'Not found'}), 404

# ============================================
# USER MANAGEMENT (Admin Only)
# ============================================
@app.route('/users')
@login_required
@roles_required('admin')
def users():
    conn = get_db()
    items = conn.execute("SELECT * FROM users ORDER BY id DESC").fetchall()
    conn.close()
    return render_template('users.html', items=items)

@app.route('/users/add', methods=['POST'])
@login_required
@roles_required('admin')
def add_user():
    name     = request.form.get('name','').strip()
    email    = request.form.get('email','').strip()
    password = request.form.get('password','')
    role     = request.form.get('role','viewer')
    if not all([name, email, password]):
        flash('All fields required!', 'error')
        return redirect(url_for('users'))
    try:
        conn = get_db()
        conn.execute("INSERT INTO users (name,email,password,role) VALUES (?,?,?,?)",
                     (name, email, hash_pw(password), role))
        conn.commit()
        conn.close()
        log_action(session['user_name'], 'ADD_USER', f'Added user: {name} ({role})')
        flash(f'User "{name}" added! ✅', 'success')
    except sqlite3.IntegrityError:
        flash('Email already exists!', 'error')
    return redirect(url_for('users'))

@app.route('/users/edit/<int:uid>', methods=['POST'])
@login_required
@roles_required('admin')
def edit_user(uid):
    name   = request.form.get('name','').strip()
    role   = request.form.get('role','viewer')
    status = request.form.get('status','active')
    conn = get_db()
    conn.execute("UPDATE users SET name=?,role=?,status=? WHERE id=?",
                 (name, role, status, uid))
    conn.commit()
    conn.close()
    log_action(session['user_name'], 'EDIT_USER', f'Edited user ID: {uid}')
    flash('User updated! ✅', 'success')
    return redirect(url_for('users'))

@app.route('/users/delete/<int:uid>')
@login_required
@roles_required('admin')
def delete_user(uid):
    if uid == session['user_id']:
        flash('Cannot delete yourself!', 'error')
        return redirect(url_for('users'))
    conn = get_db()
    conn.execute("DELETE FROM users WHERE id=?", (uid,))
    conn.commit()
    conn.close()
    log_action(session['user_name'], 'DELETE_USER', f'Deleted user ID: {uid}')
    flash('User deleted!', 'info')
    return redirect(url_for('users'))

@app.route('/users/get/<int:uid>')
@login_required
@roles_required('admin')
def get_user(uid):
    conn = get_db()
    u = conn.execute("SELECT id,name,email,role,status FROM users WHERE id=?", (uid,)).fetchone()
    conn.close()
    if u:
        return jsonify(dict(u))
    return jsonify({'error': 'Not found'}), 404

# ============================================
# REPORTS
# ============================================
@app.route('/reports')
@login_required
def reports():
    if not can_access('reports'):
        flash('Access Denied!', 'error')
        return redirect(url_for('dashboard'))
    conn = get_db()
    data = {
        'total_sales':     conn.execute("SELECT COALESCE(SUM(amount),0) FROM sales").fetchone()[0],
        'total_products':  conn.execute("SELECT COUNT(*) FROM products").fetchone()[0],
        'total_customers': conn.execute("SELECT COUNT(*) FROM customers").fetchone()[0],
        'paid_sales':      conn.execute("SELECT COALESCE(SUM(amount),0) FROM sales WHERE status='paid'").fetchone()[0],
        'pending_sales':   conn.execute("SELECT COALESCE(SUM(amount),0) FROM sales WHERE status='pending'").fetchone()[0],
        'top_products':    conn.execute("SELECT product, COUNT(*) as cnt, SUM(amount) as total FROM sales GROUP BY product ORDER BY total DESC LIMIT 5").fetchall(),
        'top_customers':   conn.execute("SELECT customer, COUNT(*) as cnt, SUM(amount) as total FROM sales GROUP BY customer ORDER BY total DESC LIMIT 5").fetchall(),
    }
    conn.close()
    return render_template('reports.html', data=data)

# ============================================
# AUDIT LOG (Admin Only)
# ============================================
@app.route('/audit')
@login_required
@roles_required('admin')
def audit():
    conn = get_db()
    logs = conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 100").fetchall()
    conn.close()
    return render_template('audit.html', logs=logs)

# ============================================
# PROFILE
# ============================================
@app.route('/profile', methods=['GET','POST'])
@login_required
def profile():
    if request.method == 'POST':
        name        = request.form.get('name','').strip()
        new_pass    = request.form.get('new_password','')
        confirm     = request.form.get('confirm_password','')
        conn = get_db()
        if new_pass:
            if new_pass != confirm:
                flash('Passwords do not match!', 'error')
                return redirect(url_for('profile'))
            if len(new_pass) < 6:
                flash('Password must be at least 6 characters!', 'error')
                return redirect(url_for('profile'))
            conn.execute("UPDATE users SET name=?,password=? WHERE id=?",
                         (name, hash_pw(new_pass), session['user_id']))
        else:
            conn.execute("UPDATE users SET name=? WHERE id=?",
                         (name, session['user_id']))
        conn.commit()
        conn.close()
        session['user_name'] = name
        log_action(name, 'UPDATE_PROFILE', 'Profile updated')
        flash('Profile updated! ✅', 'success')
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (session['user_id'],)).fetchone()
    conn.close()
    return render_template('profile.html', user=user)

# ============================================
# RUN
# ============================================
if __name__ == '__main__':
    init_db()
    print("✅ Database initialized!")
    print("🚀 Flask server starting...")
    app.run(host='0.0.0.0', port=5000, debug=False)
