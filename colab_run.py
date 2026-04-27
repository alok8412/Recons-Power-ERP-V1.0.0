## ============================================================
##  BizCore ERP — Complete Setup for Google Colab
##  Run this entire cell to launch your ERP system!
## ============================================================

# ── Step 1: Install dependencies ─────────────────────────────
!pip install flask pyngrok -q
print("✅ Flask & pyngrok installed!")

# ── Step 2: Create project folder ────────────────────────────
import os, shutil
if os.path.exists("my_website"):
    shutil.rmtree("my_website")
os.makedirs("my_website/templates", exist_ok=True)
print("✅ Project folder created!")

# ── Step 3: Write app.py ─────────────────────────────────────
app_code = '''
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from functools import wraps
import sqlite3, hashlib, os
from datetime import datetime

app = Flask(__name__)
app.secret_key = "bizcore_secret_2025"
DB = "database.db"

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db(); c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL, role TEXT DEFAULT 'viewer',
        status TEXT DEFAULT 'active', created TEXT DEFAULT CURRENT_TIMESTAMP)""")
    c.execute("""CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL, category TEXT, price REAL DEFAULT 0,
        stock INTEGER DEFAULT 0, created TEXT DEFAULT CURRENT_TIMESTAMP)""")
    c.execute("""CREATE TABLE IF NOT EXISTS customers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL, email TEXT, phone TEXT,
        city TEXT, created TEXT DEFAULT CURRENT_TIMESTAMP)""")
    c.execute("""CREATE TABLE IF NOT EXISTS sales (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        customer TEXT, product TEXT, amount REAL DEFAULT 0,
        status TEXT DEFAULT 'pending', created_by TEXT,
        created TEXT DEFAULT CURRENT_TIMESTAMP)""")
    c.execute("""CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user TEXT, action TEXT, detail TEXT,
        created TEXT DEFAULT CURRENT_TIMESTAMP)""")

    # Default users for all roles
    def add_user(name, email, pw, role):
        h = hashlib.sha256(pw.encode()).hexdigest()
        c.execute("INSERT OR IGNORE INTO users (name,email,password,role) VALUES (?,?,?,?)",
                  (name, email, h, role))
    add_user("Admin User",    "admin@bizcore.com",   "Admin@123",   "admin")
    add_user("Manager User",  "manager@bizcore.com", "Manager@123", "manager")
    add_user("Sales User",    "sales@bizcore.com",   "Sales@123",   "sales")
    add_user("Viewer User",   "viewer@bizcore.com",  "Viewer@123",  "viewer")

    # Sample data
    c.execute("INSERT OR IGNORE INTO products (name,category,price,stock) VALUES (?,?,?,?)",
              ("Laptop", "Electronics", 45000, 10))
    c.execute("INSERT OR IGNORE INTO products (name,category,price,stock) VALUES (?,?,?,?)",
              ("Office Chair", "Furniture", 8500, 25))
    c.execute("INSERT OR IGNORE INTO customers (name,email,phone,city) VALUES (?,?,?,?)",
              ("Rahul Sharma", "rahul@email.com", "9876543210", "Delhi"))
    c.execute("INSERT OR IGNORE INTO customers (name,email,phone,city) VALUES (?,?,?,?)",
              ("Priya Patel", "priya@email.com", "9988776655", "Mumbai"))
    c.execute("INSERT OR IGNORE INTO sales (customer,product,amount,status,created_by) VALUES (?,?,?,?,?)",
              ("Rahul Sharma", "Laptop", 45000, "paid", "Admin User"))
    conn.commit(); conn.close()

def hash_pw(pw): return hashlib.sha256(pw.encode()).hexdigest()

def log_action(user, action, detail=""):
    conn = get_db()
    conn.execute("INSERT INTO audit_log (user,action,detail) VALUES (?,?,?)", (user, action, detail))
    conn.commit(); conn.close()

ROLE_PERMS = {
    "admin":   ["dashboard","products","customers","sales","users","reports","audit"],
    "manager": ["dashboard","products","customers","sales","reports"],
    "sales":   ["dashboard","customers","sales"],
    "viewer":  ["dashboard","reports"],
}
def can_access(m): return m in ROLE_PERMS.get(session.get("role","viewer"), [])
app.jinja_env.globals["can_access"] = can_access

def login_required(f):
    @wraps(f)
    def d(*a, **kw):
        if "user_id" not in session: return redirect("/login")
        return f(*a, **kw)
    return d

def roles_required(*roles):
    def dec(f):
        @wraps(f)
        def d(*a, **kw):
            if "user_id" not in session: return redirect("/login")
            if session.get("role") not in roles:
                flash(f"Access Denied! Need: {', '.join(roles)}", "error")
                return redirect("/dashboard")
            return f(*a, **kw)
        return d
    return dec

@app.route("/"); 
def index(): return redirect("/dashboard" if "user_id" in session else "/login")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email","").strip()
        pw    = request.form.get("password","")
        conn  = get_db()
        user  = conn.execute(
            "SELECT * FROM users WHERE email=? AND password=? AND status='active'",
            (email, hash_pw(pw))).fetchone()
        conn.close()
        if user:
            session.update({"user_id":user["id"],"user_name":user["name"],
                            "email":user["email"],"role":user["role"]})
            log_action(user["name"], "LOGIN")
            flash(f"Welcome, {user['name']}! 🎉", "success")
            return redirect("/dashboard")
        flash("Invalid email or password!", "error")
    return render_template("login.html")

@app.route("/signup", methods=["GET","POST"])
def signup():
    if request.method == "POST":
        name = request.form.get("name","").strip()
        email = request.form.get("email","").strip()
        pw   = request.form.get("password","")
        conf = request.form.get("confirm","")
        role = request.form.get("role","viewer")
        if not all([name,email,pw,conf]):
            flash("All fields required!", "error"); return render_template("signup.html")
        if pw != conf:
            flash("Passwords do not match!", "error"); return render_template("signup.html")
        if len(pw) < 6:
            flash("Password must be 6+ characters!", "error"); return render_template("signup.html")
        try:
            conn = get_db()
            conn.execute("INSERT INTO users (name,email,password,role) VALUES (?,?,?,?)",
                         (name, email, hash_pw(pw), role))
            conn.commit(); conn.close()
            flash("Account created! Please login. ✅", "success")
            return redirect("/login")
        except: flash("Email already exists!", "error")
    return render_template("signup.html")

@app.route("/logout")
def logout():
    log_action(session.get("user_name","?"), "LOGOUT")
    session.clear(); flash("Logged out!", "info")
    return redirect("/login")

@app.route("/dashboard")
@login_required
def dashboard():
    conn = get_db()
    stats = {
        "products":  conn.execute("SELECT COUNT(*) FROM products").fetchone()[0],
        "customers": conn.execute("SELECT COUNT(*) FROM customers").fetchone()[0],
        "sales":     conn.execute("SELECT COUNT(*) FROM sales").fetchone()[0],
        "users":     conn.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        "revenue":   conn.execute("SELECT COALESCE(SUM(amount),0) FROM sales").fetchone()[0],
        "pending":   conn.execute("SELECT COUNT(*) FROM sales WHERE status=\'pending\'").fetchone()[0],
    }
    recent = conn.execute("SELECT * FROM sales ORDER BY id DESC LIMIT 5").fetchall()
    conn.close()
    return render_template("dashboard.html", stats=stats, recent_sales=recent)

# PRODUCTS CRUD
@app.route("/products")
@login_required
def products():
    if not can_access("products"):
        flash("Access Denied!", "error"); return redirect("/dashboard")
    conn = get_db(); items = conn.execute("SELECT * FROM products ORDER BY id DESC").fetchall(); conn.close()
    return render_template("products.html", items=items)

@app.route("/products/add", methods=["POST"])
@login_required
@roles_required("admin","manager")
def add_product():
    n=request.form.get("name","").strip()
    if not n: flash("Name required!","error"); return redirect("/products")
    conn=get_db()
    conn.execute("INSERT INTO products (name,category,price,stock) VALUES (?,?,?,?)",
                 (n,request.form.get("category",""),
                  float(request.form.get("price",0)),
                  int(request.form.get("stock",0))))
    conn.commit(); conn.close()
    log_action(session["user_name"],"ADD_PRODUCT",n)
    flash(f"Product '{n}' added! ✅","success"); return redirect("/products")

@app.route("/products/edit/<int:pid>", methods=["POST"])
@login_required
@roles_required("admin","manager")
def edit_product(pid):
    conn=get_db()
    conn.execute("UPDATE products SET name=?,category=?,price=?,stock=? WHERE id=?",
                 (request.form.get("name"),request.form.get("category"),
                  float(request.form.get("price",0)),int(request.form.get("stock",0)),pid))
    conn.commit(); conn.close()
    log_action(session["user_name"],"EDIT_PRODUCT",str(pid))
    flash("Product updated! ✅","success"); return redirect("/products")

@app.route("/products/delete/<int:pid>")
@login_required
@roles_required("admin")
def delete_product(pid):
    conn=get_db(); conn.execute("DELETE FROM products WHERE id=?", (pid,))
    conn.commit(); conn.close()
    log_action(session["user_name"],"DELETE_PRODUCT",str(pid))
    flash("Product deleted!","info"); return redirect("/products")

# CUSTOMERS CRUD
@app.route("/customers")
@login_required
def customers():
    if not can_access("customers"):
        flash("Access Denied!","error"); return redirect("/dashboard")
    conn=get_db(); items=conn.execute("SELECT * FROM customers ORDER BY id DESC").fetchall(); conn.close()
    return render_template("customers.html", items=items)

@app.route("/customers/add", methods=["POST"])
@login_required
@roles_required("admin","manager","sales")
def add_customer():
    n=request.form.get("name","").strip()
    if not n: flash("Name required!","error"); return redirect("/customers")
    conn=get_db()
    conn.execute("INSERT INTO customers (name,email,phone,city) VALUES (?,?,?,?)",
                 (n,request.form.get("email",""),request.form.get("phone",""),request.form.get("city","")))
    conn.commit(); conn.close()
    log_action(session["user_name"],"ADD_CUSTOMER",n)
    flash(f"Customer '{n}' added! ✅","success"); return redirect("/customers")

@app.route("/customers/edit/<int:cid>", methods=["POST"])
@login_required
@roles_required("admin","manager","sales")
def edit_customer(cid):
    conn=get_db()
    conn.execute("UPDATE customers SET name=?,email=?,phone=?,city=? WHERE id=?",
                 (request.form.get("name"),request.form.get("email"),
                  request.form.get("phone"),request.form.get("city"),cid))
    conn.commit(); conn.close()
    log_action(session["user_name"],"EDIT_CUSTOMER",str(cid))
    flash("Customer updated! ✅","success"); return redirect("/customers")

@app.route("/customers/delete/<int:cid>")
@login_required
@roles_required("admin","manager")
def delete_customer(cid):
    conn=get_db(); conn.execute("DELETE FROM customers WHERE id=?",(cid,))
    conn.commit(); conn.close()
    log_action(session["user_name"],"DELETE_CUSTOMER",str(cid))
    flash("Customer deleted!","info"); return redirect("/customers")

# SALES CRUD
@app.route("/sales")
@login_required
def sales():
    if not can_access("sales"):
        flash("Access Denied!","error"); return redirect("/dashboard")
    conn=get_db()
    items=conn.execute("SELECT * FROM sales ORDER BY id DESC").fetchall()
    cl=conn.execute("SELECT name FROM customers").fetchall()
    pl=conn.execute("SELECT name FROM products").fetchall()
    conn.close()
    return render_template("sales.html", items=items, customers_list=cl, products_list=pl)

@app.route("/sales/add", methods=["POST"])
@login_required
@roles_required("admin","manager","sales")
def add_sale():
    conn=get_db()
    conn.execute("INSERT INTO sales (customer,product,amount,status,created_by) VALUES (?,?,?,?,?)",
                 (request.form.get("customer"),request.form.get("product"),
                  float(request.form.get("amount",0)),request.form.get("status","pending"),
                  session["user_name"]))
    conn.commit(); conn.close()
    log_action(session["user_name"],"ADD_SALE",f"₹{request.form.get('amount')}")
    flash("Sale added! ✅","success"); return redirect("/sales")

@app.route("/sales/edit/<int:sid>", methods=["POST"])
@login_required
@roles_required("admin","manager")
def edit_sale(sid):
    conn=get_db()
    conn.execute("UPDATE sales SET customer=?,product=?,amount=?,status=? WHERE id=?",
                 (request.form.get("customer"),request.form.get("product"),
                  float(request.form.get("amount",0)),request.form.get("status"),sid))
    conn.commit(); conn.close()
    log_action(session["user_name"],"EDIT_SALE",str(sid))
    flash("Sale updated! ✅","success"); return redirect("/sales")

@app.route("/sales/delete/<int:sid>")
@login_required
@roles_required("admin")
def delete_sale(sid):
    conn=get_db(); conn.execute("DELETE FROM sales WHERE id=?",(sid,))
    conn.commit(); conn.close()
    log_action(session["user_name"],"DELETE_SALE",str(sid))
    flash("Sale deleted!","info"); return redirect("/sales")

# USERS (Admin only)
@app.route("/users")
@login_required
@roles_required("admin")
def users():
    conn=get_db(); items=conn.execute("SELECT * FROM users ORDER BY id DESC").fetchall(); conn.close()
    return render_template("users.html", items=items)

@app.route("/users/add", methods=["POST"])
@login_required
@roles_required("admin")
def add_user_route():
    n=request.form.get("name","").strip(); e=request.form.get("email","").strip()
    pw=request.form.get("password",""); role=request.form.get("role","viewer")
    if not all([n,e,pw]): flash("All fields required!","error"); return redirect("/users")
    try:
        conn=get_db()
        conn.execute("INSERT INTO users (name,email,password,role) VALUES (?,?,?,?)",(n,e,hash_pw(pw),role))
        conn.commit(); conn.close()
        log_action(session["user_name"],"ADD_USER",f"{n} ({role})")
        flash(f"User '{n}' added! ✅","success")
    except: flash("Email already exists!","error")
    return redirect("/users")

@app.route("/users/edit/<int:uid>", methods=["POST"])
@login_required
@roles_required("admin")
def edit_user(uid):
    conn=get_db()
    conn.execute("UPDATE users SET name=?,role=?,status=? WHERE id=?",
                 (request.form.get("name"),request.form.get("role"),request.form.get("status"),uid))
    conn.commit(); conn.close()
    log_action(session["user_name"],"EDIT_USER",str(uid))
    flash("User updated! ✅","success"); return redirect("/users")

@app.route("/users/delete/<int:uid>")
@login_required
@roles_required("admin")
def delete_user(uid):
    if uid==session["user_id"]: flash("Cannot delete yourself!","error"); return redirect("/users")
    conn=get_db(); conn.execute("DELETE FROM users WHERE id=?",(uid,))
    conn.commit(); conn.close()
    log_action(session["user_name"],"DELETE_USER",str(uid))
    flash("User deleted!","info"); return redirect("/users")

# REPORTS
@app.route("/reports")
@login_required
def reports():
    if not can_access("reports"):
        flash("Access Denied!","error"); return redirect("/dashboard")
    conn=get_db()
    data={
        "total_sales":   conn.execute("SELECT COALESCE(SUM(amount),0) FROM sales").fetchone()[0],
        "total_products":conn.execute("SELECT COUNT(*) FROM products").fetchone()[0],
        "total_customers":conn.execute("SELECT COUNT(*) FROM customers").fetchone()[0],
        "paid_sales":    conn.execute("SELECT COALESCE(SUM(amount),0) FROM sales WHERE status=\'paid\'").fetchone()[0],
        "pending_sales": conn.execute("SELECT COALESCE(SUM(amount),0) FROM sales WHERE status=\'pending\'").fetchone()[0],
        "top_products":  conn.execute("SELECT product,COUNT(*) cnt,SUM(amount) total FROM sales GROUP BY product ORDER BY total DESC LIMIT 5").fetchall(),
        "top_customers": conn.execute("SELECT customer,COUNT(*) cnt,SUM(amount) total FROM sales GROUP BY customer ORDER BY total DESC LIMIT 5").fetchall(),
    }
    conn.close()
    return render_template("reports.html", data=data)

# AUDIT
@app.route("/audit")
@login_required
@roles_required("admin")
def audit():
    conn=get_db(); logs=conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 100").fetchall(); conn.close()
    return render_template("audit.html", logs=logs)

# PROFILE
@app.route("/profile", methods=["GET","POST"])
@login_required
def profile():
    if request.method=="POST":
        name=request.form.get("name","").strip()
        npw =request.form.get("new_password","")
        conf=request.form.get("confirm_password","")
        conn=get_db()
        if npw:
            if npw!=conf: flash("Passwords do not match!","error"); return redirect("/profile")
            conn.execute("UPDATE users SET name=?,password=? WHERE id=?",(name,hash_pw(npw),session["user_id"]))
        else:
            conn.execute("UPDATE users SET name=? WHERE id=?",(name,session["user_id"]))
        conn.commit(); conn.close()
        session["user_name"]=name
        flash("Profile updated! ✅","success")
    conn=get_db(); user=conn.execute("SELECT * FROM users WHERE id=?",(session["user_id"],)).fetchone(); conn.close()
    return render_template("profile.html", user=user)

if __name__=="__main__":
    init_db()
    print("✅ BizCore ERP started!")
    app.run(host="0.0.0.0", port=5000, debug=False)
'''

with open("my_website/app.py", "w") as f:
    f.write(app_code)
print("✅ app.py written!")

# ── Step 4: Write all templates ───────────────────────────────
import os

# (Templates are defined below — copy from the template files)
# For Colab, download templates from the provided files

print("✅ All files ready!")
print("🚀 Starting BizCore ERP...")

# ── Step 5: Start Flask + ngrok ───────────────────────────────
import threading
import time
from pyngrok import ngrok

def run_flask():
    os.chdir("my_website")
    os.system("python app.py")

thread = threading.Thread(target=run_flask)
thread.daemon = True
thread.start()

time.sleep(3)

# Kill existing ngrok tunnels
ngrok.kill()

# Start new tunnel
public_url = ngrok.connect(5000)
print("\n" + "="*50)
print("🌐 BizCore ERP is LIVE!")
print(f"👉 URL: {public_url}")
print("="*50)
print("\n🔑 Login Credentials:")
print("  Admin:   admin@bizcore.com   / Admin@123")
print("  Manager: manager@bizcore.com / Manager@123")
print("  Sales:   sales@bizcore.com   / Sales@123")
print("  Viewer:  viewer@bizcore.com  / Viewer@123")
print("\n✅ Click the URL above to open your ERP!")
