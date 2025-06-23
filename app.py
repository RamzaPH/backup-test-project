
from flask import Flask, render_template, request, redirect, url_for, session, g
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

DATABASE = 'database.db'

# --- DB Setup ---
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    db.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT CHECK(role IN ('admin', 'user')) NOT NULL DEFAULT 'user'
        )
    ''')
    db.commit()

    # Auto-create admin account if it doesn't exist
    admin = db.execute("SELECT * FROM users WHERE role = 'admin'").fetchone()
    if not admin:
        hashed = generate_password_hash("admin123")
        db.execute("INSERT INTO users (username, password, role) VALUES (?, ?, 'admin')", ("admin", hashed))
        db.commit()

# --- Routes ---
@app.before_request
def before_request():
    init_db()

@app.route('/')
def landing():
    return render_template('sampol.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if user and check_password_hash(user['password'], password):
            session['username'] = user['username']
            session['role'] = user['role']
            return redirect('/admin/dashboard' if user['role'] == 'admin' else '/user/dashboard')
        return "Invalid username or password"
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        if username.lower() == 'admin':
            return "Cannot use 'admin' as a username."
        hashed = generate_password_hash(password)
        db = get_db()
        try:
            db.execute("INSERT INTO users (username, password, role) VALUES (?, ?, 'user')", (username, hashed))
            db.commit()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return "Username already exists"
    return render_template('signup.html')

@app.route('/admin/<page>')
def admin_pages(page):
    if session.get('role') != 'admin':
        return "Access Denied"
    return render_template(f'admin-page/admin-{page}.html')

@app.route('/admin/patient')
def admin_patient():
    return render_template('admin-page/admin-patient.html', current_page='patient')

@app.route('/admin/appointment')
def admin_appointment():
    return render_template('admin-page/admin-appointment.html', current_page='appointment')

@app.route('/admin/profile')
def admin_profile():
    return render_template('admin-page/admin-profile.html', current_page='profile')

@app.route('/admin/reports')
def admin_reports():
    return render_template('admin-page/admin-reports.html', current_page='reports')

@app.route('/admin/settings')
def admin_settings():
    return render_template('admin-page/admin-settings.html', current_page='settings')

@app.route('/admin/dashboard')
def admin_dashboard():
    if session.get('role') != 'admin':
        return "Access Denied"
    return render_template('admin-page/admin-dashboard.html', current_page='dashboard')

@app.route('/user/<page>')
def user_pages(page):
    if session.get('role') != 'user':
        return "Access Denied"
    return render_template(f'user-page/user-{page}.html')

@app.route('/user/dashboard')
def user_dashboard():
    return render_template('user-page/user-dashboard.html', current_page='dashboard')

@app.route('/user/appointment')
def user_appointment():
    return render_template('user-page/user-appointment.html', current_page='appointment')

@app.route('/user/prescription')
def user_prescription():
    return render_template('user-page/user-prescription.html', current_page='prescription')

@app.route('/user/orders')
def user_orders():
    return render_template('user-page/user-orders.html', current_page='orders')

@app.route('/user/profile')
def user_profile():
    return render_template('user-page/user-profile.html', current_page='profile')

@app.route('/user/settings')
def user_settings():
    return render_template('user-page/user-settings.html', current_page='settings') 

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
