from flask import Flask, render_template, request,jsonify, redirect, url_for, session, flash
import pymysql
import bcrypt
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Configure upload folder
UPLOAD_FOLDER = 'static/uploads/profile_pics'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure the upload directory exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# MySQL Database Connection
DB_HOST = 'localhost'
DB_USER = 'root'
DB_PASSWORD = ''  # Update based on your MySQL setup
DB_NAME = 'gender_equality_db'

def connect_db():
    return pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME, cursorclass=pymysql.cursors.DictCursor)

# Function to check allowed file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Routes
@app.route('/')
def home():
    return render_template('index.html', title="Home")

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')

        if not name or not email or not password:
            flash("All fields are required!", "danger")
            return redirect(url_for("signup"))

        conn = connect_db()
        cursor = conn.cursor()

        # Check if email already exists
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        existing_user = cursor.fetchone()

        if existing_user:
            flash("Email is already registered. Please log in.", "warning")
            conn.close()
            return redirect(url_for("login"))

        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Insert into the database
        cursor.execute("INSERT INTO users (name, email, password, role) VALUES (%s, %s, %s, 'user')",
                       (name, email, hashed_password))

        conn.commit()
        conn.close()

        flash("Account created successfully! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password'].encode('utf-8')

        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()
        conn.close()

        if user and bcrypt.checkpw(password, user['password'].encode('utf-8')):
            session['user_id'] = user['id']
            session['role'] = user['role']
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials, try again.', 'danger')

    return render_template('login.html', title="Login")


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please log in first.', 'warning')
        return redirect(url_for('login'))
    
    if session.get('role') == 'admin':
        return render_template('admin_dashboard.html', title="Admin Dashboard")
    
    return render_template('dashboard.html', title="User Dashboard")

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        flash('Please log in first.', 'warning')
        return redirect(url_for('login'))

    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id=%s", (session['user_id'],))
    user = cursor.fetchone()
    conn.close()

    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('login'))

    return render_template('profile.html', title="Profile", user=user)

@app.route('/update_profile', methods=['POST'])
def update_profile():
    if 'user_id' not in session:
        flash('Please log in first.', 'warning')
        return redirect(url_for('login'))

    name = request.form['name']
    # email is readonly in the form, so we don't update it
    phone = request.form['phone']
    bio = request.form['bio']
    profile_image = request.files.get('profile_image')  # Updated field name to match the HTML

    conn = connect_db()
    cursor = conn.cursor()
    
    # Start with basic profile information update
    query_params = [name, phone, bio, session['user_id']]
    update_query = "UPDATE users SET name=%s, phone=%s, bio=%s"
    
    # Handle profile picture if uploaded
    if profile_image and profile_image.filename and allowed_file(profile_image.filename):
        filename = secure_filename(f"user_{session['user_id']}_{profile_image.filename}")
        # Save file to filesystem
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        profile_image.save(file_path)
        
        # Store the relative path in database
        db_path = f"uploads/profile_pics/{filename}"
        update_query += ", profile_image=%s"  # Updated column name to match HTML
        query_params.insert(-1, db_path)  # Insert before the user_id

    # Finalize the query
    update_query += " WHERE id=%s"
    
    # Execute update query
    cursor.execute(update_query, tuple(query_params))
    conn.commit()
    conn.close()

    flash('Profile updated successfully!', 'success')
    return redirect(url_for('profile'))

@app.route('/mentorship')
def mentorship():
    return render_template('mentorship.html', title="Mentorship")

@app.route('/about')
def about():
    return render_template('about.html', title="About Us")

@app.route('/reports', methods=['GET', 'POST'])
def reports():  # Adjusted the function name to 'reports' for consistency
    if request.method == 'POST':
        if 'user_id' not in session:
            flash('You must be logged in to submit a report.', 'warning')
            return redirect(url_for('login'))

        report_text = request.form['report']
        user_id = session['user_id']

        conn = connect_db()
        cursor = conn.cursor()

        try:
            cursor.execute("INSERT INTO reports (user_id, report_text) VALUES (%s, %s)", (user_id, report_text))
            conn.commit()
            flash('Report submitted successfully!', 'success')
        except pymysql.MySQLError as e:
            print("Database Error:", e)
            flash('Error submitting report. Please try again.', 'danger')
        finally:
            conn.close()

    return render_template('reports.html', title="Reports")


@app.route('/health')
def health():
    return render_template('health.html', title="Health")

@app.route('/tracker')
def tracker():
    return render_template('tracker.html', title="Tracker")

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        message = request.form['message']

        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO contact_messages (name, email, message) VALUES (%s, %s, %s)", (name, email, message))
        conn.commit()
        conn.close()

        flash('Message sent successfully!', 'success')

    return render_template('contact.html', title="Contact")

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/get-involved')
def get_involved():
    return render_template('get_involved.html', title="Get Involved")

@app.route('/programs')
def programs():
    return render_template('programs.html', title="Our Programs")

@app.route('/jobs')
def jobs():
    return render_template('jobs.html', title="Job Opportunities")

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if request.method == 'POST':
        if 'user_id' not in session:
            flash('Please log in first.', 'warning')
            return redirect(url_for('login'))
            
        current_password = request.form['current_password'].encode('utf-8')
        new_password = request.form['new_password'].encode('utf-8')
        confirm_password = request.form['confirm_password'].encode('utf-8')
        
        if new_password != confirm_password:
            flash('New passwords do not match.', 'danger')
            return redirect(url_for('change_password'))
            
        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE id=%s", (session['user_id'],))
        user = cursor.fetchone()
        
        if not user or not bcrypt.checkpw(current_password, user['password'].encode('utf-8')):
            flash('Current password is incorrect.', 'danger')
            conn.close()
            return redirect(url_for('change_password'))
            
        hashed_new_password = bcrypt.hashpw(new_password, bcrypt.gensalt())
        cursor.execute("UPDATE users SET password=%s WHERE id=%s", (hashed_new_password, session['user_id']))
        conn.commit()
        conn.close()
        
        flash('Password changed successfully!', 'success')
        return redirect(url_for('profile'))
        
    return render_template('change_password.html', title="Change Password")

@app.route('/login/google')
def google_login():
    return "Google Login Route"

@app.route('/login/facebook')
def facebook_login():
    return "Facebook Login Route"

@app.route("/admin/manage-users")
def manage_users():
    connection = connect_db()
    with connection.cursor() as cursor:
        cursor.execute("SELECT id, name, email, role, status FROM users")  # Ensure 'status' column exists
        users = cursor.fetchall()
    connection.close()
    return render_template("manage_users.html", users=users)

@app.route("/admin/promote/<int:user_id>")
def promote_user(user_id):
    connection = connect_db()
    with connection.cursor() as cursor:
        cursor.execute("UPDATE users SET role = 'admin' WHERE id = %s", (user_id,))
        connection.commit()
    connection.close()
    return redirect(url_for("manage_users"))

@app.route("/admin/demote/<int:user_id>")
def demote_user(user_id):
    connection = connect_db()
    with connection.cursor() as cursor:
        cursor.execute("UPDATE users SET role = 'user' WHERE id = %s", (user_id,))
        connection.commit()
    connection.close()
    return redirect(url_for("manage_users"))

@app.route("/admin/suspend/<int:user_id>")
def suspend_user(user_id):
    connection = connect_db()
    with connection.cursor() as cursor:
        cursor.execute("UPDATE users SET status = 'suspended' WHERE id = %s", (user_id,))
        connection.commit()
    connection.close()
    return redirect(url_for("manage_users"))

@app.route("/admin/activate/<int:user_id>")
def activate_user(user_id):
    connection = connect_db()
    with connection.cursor() as cursor:
        cursor.execute("UPDATE users SET status = 'active' WHERE id = %s", (user_id,))
        connection.commit()
    connection.close()
    return redirect(url_for("manage_users"))


if __name__ == '__main__':
    app.run(debug=True)