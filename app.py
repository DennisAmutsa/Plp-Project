from flask import Flask, render_template, request, redirect, url_for, session, flash
import pymysql
import bcrypt

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# MySQL Database Connection
DB_HOST = 'localhost'
DB_USER = 'root'
DB_PASSWORD = ''  # Update based on your MySQL setup
DB_NAME = 'gender_equality_db'

def connect_db():
    return pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME, cursorclass=pymysql.cursors.DictCursor)

# Routes

@app.route('/')
def home():
    return render_template('index.html', title="Home")

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        conn = connect_db()
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO users (name, email, password) VALUES (%s, %s, %s)", (name, email, hashed_password))
            conn.commit()
            flash('Signup successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except pymysql.MySQLError:
            flash('Error signing up. Try again.', 'danger')
        finally:
            conn.close()
    
    return render_template('signup.html', title="Sign Up")

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
    
    return render_template('dashboard.html', title="Dashboard")

@app.route('/mentorship')
def mentorship():
    return render_template('mentorship.html', title="Mentorship")

@app.route('/about')
def about():
    return render_template('about.html', title="About Us")

@app.route('/reports', methods=['GET', 'POST'])
def reports():
    if request.method == 'POST':
        if 'user_id' not in session:
            flash('You must be logged in to submit a report.', 'warning')
            return redirect(url_for('login'))
        
        report_text = request.form['report']
        user_id = session['user_id']

        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO reports (user_id, report_text) VALUES (%s, %s)", (user_id, report_text))
        conn.commit()
        conn.close()
        flash('Report submitted successfully!', 'success')

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

if __name__ == '__main__':
    app.run(debug=True)
