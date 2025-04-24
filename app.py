from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
import joblib
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'oidbncsh37jhbhcd'

model = joblib.load('model.pkl')

def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    email = request.form['logemail']
    password = request.form['logpass']

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE email = ?', (email,))
    user = c.fetchone()
    conn.close()

    if user and check_password_hash(user[3], password):
        session['user'] = user[1]
        flash('Logged in successfully.', 'success')
        return redirect(url_for('dashboard'))
    else:
        flash('Invalid credentials.', 'error')
        return redirect(url_for('login'))

@app.route('/signup', methods=['POST'])
def signup():
    name = request.form['logname']
    email = request.form['logemail']
    password = request.form['logpass']
    hashed_password = generate_password_hash(password)

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    try:
        c.execute('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', (name, email, hashed_password))
        conn.commit()
        flash('Account created successfully. Please log in.', 'success')
        return redirect(url_for('login'))
    except sqlite3.IntegrityError:
        flash('Email already exists.', 'error')
        return redirect(url_for('login'))
    finally:
        conn.close()

@app.route('/dashboard')
def dashboard():
    if 'user' in session:
        return render_template('dashboard.html', username=session['user'])
    else:
        return redirect(url_for('login'))


@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/predict', methods=['GET', 'POST'])
def predict():
    if 'user' not in session:
        return redirect(url_for('login'))

    variables = ['Male', 'Age', 'Debt', 'YearsEmployed', 'PriorDefault', 'Employed', 'Income']

    if request.method == 'POST':
        try:
            inputs = [float(request.form[var]) for var in variables]
            prediction = model.predict([inputs])[0]
            return render_template('result.html', prediction=prediction)
        except:
            return 'Invalid input. Please enter numeric values only.'

    return render_template('form.html', variables=variables)

if __name__ == '__main__':
    app.run(debug=True)
