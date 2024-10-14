from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import re


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'  # Change this to a random secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(100))  
    date_of_birth = db.Column(db.String(100))  

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password')
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        name = request.form.get('name')
        date_of_birth = request.form.get('date_of_birth')

        # Check if the email already exists
        user = User.query.filter_by(email=email).first()
        if user:
            error = 'Email already in use. Please use a different email or log in.'
            return render_template('register.html', error=error)

        # Check if passwords match
        if password != confirm_password:
            error = 'Passwords do not match. Please try again.'
            return render_template('register.html', error=error)

        # Password strength validation
        if len(password) < 8:
            error = 'Password must be at least 8 characters long.'
            return render_template('register.html', error=error)
        if not re.search(r"[A-Z]", password):
            error = 'Password must contain at least one uppercase letter.'
            return render_template('register.html', error=error)
        if not re.search(r"[a-z]", password):
            error = 'Password must contain at least one lowercase letter.'
            return render_template('register.html', error=error)
        if not re.search(r"[0-9]", password):
            error = 'Password must contain at least one digit.'
            return render_template('register.html', error=error)
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            error = 'Password must contain at least one special character.'
            return render_template('register.html', error=error)

        # Create new user if all checks pass
        new_user = User(
            email=email,
            password=generate_password_hash(password, method='pbkdf2:sha256'),
            name=name,
            date_of_birth=date_of_birth
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('index'))

    return render_template('register.html')



@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)