from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from firebase_admin import auth as firebase_auth
from firebase_admin.exceptions import FirebaseError
from functools import wraps
import pyrebase
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.login_view = 'auth.login'

# Initialize Firebase Auth (client-side)
firebase_config = {
    "apiKey": os.getenv('FIREBASE_API_KEY'),
    "authDomain": f"{os.getenv('FIREBASE_PROJECT_ID')}.firebaseapp.com",
    "projectId": os.getenv('FIREBASE_PROJECT_ID'),
    "storageBucket": f"{os.getenv('FIREBASE_PROJECT_ID')}.appspot.com",
    "messagingSenderId": os.getenv('FIREBASE_MESSAGING_SENDER_ID'),
    "appId": os.getenv('FIREBASE_APP_ID'),
    "measurementId": os.getenv('FIREBASE_MEASUREMENT_ID'),
    "databaseURL": os.getenv('FIREBASE_DATABASE_URL')
}

firebase = pyrebase.initialize_app(firebase_config)
auth_client = firebase.auth()

auth_bp = Blueprint('auth', __name__)

class User(UserMixin):
    def __init__(self, uid, email, is_admin=False):
        self.id = uid
        self.email = email
        self.is_admin = is_admin

    @staticmethod
    def get(uid):
        try:
            user = firebase_auth.get_user(uid)
            return User(uid=user.uid, email=user.email)
        except FirebaseError:
            return None

@login_manager.user_loader
def load_user(uid):
    return User.get(uid)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        try:
            # Sign in with Firebase Auth
            user = auth_client.sign_in_with_email_and_password(email, password)
            
            # Get user data from Firebase Auth
            user_info = auth_client.get_account_info(user['idToken'])
            uid = user_info['users'][0]['localId']
            
            # Create user object and log them in
            user_obj = User(uid=uid, email=email)
            login_user(user_obj)
            
            return redirect(url_for('main.dashboard'))
            
        except Exception as e:
            error_message = str(e)
            if 'INVALID_PASSWORD' in error_message or 'EMAIL_NOT_FOUND' in error_message:
                flash('Invalid email or password', 'error')
            else:
                flash('An error occurred. Please try again.', 'error')
    
    return render_template('login.html')

@auth_bp.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('auth.signup'))
            
        try:
            # Create user with Firebase Auth
            user = auth_client.create_user_with_email_and_password(email, password)
            
            # Send email verification
            auth_client.send_email_verification(user['idToken'])
            
            flash('Account created successfully! Please check your email to verify your account.', 'success')
            return redirect(url_for('auth.login'))
            
        except Exception as e:
            error_message = str(e)
            if 'EMAIL_EXISTS' in error_message:
                flash('Email already in use', 'error')
            else:
                flash('An error occurred. Please try again.', 'error')
    
    return render_template('signup.html')

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('You do not have permission to access this page.', 'error')
            return redirect(url_for('main.index'))
        return f(*args, **kwargs)
    return decorated_function
