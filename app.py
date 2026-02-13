from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from authlib.integrations.flask_client import OAuth
from models import db, User, OTPVerification
from forms import LoginForm, SignUpForm, ForgotPasswordForm, OTPVerificationForm, SetPasswordForm
from datetime import datetime, timedelta
import random
import os
from dotenv import load_dotenv


load_dotenv()

# Allow OAuth using HTTP for local development
if os.environ.get('FLASK_ENV') == 'development':
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-change-this-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///greennest.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# OAuth configuration
app.config['GOOGLE_CLIENT_ID'] = os.environ.get('GOOGLE_CLIENT_ID')
app.config['GOOGLE_CLIENT_SECRET'] = os.environ.get('GOOGLE_CLIENT_SECRET')
app.config['FACEBOOK_APP_ID'] = os.environ.get('FACEBOOK_APP_ID')
app.config['FACEBOOK_APP_SECRET'] = os.environ.get('FACEBOOK_APP_SECRET')

db.init_app(app)

# Initialize OAuth
oauth = OAuth(app)


# Register Google OAuth
google = oauth.register(
    name='google',
    client_id=app.config.get('GOOGLE_CLIENT_ID'),
    client_secret=app.config.get('GOOGLE_CLIENT_SECRET'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'},
)

# Register Facebook OAuth
facebook = oauth.register(
    name='facebook',
    client_id=app.config.get('FACEBOOK_APP_ID'),
    client_secret=app.config.get('FACEBOOK_APP_SECRET'),
    access_token_url='https://graph.facebook.com/v18.0/oauth/access_token',
    access_token_params=None,
    authorize_url='https://www.facebook.com/v18.0/dialog/oauth',
    authorize_params=None,
    api_base_url='https://graph.facebook.com/v18.0/',
    userinfo_endpoint='https://graph.facebook.com/me?fields=id,name,email,picture',
    client_kwargs={'scope': 'email'},
)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def generate_otp():
    """Generate a random 4-digit OTP"""
    return ''.join([str(random.randint(0, 9)) for _ in range(4)])


def send_otp_email(email, otp):
    """
    Send OTP via email (mock implementation)
    In production, integrate with SendGrid, AWS SES, or similar service
    """
    print(f"[EMAIL] Sending OTP {otp} to {email}")
    # TODO: Implement actual email sending
    return True


def send_otp_sms(phone, otp):
    """
    Send OTP via SMS (mock implementation)
    In production, integrate with Twilio, AWS SNS, or similar service
    """
    print(f"[SMS] Sending OTP {otp} to {phone}")
    # TODO: Implement actual SMS sending
    return True


def get_or_create_user_from_oauth(oauth_user_data, provider):
    """
    Helper function to get or create a user from OAuth provider data.
    
    Args:
        oauth_user_data (dict): User data from OAuth provider
        provider (str): OAuth provider name ('google' or 'facebook')
    
    Returns:
        User: The user object
    """
    email = oauth_user_data.get('email')
    
    # Check if user already exists by email
    user = User.query.filter_by(email=email).first()
    
    if user:
        # Update existing user with OAuth info
        if provider == 'google':
            user.google_id = oauth_user_data.get('sub')
        elif provider == 'facebook':
            user.facebook_id = oauth_user_data.get('id')
        
        user.oauth_provider = provider
        if not user.full_name and oauth_user_data.get('name'):
            user.full_name = oauth_user_data.get('name')
        if oauth_user_data.get('picture'):
            user.profile_picture = oauth_user_data.get('picture')
    else:
        # Create new user from OAuth data
        full_name = oauth_user_data.get('name', email.split('@')[0])
        
        user = User(
            full_name=full_name,
            email=email,
            oauth_provider=provider,
            profile_picture=oauth_user_data.get('picture')
        )
        
        if provider == 'google':
            user.google_id = oauth_user_data.get('sub')
        elif provider == 'facebook':
            user.facebook_id = oauth_user_data.get('id')
    
    db.session.add(user)
    db.session.commit()
    
    return user



@app.route('/')
def index():
    """Root URL - redirects to login or home"""
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    form = LoginForm()
    
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        
        # Check if username is email or phone
        if '@' in username:
            user = User.query.filter_by(email=username).first()
        else:
            user = User.query.filter_by(phone=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            flash('Login successful! Welcome back.', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Invalid username or password. Please try again.', 'error')
    
    return render_template('login.html', form=form)


@app.route('/auth/google')
def auth_google():
    """Initiate Google OAuth login"""
    if not app.config.get('GOOGLE_CLIENT_ID') or not app.config.get('GOOGLE_CLIENT_SECRET'):
        flash('Google OAuth is not configured. Please add GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET to environment variables.', 'error')
        return redirect(url_for('login'))
    
    # redirect_uri = url_for('auth_google_callback', _external=True).replace('localhost', '127.0.0.1')
    redirect_uri = url_for('auth_google_callback', _external=True)
    print(f"DEBUG: Using Redirect URI: {redirect_uri}")
    print(f"IMPORTANT: Ensure this URI is added to your Google Cloud Console Authorized Redirect URIs")
    return google.authorize_redirect(redirect_uri)


@app.route('/auth/google/callback')
def auth_google_callback():
    """Google OAuth callback"""
    try:
        token = google.authorize_access_token()
        user_info = google.parse_id_token(token)
        
        # Get or create user
        user = get_or_create_user_from_oauth(user_info, 'google')
        
        login_user(user)
        flash(f'Welcome {user.full_name}! Logged in with Google.', 'success')
        return redirect(url_for('home'))
    except Exception as e:
        print(f"Google OAuth error: {e}")
        flash('Failed to login with Google. Please try again.', 'error')
        return redirect(url_for('login'))


@app.route('/auth/facebook')
def auth_facebook():
    """Initiate Facebook OAuth login"""
    if not app.config.get('FACEBOOK_APP_ID') or not app.config.get('FACEBOOK_APP_SECRET'):
        flash('Facebook OAuth is not configured. Please add FACEBOOK_APP_ID and FACEBOOK_APP_SECRET to environment variables.', 'error')
        return redirect(url_for('login'))
    
    redirect_uri = url_for('auth_facebook_callback', _external=True)
    return facebook.authorize_redirect(redirect_uri)


@app.route('/auth/facebook/callback')
def auth_facebook_callback():
    """Facebook OAuth callback"""
    try:
        token = facebook.authorize_access_token()
        
        # Get user info from Facebook
        resp = facebook.get('me?fields=id,name,email,picture.type(large)', 
                           token=token)
        user_info = resp.json()
        
        # Extract picture URL if available
        if user_info.get('picture') and user_info['picture'].get('data'):
            user_info['picture'] = user_info['picture']['data'].get('url')
        
        # Get or create user
        user = get_or_create_user_from_oauth(user_info, 'facebook')
        
        login_user(user)
        flash(f'Welcome {user.full_name}! Logged in with Facebook.', 'success')
        return redirect(url_for('home'))
    except Exception as e:
        print(f"Facebook OAuth error: {e}")
        flash('Failed to login with Facebook. Please try again.', 'error')
        return redirect(url_for('login'))





@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Sign up page"""
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    form = SignUpForm()
    
    if form.validate_on_submit():
        full_name = form.full_name.data
        email_or_phone = form.email_or_phone.data
        password = form.password.data
        
        # Determine if email or phone
        if '@' in email_or_phone:
            email = email_or_phone
            phone = None
        else:
            email = None
            phone = email_or_phone
        
        # Create new user
        user = User(
            full_name=full_name,
            email=email if email else f"user_{phone}@greennest.com",  # Dummy email for phone users
            phone=phone
        )
        user.set_password(password)
        
        try:
            db.session.add(user)
            db.session.commit()
            
            login_user(user)
            flash('Account created successfully! Welcome to GreenNest.', 'success')
            return redirect(url_for('home'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred. Please try again.', 'error')
            print(f"Error creating user: {e}")
    
    return render_template('signup.html', form=form)


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """Forgot password page"""
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    form = ForgotPasswordForm()
    
    if form.validate_on_submit():
        email_or_phone = form.email_or_phone.data
        
        # Find user
        if '@' in email_or_phone:
            user = User.query.filter_by(email=email_or_phone).first()
            contact_type = 'email'
        else:
            user = User.query.filter_by(phone=email_or_phone).first()
            contact_type = 'phone'
        
        if user:
            # Generate OTP
            otp = generate_otp()
            
            # Save OTP to database
            otp_verification = OTPVerification(
                email=user.email,
                otp_code=otp,
                expires_at=datetime.utcnow() + timedelta(minutes=10)
            )
            db.session.add(otp_verification)
            db.session.commit()
            
            # Send OTP
            if contact_type == 'email':
                send_otp_email(user.email, otp)
            else:
                send_otp_sms(user.phone, otp)
            
            # Store email in session for next step
            session['reset_email'] = user.email
            flash(f'Verification code sent to your {contact_type}!', 'success')
            return redirect(url_for('verify_otp'))
        else:
            flash('No account found with this email or phone number.', 'error')
    
    return render_template('forgot_password.html', form=form)


@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    """OTP verification page"""
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    if 'reset_email' not in session:
        flash('Please start the password reset process first.', 'error')
        return redirect(url_for('forgot_password'))
    
    form = OTPVerificationForm()
    
    if form.validate_on_submit():
        # Combine OTP digits
        otp = (form.otp_digit_1.data + form.otp_digit_2.data + 
               form.otp_digit_3.data + form.otp_digit_4.data)
        
        # Verify OTP
        email = session.get('reset_email')
        otp_record = OTPVerification.query.filter_by(
            email=email,
            otp_code=otp,
            is_used=False
        ).first()
        
        if otp_record and otp_record.is_valid():
            # Mark OTP as used
            otp_record.is_used = True
            db.session.commit()
            
            flash('OTP verified successfully!', 'success')
            return redirect(url_for('set_password'))
        else:
            flash('Invalid or expired OTP. Please try again.', 'error')
    
    return render_template('verify_otp.html', form=form)


@app.route('/set-password', methods=['GET', 'POST'])
def set_password():
    """Set new password page"""
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    if 'reset_email' not in session:
        flash('Please complete the verification process first.', 'error')
        return redirect(url_for('forgot_password'))
    
    form = SetPasswordForm()
    
    if form.validate_on_submit():
        email = session.get('reset_email')
        user = User.query.filter_by(email=email).first()
        
        if user:
            user.set_password(form.password.data)
            db.session.commit()
            
            # Clear session
            session.pop('reset_email', None)
            
            flash('Password updated successfully! Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('An error occurred. Please try again.', 'error')
    
    return render_template('set_password.html', form=form)


@app.route('/home')
@login_required
def home():
    """Home page (protected)"""
    return render_template('home.html')


@app.route('/logout')
@login_required
def logout():
    """Logout user"""
    logout_user()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('login'))


@app.errorhandler(404)
def not_found(error):
    """404 error handler"""
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    """500 error handler"""
    db.session.rollback()
    return render_template('500.html'), 500


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print("Database tables created successfully!")
    
    app.run(debug=True, host='0.0.0.0', port=5001)