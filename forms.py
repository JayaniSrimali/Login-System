from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
from models import User
import re

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login Now')


class SignUpForm(FlaskForm):
    full_name = StringField('Full Name', validators=[
        DataRequired(message="Full name is required"),
        Length(min=2, max=100, message="Name must be between 2 and 100 characters")
    ])
    
    email_or_phone = StringField('Email Address or Phone Number', validators=[
        DataRequired(message="Email or phone number is required")
    ])
    
    password = PasswordField('Password', validators=[
        DataRequired(message="Password is required"),
        Length(min=8, message="Password must be at least 8 characters long")
    ])
    
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(message="Please confirm your password"),
        EqualTo('password', message="Passwords must match")
    ])
    
    submit = SubmitField('SIGN UP')
    
    def validate_password(self, field):
        """Validate password strength"""
        password = field.data
        if not re.search(r'[A-Z]', password):
            raise ValidationError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', password):
            raise ValidationError('Password must contain at least one lowercase letter')
        if not re.search(r'[0-9]', password):
            raise ValidationError('Password must contain at least one number')
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            raise ValidationError('Password must contain at least one special character')
    
    def validate_email_or_phone(self, field):
        """Check if user already exists"""
        value = field.data
        
        # Check if it's an email or phone
        if '@' in value:
            # It's an email
            user = User.query.filter_by(email=value).first()
            if user:
                raise ValidationError('An account with this email already exists')
        else:
            # It's a phone number
            user = User.query.filter_by(phone=value).first()
            if user:
                raise ValidationError('An account with this phone number already exists')


class ForgotPasswordForm(FlaskForm):
    email_or_phone = StringField('Email or Phone Number', validators=[
        DataRequired(message="Email or phone number is required")
    ])
    submit = SubmitField('Continue')


class OTPVerificationForm(FlaskForm):
    otp_digit_1 = StringField('', validators=[DataRequired(), Length(min=1, max=1)])
    otp_digit_2 = StringField('', validators=[DataRequired(), Length(min=1, max=1)])
    otp_digit_3 = StringField('', validators=[DataRequired(), Length(min=1, max=1)])
    otp_digit_4 = StringField('', validators=[DataRequired(), Length(min=1, max=1)])
    submit = SubmitField('Continue')


class SetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[
        DataRequired(message="Password is required"),
        Length(min=8, message="Password must be at least 8 characters long")
    ])
    
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(message="Please confirm your password"),
        EqualTo('password', message="Passwords must match")
    ])
    
    submit = SubmitField('Continue')
    
    def validate_password(self, field):
        """Validate password strength"""
        password = field.data
        if not re.search(r'[A-Z]', password):
            raise ValidationError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', password):
            raise ValidationError('Password must contain at least one lowercase letter')
        if not re.search(r'[0-9]', password):
            raise ValidationError('Password must contain at least one number')
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            raise ValidationError('Password must contain at least one special character')