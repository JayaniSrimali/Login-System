"""
Flask Authentication System Configuration
==========================================
This module contains configuration settings for development and production environments.
Uses environment variables for sensitive data to maintain security best practices.
"""

import os
from datetime import timedelta
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


class Config:
    """
    Base configuration class with settings common to all environments.
    """
    
    # ==================== SECRET KEY ====================
    # Used for session management, CSRF protection, and token generation
    # CRITICAL: Must be set in environment variables for production
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    
    # ==================== DATABASE CONFIGURATION ====================
    # SQLAlchemy database URI - supports both SQLite and MySQL
    # Format for MySQL: mysql+pymysql://username:password@localhost/dbname
    # Format for SQLite: sqlite:///database.db
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///auth_system.db'
    
    # Disable SQLAlchemy event system (reduces overhead)
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Database connection pool settings (important for production)
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_size': 10,
        'pool_recycle': 3600,
        'pool_pre_ping': True,  # Verify connections before using
    }
    
    # ==================== SESSION CONFIGURATION ====================
    # Session timeout and security settings
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)
    SESSION_COOKIE_SECURE = False  # Set to True in production with HTTPS
    SESSION_COOKIE_HTTPONLY = True  # Prevent JavaScript access to session cookie
    SESSION_COOKIE_SAMESITE = 'Lax'  # CSRF protection
    
    # ==================== MAIL CONFIGURATION ====================
    # Email settings for OTP and password reset functionality
    MAIL_SERVER = os.environ.get('MAIL_SERVER') or 'smtp.gmail.com'
    MAIL_PORT = int(os.environ.get('MAIL_PORT') or 587)
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'True').lower() == 'true'
    MAIL_USE_SSL = os.environ.get('MAIL_USE_SSL', 'False').lower() == 'true'
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER') or MAIL_USERNAME
    
    # Mail configuration for OTP
    MAIL_SUBJECT_PREFIX = '[Auth System]'
    MAIL_MAX_EMAILS = None  # No limit on emails sent per connection
    
    # ==================== OAUTH CONFIGURATION ====================
    # Google OAuth settings
    GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
    GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')
    
    # Facebook OAuth settings
    FACEBOOK_APP_ID = os.environ.get('FACEBOOK_APP_ID')
    FACEBOOK_APP_SECRET = os.environ.get('FACEBOOK_APP_SECRET')
    
    # OAuth callback settings
    PREFERRED_URL_SCHEME = 'http'  # Set to 'https' in production
    OAUTH_CALLBACK_DOMAIN = os.environ.get('OAUTH_CALLBACK_DOMAIN') or 'localhost:5000'
    
    # ==================== OTP CONFIGURATION ====================
    # One-Time Password settings
    OTP_LENGTH = 6  # Length of OTP code
    OTP_EXPIRY_MINUTES = 10  # OTP expires after 10 minutes
    OTP_MAX_ATTEMPTS = 3  # Maximum verification attempts
    
    # ==================== PASSWORD RESET CONFIGURATION ====================
    # Password reset token settings
    PASSWORD_RESET_EXPIRY_MINUTES = 30  # Reset link expires after 30 minutes
    PASSWORD_MIN_LENGTH = 8  # Minimum password length
    PASSWORD_REQUIRE_UPPERCASE = True
    PASSWORD_REQUIRE_LOWERCASE = True
    PASSWORD_REQUIRE_DIGITS = True
    PASSWORD_REQUIRE_SPECIAL = True
    
    # ==================== JWT CONFIGURATION ====================
    # JSON Web Token settings (if using JWT for authentication)
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or SECRET_KEY
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    JWT_TOKEN_LOCATION = ['headers', 'cookies']
    JWT_COOKIE_SECURE = False  # Set to True in production with HTTPS
    JWT_COOKIE_CSRF_PROTECT = True
    JWT_CSRF_IN_COOKIES = True
    JWT_ACCESS_COOKIE_NAME = 'access_token_cookie'
    JWT_REFRESH_COOKIE_NAME = 'refresh_token_cookie'
    JWT_COOKIE_SAMESITE = 'Lax'
    
    # JWT algorithm and header configuration
    JWT_ALGORITHM = 'HS256'
    JWT_HEADER_NAME = 'Authorization'
    JWT_HEADER_TYPE = 'Bearer'
    
    # ==================== SECURITY CONFIGURATION ====================
    # Account lockout settings (brute force protection)
    MAX_LOGIN_ATTEMPTS = 5
    ACCOUNT_LOCKOUT_DURATION_MINUTES = 30
    
    # Rate limiting (requests per minute)
    RATELIMIT_ENABLED = True
    RATELIMIT_DEFAULT = "100 per hour"
    RATELIMIT_STORAGE_URL = os.environ.get('REDIS_URL') or 'memory://'
    
    # CORS settings (if building API for frontend)
    CORS_ORIGINS = os.environ.get('CORS_ORIGINS', '*').split(',')
    
    # ==================== FILE UPLOAD CONFIGURATION ====================
    # If handling profile pictures or document uploads
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5MB max file size
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}
    
    # ==================== LOGGING CONFIGURATION ====================
    LOG_LEVEL = os.environ.get('LOG_LEVEL') or 'INFO'
    LOG_FILE = os.environ.get('LOG_FILE') or 'auth_system.log'
    
    # ==================== APPLICATION SETTINGS ====================
    APP_NAME = 'Flask Auth System'
    SUPPORT_EMAIL = os.environ.get('SUPPORT_EMAIL') or 'support@example.com'
    
    # Timezone
    TIMEZONE = 'UTC'
    
    # Language and localization
    BABEL_DEFAULT_LOCALE = 'en'
    BABEL_DEFAULT_TIMEZONE = 'UTC'


class DevelopmentConfig(Config):
    """
    Development environment specific configuration.
    Enables debug mode and uses SQLite for easier development.
    """
    
    DEBUG = True
    TESTING = False
    
    # Use SQLite for development (easier setup)
    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or \
        'sqlite:///' + os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dev_auth.db')
    
    # Less strict settings for development
    SESSION_COOKIE_SECURE = False
    JWT_COOKIE_SECURE = False
    
    # Detailed error pages in development
    PROPAGATE_EXCEPTIONS = True
    
    # SQLAlchemy echo queries in development (useful for debugging)
    SQLALCHEMY_ECHO = os.environ.get('SQLALCHEMY_ECHO', 'False').lower() == 'true'
    
    # Disable rate limiting in development
    RATELIMIT_ENABLED = False
    
    # Mail debug settings (print emails to console instead of sending)
    MAIL_DEBUG = True
    MAIL_SUPPRESS_SEND = os.environ.get('MAIL_SUPPRESS_SEND', 'False').lower() == 'true'


class ProductionConfig(Config):
    """
    Production environment specific configuration.
    Enforces strict security settings and requires environment variables.
    """
    
    DEBUG = False
    TESTING = False
    
    # Require SECRET_KEY to be set in production
    SECRET_KEY = os.environ.get('SECRET_KEY')
    if not SECRET_KEY:
        raise ValueError("SECRET_KEY environment variable must be set in production!")
    
    # Require database URL in production
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    if not SQLALCHEMY_DATABASE_URI:
        raise ValueError("DATABASE_URL environment variable must be set in production!")
    
    # Production MySQL/PostgreSQL connection pool settings
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_size': 20,
        'max_overflow': 40,
        'pool_recycle': 3600,
        'pool_pre_ping': True,
        'pool_timeout': 30,
    }
    
    # Strict security settings for production
    SESSION_COOKIE_SECURE = True  # Requires HTTPS
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Strict'
    
    # JWT security for production
    JWT_COOKIE_SECURE = True  # Requires HTTPS
    JWT_COOKIE_CSRF_PROTECT = True
    JWT_CSRF_IN_COOKIES = True
    
    # Enable rate limiting in production
    RATELIMIT_ENABLED = True
    RATELIMIT_STORAGE_URL = os.environ.get('REDIS_URL')
    if not RATELIMIT_STORAGE_URL:
        print("WARNING: REDIS_URL not set. Rate limiting will use in-memory storage.")
        RATELIMIT_STORAGE_URL = 'memory://'
    
    # Stricter password requirements
    PASSWORD_MIN_LENGTH = 12
    
    # Production logging
    LOG_LEVEL = 'WARNING'
    
    # Disable SQLAlchemy query echo in production
    SQLALCHEMY_ECHO = False
    
    # Mail configuration validation
    if not os.environ.get('MAIL_USERNAME') or not os.environ.get('MAIL_PASSWORD'):
        print("WARNING: MAIL_USERNAME and MAIL_PASSWORD should be set for email functionality.")


class TestingConfig(Config):
    """
    Testing environment specific configuration.
    Uses in-memory SQLite database and disables external services.
    """
    
    DEBUG = False
    TESTING = True
    
    # Use in-memory SQLite for testing
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    
    # Disable CSRF protection in tests
    WTF_CSRF_ENABLED = False
    JWT_COOKIE_CSRF_PROTECT = False
    
    # Suppress email sending in tests
    MAIL_SUPPRESS_SEND = True
    
    # Faster password hashing for tests
    BCRYPT_LOG_ROUNDS = 4
    
    # Disable rate limiting in tests
    RATELIMIT_ENABLED = False
    
    # Short token expiry for testing
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=5)
    OTP_EXPIRY_MINUTES = 5


# Configuration dictionary for easy access
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}


def get_config(config_name=None):
    """
    Helper function to get configuration class based on environment.
    
    Args:
        config_name (str): Configuration name ('development', 'production', 'testing')
                          If None, uses FLASK_ENV environment variable.
    
    Returns:
        Config: Configuration class instance
    """
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')
    
    return config.get(config_name, DevelopmentConfig)