# Social Authentication Setup Guide

Your Flask login system now supports Google and Facebook OAuth! Follow these steps to configure it.

## Setup Instructions

### 1. Update the Database

Since we've added new fields to the User model, you need to update your database:

```bash
# Delete the old database file (or backup it first)
rm flask-plant-login/greennest.db

# The app will automatically create tables with new fields on next startup
```

### 2. Configure Google OAuth

1. Go to [Google Cloud Console](https://console.cloud.google.com)
2. Create a new project (or select an existing one)
3. Enable Google+ API:
   - Go to "APIs & Services" > "Library"
   - Search for "Google+ API"
   - Click enable
4. Create OAuth 2.0 credentials:
   - Go to "APIs & Services" > "Credentials"
   - Click "Create Credentials" > "OAuth client ID"
   - Choose "Web application"
   - Add Authorized Redirect URIs:
     - Development: `http://localhost:5000/auth/google/callback`
     - Production: `https://yourdomain.com/auth/google/callback`
5. Copy your Client ID and Client Secret
6. Add to `.env` file:
   ```
   GOOGLE_CLIENT_ID=your-client-id
   GOOGLE_CLIENT_SECRET=your-client-secret
   ```

### 3. Configure Facebook OAuth

1. Go to [Facebook Developers](https://developers.facebook.com)
2. Create a new app:
   - Click "Create App"
   - Choose "Consumer" as app type
   - Fill in app details
3. Add "Facebook Login" product:
   - In your app dashboard, click "Add Product"
   - Search and add "Facebook Login"
4. Configure Facebook Login:
   - Go to "Facebook Login" > "Settings"
   - Add Valid OAuth Redirect URIs:
     - Development: `http://localhost:5000/auth/facebook/callback`
     - Production: `https://yourdomain.com/auth/facebook/callback`
5. Get your credentials:
   - Go to "Settings" > "Basic"
   - Copy App ID and App Secret
6. Add to `.env` file:
   ```
   FACEBOOK_APP_ID=your-app-id
   FACEBOOK_APP_SECRET=your-app-secret
   ```

### 4. Update Your .env File

Edit `.env` file with your credentials:

```
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
FACEBOOK_APP_ID=your-facebook-app-id
FACEBOOK_APP_SECRET=your-facebook-app-secret
OAUTH_CALLBACK_DOMAIN=localhost:5000
```

## Testing OAuth Locally

1. Restart your Flask app
2. Go to `http://localhost:5000/login`
3. Click "Google" or "Facebook" button
4. You'll be redirected to the OAuth provider
5. Login with your credentials
6. You'll be redirected back and automatically logged in

## How It Works

1. **OAuth Flow**: When users click a social login button, they're redirected to Google/Facebook
2. **User Creation**: After authentication, a new user account is automatically created or existing account updated
3. **Auto-Login**: Users are automatically logged in after OAuth authentication
4. **Profile Data**: Name and profile picture are saved from the OAuth provider

## New User Fields

The User model now includes:

- `oauth_provider`: Which provider was used ('google', 'facebook', or None)
- `google_id`: Google's unique user ID
- `facebook_id`: Facebook's unique user ID
- `profile_picture`: User's profile picture URL
- `password_hash`: Now nullable (OAuth users don't need passwords)

## Important Notes

- **Development vs Production**:
  - For development: Use `http://localhost:5000`
  - For production: Use your actual domain with HTTPS
- **Database Migration**:
  - Existing users will need to migrate to the new schema
  - Or delete and recreate the database

- **Security**:
  - Never commit `.env` to version control
  - Keep CLIENT_ID and CLIENT_SECRET confidential
  - In production, use environment variables instead of `.env` files

## Troubleshooting

### "OAuth is not configured" message

- Ensure GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET or FACEBOOK_APP_ID/FACEBOOK_APP_SECRET are set in `.env`
- Restart the Flask app after updating `.env`

### "Redirect URI mismatch" error

- Ensure the callback URLs in your OAuth provider settings match exactly
- For development: `http://localhost:5000/auth/google/callback`
- For Facebook, also check Social Plugins > Website URL

### User not being created

- Check Flask console for error messages
- Ensure email is being returned by OAuth provider
- Some providers may require specific scopes

## Files Modified

1. **models.py** - Added OAuth fields to User model
2. **app.py** - Added OAuth routes and configuration
3. **login.html** - Updated social buttons to link to OAuth routes
4. **config.py** - Added OAuth configuration settings
5. **requirements.txt** - Added authlib dependency
6. **.env** - Created environment configuration file

Enjoy your working social authentication! 🎉
