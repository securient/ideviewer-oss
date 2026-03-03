"""
Authentication routes.
"""

from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app
from flask_login import login_user, logout_user, login_required, current_user
from urllib.parse import urlparse

from app import db, oauth
from app.models import User
from app.auth.forms import LoginForm, RegistrationForm

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """User login."""
    
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    form = LoginForm()
    
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        
        if user is None or not user.check_password(form.password.data):
            flash('Invalid email or password', 'error')
            return redirect(url_for('auth.login'))
        
        if not user.is_active:
            flash('Your account has been disabled', 'error')
            return redirect(url_for('auth.login'))
        
        login_user(user, remember=form.remember_me.data)
        
        # Handle next page redirect
        next_page = request.args.get('next')
        if not next_page or urlparse(next_page).netloc != '':
            next_page = url_for('main.dashboard')
        
        flash(f'Welcome back, {user.username}!', 'success')
        return redirect(next_page)
    
    return render_template('auth/login.html', form=form)


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """User registration."""
    
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    form = RegistrationForm()
    
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            email=form.email.data.lower()
        )
        user.set_password(form.password.data)
        
        db.session.add(user)
        db.session.commit()
        
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('auth.login'))
    
    return render_template('auth/register.html', form=form)


@auth_bp.route('/logout')
@login_required
def logout():
    """User logout."""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))


@auth_bp.route('/login/google')
def google_login():
    """Initiate Google OAuth login."""
    if not current_app.config.get('GOOGLE_CLIENT_ID'):
        flash('Google login is not configured.', 'error')
        return redirect(url_for('auth.login'))
    
    # Build the callback URL
    redirect_uri = url_for('auth.google_callback', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)


@auth_bp.route('/login/google/callback')
def google_callback():
    """Handle Google OAuth callback."""
    if not current_app.config.get('GOOGLE_CLIENT_ID'):
        flash('Google login is not configured.', 'error')
        return redirect(url_for('auth.login'))
    
    try:
        # Get the access token
        token = oauth.google.authorize_access_token()
        
        # Get user info from Google
        user_info = token.get('userinfo')
        if not user_info:
            # Fallback: fetch from userinfo endpoint
            user_info = oauth.google.userinfo()
        
        if not user_info or not user_info.get('email'):
            flash('Failed to get user information from Google.', 'error')
            return redirect(url_for('auth.login'))
        
        email = user_info['email']
        
        # Check if email is verified
        if not user_info.get('email_verified', False):
            flash('Please verify your Google email address first.', 'error')
            return redirect(url_for('auth.login'))
        
        # Extract user details
        google_id = user_info.get('sub')
        name = user_info.get('name', email.split('@')[0])
        picture = user_info.get('picture')
        
        # Get or create the user
        user = User.get_or_create_oauth_user(
            email=email,
            username=name,
            provider='google',
            oauth_id=google_id,
            avatar_url=picture
        )
        
        if not user.is_active:
            flash('Your account has been disabled.', 'error')
            return redirect(url_for('auth.login'))
        
        # Log in the user
        login_user(user, remember=True)
        flash(f'Welcome, {user.username}!', 'success')
        
        # Handle next page redirect
        next_page = request.args.get('next')
        if not next_page or urlparse(next_page).netloc != '':
            next_page = url_for('main.dashboard')
        
        return redirect(next_page)
        
    except Exception as e:
        current_app.logger.error(f'Google OAuth error: {e}')
        flash('An error occurred during Google login. Please try again.', 'error')
        return redirect(url_for('auth.login'))
