"""
Authentication routes.
"""

from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app
from flask_login import login_user, logout_user, login_required, current_user
from urllib.parse import urlparse

from app import db, oauth
from app.models import User
from app.auth.forms import LoginForm, ChangePasswordForm

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """User login via username or email."""

    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    # Compute local login status
    google_oauth = bool(current_app.config.get('GOOGLE_CLIENT_ID') and current_app.config.get('GOOGLE_CLIENT_SECRET'))
    disable_mode = current_app.config.get('DISABLE_LOCAL_LOGIN', 'false')
    local_login_enabled = True
    if disable_mode == 'true':
        local_login_enabled = False
    elif disable_mode == 'auto' and google_oauth:
        local_login_enabled = False

    # If local login is disabled and Google OAuth is available, redirect straight to Google
    if not local_login_enabled and google_oauth:
        return redirect(url_for('auth.google_login'))

    form = LoginForm()

    if form.validate_on_submit():
        # Block local login if disabled
        if not local_login_enabled:
            flash('Local login is disabled. Please use Google login.', 'error')
            return redirect(url_for('auth.login'))

        identifier = form.username.data.strip()
        # Allow login by username or email
        user = User.query.filter_by(username=identifier).first()
        if user is None:
            user = User.query.filter_by(email=identifier.lower()).first()

        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password', 'error')
            return redirect(url_for('auth.login'))

        if not user.is_active:
            flash('Your account has been disabled', 'error')
            return redirect(url_for('auth.login'))

        login_user(user, remember=form.remember_me.data)

        # Check if user needs to change default password
        if user.must_change_password:
            flash('Please change your default password.', 'warning')
            return redirect(url_for('auth.change_password'))

        # Handle next page redirect
        next_page = request.args.get('next')
        if not next_page or urlparse(next_page).netloc != '':
            next_page = url_for('main.dashboard')

        flash(f'Welcome back, {user.username}!', 'success')
        return redirect(next_page)

    return render_template('auth/login.html', form=form)


@auth_bp.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Change password page."""
    form = ChangePasswordForm()

    if form.validate_on_submit():
        if not current_user.check_password(form.current_password.data):
            flash('Current password is incorrect.', 'error')
            return redirect(url_for('auth.change_password'))

        current_user.set_password(form.new_password.data)
        current_user.must_change_password = False
        db.session.commit()

        flash('Your password has been updated.', 'success')
        return redirect(url_for('main.dashboard'))

    return render_template('auth/change_password.html', form=form)


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

    redirect_uri = url_for('auth.google_callback', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)


@auth_bp.route('/login/google/callback')
def google_callback():
    """Handle Google OAuth callback."""
    if not current_app.config.get('GOOGLE_CLIENT_ID'):
        flash('Google login is not configured.', 'error')
        return redirect(url_for('auth.login'))

    try:
        token = oauth.google.authorize_access_token()
        user_info = token.get('userinfo')
        if not user_info:
            user_info = oauth.google.userinfo()

        if not user_info or not user_info.get('email'):
            flash('Failed to get user information from Google.', 'error')
            return redirect(url_for('auth.login'))

        email = user_info['email']

        if not user_info.get('email_verified', False):
            flash('Please verify your Google email address first.', 'error')
            return redirect(url_for('auth.login'))

        google_id = user_info.get('sub')
        name = user_info.get('name', email.split('@')[0])
        picture = user_info.get('picture')

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

        login_user(user, remember=True)
        flash(f'Welcome, {user.username}!', 'success')

        next_page = request.args.get('next')
        if not next_page or urlparse(next_page).netloc != '':
            next_page = url_for('main.dashboard')

        return redirect(next_page)

    except Exception as e:
        current_app.logger.error(f'Google OAuth error: {e}')
        flash('An error occurred during Google login. Please try again.', 'error')
        return redirect(url_for('auth.login'))
