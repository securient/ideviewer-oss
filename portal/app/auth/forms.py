"""
Authentication forms.
"""

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError

from app.models import User


class LoginForm(FlaskForm):
    """Login form — accepts username or email."""

    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember me')
    submit = SubmitField('Sign In')


class ChangePasswordForm(FlaskForm):
    """Change password form."""

    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[
        DataRequired(),
        Length(min=8, message='Password must be at least 8 characters')
    ])
    confirm_password = PasswordField('Confirm New Password', validators=[
        DataRequired(),
        EqualTo('new_password', message='Passwords must match')
    ])
    submit = SubmitField('Change Password')


class CustomerKeyForm(FlaskForm):
    """Form for creating a new customer key."""
    
    name = StringField('Key Name', validators=[
        DataRequired(),
        Length(min=1, max=100, message='Name must be between 1 and 100 characters')
    ])
    max_hosts = StringField('Max Hosts', default='5')
    submit = SubmitField('Generate Key')
