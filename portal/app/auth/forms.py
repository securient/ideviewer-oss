"""
Authentication forms.
"""

from flask_wtf import FlaskForm
from wtforms import (
    StringField,
    PasswordField,
    BooleanField,
    SubmitField,
    SelectField,
    SelectMultipleField,
    URLField,
    widgets,
)
from wtforms.validators import DataRequired, Email, EqualTo, Length, URL, ValidationError

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
    submit = SubmitField('Generate Key')


SUPPORTED_WEBHOOK_EVENTS = [
    ('tamper_alert.created', 'Tamper alert created'),
    ('extension.high_risk_detected', 'High-risk extension detected'),
    ('hook_bypass.detected', 'Git hook bypass detected'),
    ('policy.violation', 'Policy violation (T2.2)'),
]


class WebhookSubscriptionForm(FlaskForm):
    """Form for creating/editing an outbound webhook subscription."""

    name = StringField('Name', validators=[
        DataRequired(),
        Length(min=1, max=100),
    ])
    url = URLField('Endpoint URL', validators=[
        DataRequired(),
        URL(require_tld=False, message='Must be a valid URL'),
        Length(max=500),
    ])
    customer_key_id = SelectField('Customer key', coerce=int, validators=[DataRequired()])
    event_types = SelectMultipleField(
        'Event types',
        choices=SUPPORTED_WEBHOOK_EVENTS,
        option_widget=widgets.CheckboxInput(),
        widget=widgets.ListWidget(prefix_label=False),
        validators=[DataRequired(message='Select at least one event type')],
    )
    submit = SubmitField('Save')
