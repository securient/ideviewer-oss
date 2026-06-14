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
    IntegerField,
    URLField,
    widgets,
)
from wtforms.validators import (
    DataRequired,
    Email,
    EqualTo,
    Length,
    NumberRange,
    Optional as OptionalValidator,
    URL,
    ValidationError,
)

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
    # Proactive — fired as the developer's machine changes
    ('extension.installed', 'Extension installed'),
    ('extension.updated', 'Extension updated'),
    ('extension.removed', 'Extension removed / uninstalled'),
    ('secret.detected', 'Plaintext secret detected'),
    ('extension.high_risk_detected', 'High-risk extension detected'),
    ('extension.threat_matched', 'Known-bad / typosquat extension (threat intel)'),
    ('extension.unpublished_detected', 'Extension removed from marketplace'),
    # Policy & enforcement
    ('policy.violation', 'Policy violation'),
    ('enforcement.action_created', 'Enforcement action created'),
    ('enforcement.completed', 'Enforcement action completed'),
    # Integrity / tamper
    ('tamper_alert.created', 'Tamper alert created'),
    ('hook_bypass.detected', 'Git hook bypass detected'),
    # Fleet drift / anomaly (B7)
    ('anomaly.new_risky_extension', 'New risky extension in fleet'),
    ('anomaly.rapid_propagation', 'Extension spreading rapidly across fleet'),
]


WEBHOOK_TYPES = [
    ('generic', 'Generic (signed JSON)'),
    ('slack', 'Slack'),
    ('pagerduty', 'PagerDuty'),
]


class WebhookSubscriptionForm(FlaskForm):
    """Form for creating/editing an outbound webhook subscription."""

    name = StringField('Name', validators=[
        DataRequired(),
        Length(min=1, max=100),
    ])
    type = SelectField('Type', choices=WEBHOOK_TYPES, validators=[DataRequired()])
    # For slack/generic this is a URL; for pagerduty it's the Events API v2
    # routing (integration) key. Validation is type-aware in validate().
    url = StringField('Endpoint URL / routing key', validators=[
        DataRequired(),
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

    def validate(self, extra_validators=None):
        if not super().validate(extra_validators=extra_validators):
            return False
        # PagerDuty uses a routing key (not a URL); slack/generic need a URL.
        if self.type.data == 'pagerduty':
            if len((self.url.data or '').strip()) < 8:
                self.url.errors.append('Enter your PagerDuty Events API v2 routing key')
                return False
        else:
            u = (self.url.data or '').strip().lower()
            if not (u.startswith('http://') or u.startswith('https://')):
                self.url.errors.append('Must be an http(s) URL')
                return False
        return True


POLICY_ACTIONS = [
    ('allow', 'Allow (whitelist)'),
    ('warn', 'Warn'),
    ('block-alert', 'Alert only (critical alert, no enforcement)'),
    ('quarantine', 'Quarantine (alert + quarantine on endpoint)'),
]

POLICY_RISK_LEVELS = [
    ('', 'Any'),
    ('low', 'Low or higher'),
    ('medium', 'Medium or higher'),
    ('high', 'High or higher'),
    ('critical', 'Critical only'),
]


class ExtensionPolicyForm(FlaskForm):
    """Form for creating an extension policy."""

    name = StringField('Name', validators=[
        DataRequired(),
        Length(min=1, max=100),
    ])
    customer_key_id = SelectField('Customer key', coerce=int, validators=[DataRequired()])
    priority = IntegerField('Priority', default=100, validators=[
        DataRequired(),
        NumberRange(min=1, max=10000, message='Priority must be 1-10000'),
    ])
    action = SelectField('Action', choices=POLICY_ACTIONS, validators=[DataRequired()])
    match_publisher = StringField('Publisher glob', validators=[
        OptionalValidator(), Length(max=200),
    ])
    match_extension_id = StringField('Extension ID glob', validators=[
        OptionalValidator(), Length(max=200),
    ])
    match_permission_glob = StringField('Permission glob', validators=[
        OptionalValidator(), Length(max=200),
    ])
    match_risk_level = SelectField('Risk level threshold', choices=POLICY_RISK_LEVELS, validators=[
        OptionalValidator(),
    ])
    submit = SubmitField('Save policy')

    def validate(self, extra_validators=None):
        ok = super().validate(extra_validators=extra_validators)
        if not ok:
            return False
        if not any([
            self.match_publisher.data,
            self.match_extension_id.data,
            self.match_permission_glob.data,
            self.match_risk_level.data,
        ]):
            self.match_publisher.errors.append(
                'At least one match criterion is required'
            )
            return False
        return True
