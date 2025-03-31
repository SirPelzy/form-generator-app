# forms.py
from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, BooleanField, SubmitField # Added SelectField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError # Added Length
from models import User # Import User model to check for existing users

class RegistrationForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    # Custom validators to check if username or email already exist
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is already registered. Please choose a different one or login.')

class LoginForm(FlaskForm):
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

# --- New Form for Adding/Editing Fields ---
class FieldForm(FlaskForm):
    label = StringField('Field Label',
                        validators=[DataRequired(), Length(min=2, max=100)])
    # Choices will be populated dynamically in the route
    field_type = SelectField('Field Type',
                             choices=[],
                             validators=[DataRequired()])
    required = BooleanField('Required?')
    # Add validation later if needed (e.g., ensure options only for select/radio)
    options = StringField('Options (comma-separated for Select/Radio)')
    # Submit button text might be changed in the template if needed
    submit = SubmitField('Save Field')
