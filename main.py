# main.py
# Talisman imports and initialization removed

import os
from flask import Flask, render_template, redirect, url_for, flash, request
import json
import uuid
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from flask_bcrypt import Bcrypt
from models import db, User, Form, Field, Submission # Import db and models directly now
from forms import RegistrationForm, LoginForm, FieldForm # Import FieldForm
import secrets
# Use specific imports for clarity
from flask_wtf.csrf import CSRFProtect, validate_csrf
from wtforms.validators import ValidationError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
# Removed: from flask_talisman import Talisman

# Initialize Flask App
app = Flask(__name__)

# Configuration
# IMPORTANT: Make sure SECRET_KEY is set securely in Railway environment variables
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a_very_secret_key_for_dev_only_398u3nf')

# --- DATABASE CONFIGURATION ---
DATABASE_URL = os.environ.get('DATABASE_URL')
if DATABASE_URL and DATABASE_URL.startswith('postgres'):
    # Railway provides a postgres URL, but SQLAlchemy needs 'postgresql'
    app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL.replace('postgres://', 'postgresql://', 1)
else:
    # Fallback for local development (Replit) - Railway will use the above
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- Initialize CSRF Protection AFTER setting SECRET_KEY ---
csrf = CSRFProtect(app)
# --- END CSRF Initialization ---

# --- Initialize Rate Limiter ---
limiter = Limiter(
    get_remote_address, # Use IP address to identify users for limiting
    app=app,
    default_limits=["200 per day", "50 per hour"], # Default limits for all routes
    storage_uri="memory://", # Use in-memory storage (Note: limits reset on app restart)
)
# --- End Rate Limiter Initialization ---

# --- Initialize Other Extensions ---
db.init_app(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Configure the user loader function required by Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Define allowed field types (used in the template dropdown and validation)
ALLOWED_FIELD_TYPES = [
    'text', 'email', 'textarea', 'number', 'date',
    'checkbox', 'radio', 'select'
]

# --- Routes ---

@app.route('/')
@app.route('/home')
def home():
    return render_template('home.html', title='Home')

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("10 per hour", methods=['POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password_hash=hashed_password)
        try:
            db.session.add(user)
            db.session.commit()
            flash(f'Account created for {form.username.data}! You can now log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating account: {e}', 'danger')
            print(f"Error creating account: {e}")
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute", methods=['POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password_hash, form.password.data):
            login_user(user, remember=form.remember.data)
            flash('Login successful!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check email and password.', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    user_forms = Form.query.filter_by(user_id=current_user.id).order_by(Form.created_at.desc()).all()
    return render_template('dashboard.html', title='Dashboard', user_forms=user_forms)

# create_form still uses basic HTML form - recommend refactoring to WTForms later
@app.route('/create_form', methods=['GET', 'POST'])
@login_required
def create_form():
    if request.method == 'POST':
        # *** Manual CSRF Check needed if not using WTForms ***
        try:
            validate_csrf(request.form.get('csrf_token'))
        except ValidationError:
             flash('Invalid CSRF token.', 'danger'); return redirect(url_for('dashboard'))
        # *** End CSRF Check ***

        form_title = request.form.get('form_title')
        form_description = request.form.get('form_description')

        if not form_title:
            flash('Form title is required.', 'warning')
            # Need to pass token for re-render
            return render_template('create_form.html', title='Create Form', current_title=form_title, current_description=form_description)

        form_key = secrets.token_urlsafe(16)
        new_form = Form(title=form_title, description=form_description,
                        user_id=current_user.id, unique_key=form_key)

        try:
            db.session.add(new_form)
            db.session.commit()
            flash(f'Form "{form_title}" created successfully! Now add some fields.', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating form: {e}', 'danger')
            print(f"Error creating form: {e}")
            # Need to pass token for re-render
            return render_template('create_form.html', title='Create Form', current_title=form_title, current_description=form_description)

    # GET request
    return render_template('create_form.html', title='Create Form')

# --- EDIT FORM Route (Handles Adding Fields and Displaying) ---
@app.route('/edit_form/<int:form_id>', methods=['GET', 'POST'])
@login_required
def edit_form(form_id):
    form_to_edit = Form.query.get_or_404(form_id)
    if form_to_edit.author != current_user:
        flash('You do not have permission to edit this form.', 'danger')
        return redirect(url_for('dashboard'))

    add_field_form = FieldForm()
    add_field_form.field_type.choices = [(ft, ft.capitalize()) for ft in ALLOWED_FIELD_TYPES]

    if add_field_form.validate_on_submit():
        label = add_field_form.label.data
        field_type = add_field_form.field_type.data
        required = add_field_form.required.data
        options = add_field_form.options.data

        if field_type not in ['radio', 'select']: options = None

        new_field = Field(label=label, field_type=field_type, required=required,
                          options=options, form_id=form_id)
        try:
            db.session.add(new_field)
            db.session.commit()
            flash(f'Field "{label}" added successfully.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding field: {e}', 'danger')
            print(f"Error adding field to form {form_id}: {e}")
        return redirect(url_for('edit_form', form_id=form_id))

    fields = Field.query.filter_by(form_id=form_id).order_by(Field.id).all()
    # Generate embed code - Moved logic here as Talisman removed
    # No specific headers needed here now

    return render_template('edit_form.html',
                           title=f'Edit Form: {form_to_edit.title}',
                           form_data=form_to_edit,
                           fields=fields,
                           add_field_form=add_field_form)

# --- EDIT FIELD Route ---
@app.route('/edit_field/<int:field_id>', methods=['GET', 'POST'])
@login_required
def edit_field(field_id):
    field_to_edit = Field.query.get_or_404(field_id)
    parent_form = field_to_edit.form
    if parent_form.author != current_user:
        flash('You do not have permission to edit this field.', 'danger')
        return redirect(url_for('dashboard'))

    form = FieldForm(obj=field_to_edit if request.method == 'GET' else None)
    form.field_type.choices = [(ft, ft.capitalize()) for ft in ALLOWED_FIELD_TYPES]

    if form.validate_on_submit():
        form.populate_obj(field_to_edit)
        if field_to_edit.field_type not in ['radio', 'select']:
             field_to_edit.options = None
        try:
            db.session.commit()
            flash(f'Field "{field_to_edit.label}" updated successfully.', 'success')
            return redirect(url_for('edit_form', form_id=parent_form.id))
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating field: {e}', 'danger')
            print(f"Error updating field ID {field_id}: {e}")
            return redirect(url_for('edit_form', form_id=parent_form.id))

    return render_template('edit_field.html',
                           title=f'Edit Field: {field_to_edit.label}',
                           form=form,
                           field=field_to_edit)

# --- DELETE FIELD Route ---
@app.route('/delete_field/<int:field_id>', methods=['POST'])
@login_required
def delete_field(field_id):
    try:
        validate_csrf(request.form.get('csrf_token'))
    except ValidationError:
        flash('Invalid CSRF token. Please try again.', 'danger')
        return redirect(url_for('dashboard'))

    field_to_delete = Field.query.get_or_404(field_id)
    form_id_redirect = field_to_delete.form_id
    if field_to_delete.form.author != current_user:
        flash('You do not have permission to delete this field.', 'danger')
        return redirect(url_for('dashboard'))
    try:
        field_label = field_to_delete.label
        db.session.delete(field_to_delete)
        db.session.commit()
        flash(f'Field "{field_label}" deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting field: {e}', 'danger')
        print(f"Error deleting field ID {field_id}: {e}")
    return redirect(url_for('edit_form', form_id=form_id_redirect))

# --- DELETE FORM Route ---
@app.route('/delete_form/<int:form_id>', methods=['POST'])
@login_required
def delete_form(form_id):
    try:
        validate_csrf(request.form.get('csrf_token'))
    except ValidationError:
        flash('Invalid CSRF token. Please try again.', 'danger')
        return redirect(url_for('dashboard'))

    form_to_delete = Form.query.get_or_404(form_id)
    if form_to_delete.author != current_user:
        flash('You do not have permission to delete this form.', 'danger')
        return redirect(url_for('dashboard'))
    try:
        form_title = form_to_delete.title
        db.session.delete(form_to_delete)
        db.session.commit()
        flash(f'Form "{form_title}" and all its data deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting form: {e}', 'danger')
        print(f"Error deleting form ID {form_id}: {e}")
    return redirect(url_for('dashboard'))

# --- PUBLIC FORM DISPLAY & SUBMISSION Route ---
# Removed Talisman decorator
@app.route('/form/<string:form_key>', methods=['GET', 'POST'])
@limiter.limit("60 per hour", methods=['POST']) # Keep rate limit
def public_form(form_key):
    form = Form.query.filter_by(unique_key=form_key).first_or_404()
    fields = Field.query.filter_by(form_id=form.id).order_by(Field.id).all() # Fetch fields for both GET & POST logic

    if request.method == 'POST':
        try: # Check CSRF on public POST
            validate_csrf(request.form.get('csrf_token'))
        except ValidationError:
            flash('Invalid submission token.', 'warning')
            return render_template('public_form.html', form=form, fields=fields, errors={}, submitted_data=request.form)

        submitted_data = request.form
        errors = {}
        # Server-Side Validation
        for field in fields:
            field_name = f"field_{field.id}"
            value = submitted_data.get(field_name)
            if field.required:
                is_missing = False
                if field.field_type == 'checkbox':
                    if field_name not in submitted_data: is_missing = True
                elif not value: is_missing = True
                if is_missing: errors[field_name] = "This field is required."

        if errors:
            flash('Please correct the errors below.', 'warning')
            return render_template('public_form.html', form=form, fields=fields, errors=errors, submitted_data=submitted_data)

        # Save submission
        submission_data_dict = {}
        try:
            for field in fields:
                field_name = f"field_{field.id}"
                if field.field_type == 'checkbox': value = 'true' if field_name in submitted_data else 'false'
                else: value = submitted_data.get(field_name)
                submission_data_dict[field_name] = value

            data_json = json.dumps(submission_data_dict)
            new_submission = Submission(form_id=form.id, data=data_json)
            db.session.add(new_submission)
            db.session.commit()
            flash('Thank you! Your submission has been recorded.', 'success')
            return redirect(url_for('public_form', form_key=form_key))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred while saving submission: {e}', 'danger')
            print(f"Error saving submission form {form.id}: {e}")
            return render_template('public_form.html', form=form, fields=fields, errors={"_save_error": "Could not save submission."}, submitted_data=submitted_data)

    # GET request
    return render_template('public_form.html', form=form, fields=fields, errors={}, submitted_data={})

# --- VIEW SUBMISSIONS Route ---
@app.route('/form/<int:form_id>/submissions')
@login_required
def view_submissions(form_id):
    form = Form.query.get_or_404(form_id)
    if form.author != current_user:
        flash('You do not have permission to view submissions for this form.', 'danger')
        return redirect(url_for('dashboard'))

    fields = Field.query.filter_by(form_id=form.id).order_by(Field.id).all()
    submissions_raw = Submission.query.filter_by(form_id=form.id).order_by(Submission.submitted_at.desc()).all()
    parsed_submissions = []
    for sub in submissions_raw:
        try: data_dict = json.loads(sub.data)
        except json.JSONDecodeError: data_dict = {"error": "Could not parse data."}; print(f"JSON Error Sub ID {sub.id}")
        parsed_submissions.append({'id': sub.id, 'submitted_at': sub.submitted_at, 'data': data_dict})

    return render_template('view_submissions.html',
                           title=f'Submissions for {form.title}',
                           form=form, fields=fields, submissions=parsed_submissions)

# --- Run Application ---
if __name__ == '__main__':
    # DO NOT run db.create_all() here in production
    app.run(host='0.0.0.0', port=os.environ.get('PORT', 81)) # Use PORT env var if available
