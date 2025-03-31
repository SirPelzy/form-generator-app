# main.py
print("===> STARTING main.py execution <===") # Check 1
import os
from flask import Flask, render_template, redirect, url_for, flash, request
import json
import uuid # Not strictly needed now unless used elsewhere, but keep for now
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from flask_bcrypt import Bcrypt
print("Imports: Flask, SQLAlchemy, Login, Bcrypt...") # Check 2
from models import db, User, Form, Field, Submission
print("Imports: Local models...") # Check 3
# Removed FieldForm import as it's not used in this version
from forms import RegistrationForm, LoginForm
print("Imports: Local forms...") # Check 4
import secrets
# Use specific imports for clarity
from flask_wtf.csrf import CSRFProtect, validate_csrf
from wtforms.validators import ValidationError
# Imports for Flask-Limiter (Make sure Flask-Limiter is in requirements.txt)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
print("Imports: CSRF, Limiter...") # Check 5

# Initialize Flask App
app = Flask(__name__)
print("Flask app created.") # Check 6

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a_very_secret_key_for_dev_only_398u3nf')
print("Applying configuration...") # Check 7

# --- DATABASE CONFIGURATION ---
DATABASE_URL = os.environ.get('DATABASE_URL')
if DATABASE_URL and DATABASE_URL.startswith('postgres'):
    app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL.replace('postgres://', 'postgresql://', 1)
    print(f"Using DATABASE_URL (type: postgres)") # Check 7a
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
    print(f"Using fallback SQLite DB") # Check 7b

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
print("Configuration applied.") # Check 8

# --- Initialize CSRF Protection AFTER setting SECRET_KEY ---
try:
    csrf = CSRFProtect(app)
    print("CSRF initialized.") # Check 9
except Exception as e:
    print(f"ERROR initializing CSRF: {e}") # Check 9 Error
# --- END CSRF Initialization ---

# --- Re-add Rate Limiter Initialization ---
try:
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=["200 per day", "50 per hour"],
        storage_uri="memory://", # Limits reset on app restart
    )
    print("Limiter initialized.") # Check 10
except Exception as e:
    print(f"ERROR initializing Limiter: {e}") # Check 10 Error
# --- End Rate Limiter Initialization ---

# --- Initialize Other Extensions ---
try:
    db.init_app(app)
    print("DB initialized.") # Check 11
except Exception as e:
    print(f"ERROR initializing DB: {e}") # Check 11 Error

try:
    bcrypt = Bcrypt(app)
    print("Bcrypt initialized.") # Check 12
except Exception as e:
    print(f"ERROR initializing Bcrypt: {e}") # Check 12 Error

try:
    login_manager = LoginManager(app)
    login_manager.login_view = 'login'
    login_manager.login_message_category = 'info'
    print("LoginManager initialized.") # Check 13
except Exception as e:
    print(f"ERROR initializing LoginManager: {e}") # Check 13 Error


# --- User Loader ---
@login_manager.user_loader
def load_user(user_id):
    # print(f"Attempting to load user {user_id}") # Can add logging here too
    return User.query.get(int(user_id))

print("User loader defined.") # Check 14

# --- Define Allowed Field Types ---
ALLOWED_FIELD_TYPES = [...] # Keep your list here
print("ALLOWED_FIELD_TYPES defined.") # Check 15

# --- Define Health Check Route FIRST ---
@app.route('/_health')
def health_check():
     print("HEALTH CHECK ENDPOINT HIT!") # Check 16 (When accessed)
     # Try a minimal DB interaction if you suspect DB connection issues after init
     # try:
     #    db.session.execute(db.text('SELECT 1'))
     #    print("DB health check successful.")
     #    return "OK_DB", 200
     # except Exception as e:
     #    print(f"DB health check FAILED: {e}")
     #    return "FAIL_DB", 500
     return "OK", 200 # Basic health check

print("Health check route defined.") # Check 17
# --- Routes ---

@app.route('/')
@app.route('/home')
def home():
    return render_template('home.html', title='Home')

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("10 per hour", methods=['POST']) # <-- Re-add Rate Limiter decorator
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
@limiter.limit("10 per minute", methods=['POST']) # <-- Re-add Rate Limiter decorator
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

@app.route('/create_form', methods=['GET', 'POST'])
@login_required
def create_form():
    if request.method == 'POST':
        # *** Re-add CSRF Check for this non-WTForm POST ***
        try:
            validate_csrf(request.form.get('csrf_token'))
        except ValidationError:
             flash('Invalid CSRF token.', 'danger'); return redirect(url_for('dashboard'))
        # *** End CSRF Check ***

        form_title = request.form.get('form_title')
        form_description = request.form.get('form_description')

        if not form_title:
            flash('Form title is required.', 'warning')
            # Need to handle re-rendering with CSRF token available if using one in template
            # For now, redirecting on validation fail might be simpler if not using WTForms here
            # Let's stick to re-rendering for consistency
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
            return render_template('create_form.html', title='Create Form', current_title=form_title, current_description=form_description)

    # GET request
    return render_template('create_form.html', title='Create Form')

# --- EDIT FORM Route (Reverted to basic HTML form handling) ---
@app.route('/edit_form/<int:form_id>', methods=['GET', 'POST'])
@login_required
def edit_form(form_id):
     form_to_edit = Form.query.get_or_404(form_id) # Renamed to avoid clash
     if form_to_edit.author != current_user:
          flash('You do not have permission to edit this form.', 'danger')
          return redirect(url_for('dashboard'))

     # Handle ADDING a field (POST request using basic form data)
     if request.method == 'POST':
          # *** Add CSRF Check for this non-WTForm POST ***
          try:
              validate_csrf(request.form.get('csrf_token'))
          except ValidationError:
               flash('Invalid CSRF token.', 'danger'); return redirect(url_for('edit_form', form_id=form_id))
          # *** End CSRF Check ***

          field_label = request.form.get('field_label')
          field_type = request.form.get('field_type')
          field_required = 'field_required' in request.form
          field_options = request.form.get('field_options')

          # Basic Validation
          if not field_label: flash('Field label is required.', 'warning')
          elif field_type not in ALLOWED_FIELD_TYPES: flash('Invalid field type selected.', 'warning')
          else:
               options = field_options if field_type in ['radio', 'select'] else None
               new_field = Field(label=field_label, field_type=field_type, required=field_required,
                                 options=options, form_id=form_id)
               try:
                    db.session.add(new_field)
                    db.session.commit()
                    flash(f'Field "{field_label}" added successfully.', 'success')
                    # Redirect PRG pattern
                    return redirect(url_for('edit_form', form_id=form_id))
               except Exception as e:
                    db.session.rollback()
                    flash(f'Error adding field: {e}', 'danger')
                    print(f"Error adding field to form {form_id}: {e}")
                    # Fall through to render template below on error

     # GET Request OR failed POST validation: Display form info and existing fields
     fields = Field.query.filter_by(form_id=form_id).order_by(Field.id).all()

     return render_template('edit_form.html',
                           title=f'Edit Form: {form_to_edit.title}',
                           form=form_to_edit, # Pass the Form model object
                           fields=fields,
                           allowed_field_types=ALLOWED_FIELD_TYPES) # Pass types for dropdown

# --- EDIT FIELD Route (Reverted to basic HTML form handling) ---
@app.route('/edit_field/<int:field_id>', methods=['GET', 'POST'])
@login_required
def edit_field(field_id):
    field_to_edit = Field.query.get_or_404(field_id)
    parent_form = field_to_edit.form
    if parent_form.author != current_user:
        flash('You do not have permission to edit this field.', 'danger')
        return redirect(url_for('dashboard'))

    # Handle SAVING changes (POST request using basic form data)
    if request.method == 'POST':
        # *** Add CSRF Check for this non-WTForm POST ***
        try:
            validate_csrf(request.form.get('csrf_token'))
        except ValidationError:
             flash('Invalid CSRF token.', 'danger'); return redirect(url_for('edit_form', form_id=parent_form.id))
        # *** End CSRF Check ***

        new_label = request.form.get('field_label')
        new_type = request.form.get('field_type')
        new_required = 'field_required' in request.form
        new_options = request.form.get('field_options')

        # Basic Validation
        if not new_label: flash('Field label is required.', 'warning')
        elif new_type not in ALLOWED_FIELD_TYPES: flash('Invalid field type selected.', 'warning')
        else:
            # Update existing field object
            field_to_edit.label = new_label
            field_to_edit.field_type = new_type
            field_to_edit.required = new_required
            field_to_edit.options = new_options if new_type in ['radio', 'select'] else None
            try:
                db.session.commit()
                flash(f'Field "{new_label}" updated successfully.', 'success')
                return redirect(url_for('edit_form', form_id=parent_form.id))
            except Exception as e:
                db.session.rollback()
                flash(f'Error updating field: {e}', 'danger')
                print(f"Error updating field ID {field_id}: {e}")
                # Redirect back even on error
                return redirect(url_for('edit_form', form_id=parent_form.id))

        # If validation failed, re-render the edit page
        # Pass submitted data back? Or just the field object? Let's keep it simple
        # and just re-render with the original field data for now.
        return render_template('edit_field.html',
                               title=f'Edit Field: {field_to_edit.label}',
                               field=field_to_edit,
                               allowed_field_types=ALLOWED_FIELD_TYPES)

    # GET request: Display the edit form pre-filled
    return render_template('edit_field.html',
                           title=f'Edit Field: {field_to_edit.label}',
                           field=field_to_edit,
                           allowed_field_types=ALLOWED_FIELD_TYPES)

# --- DELETE FIELD Route --- (Keep CSRF Check)
@app.route('/delete_field/<int:field_id>', methods=['POST'])
@login_required
def delete_field(field_id):
    try: validate_csrf(request.form.get('csrf_token'))
    except ValidationError: flash('Invalid CSRF token.', 'danger'); return redirect(url_for('dashboard'))

    field_to_delete = Field.query.get_or_404(field_id)
    form_id_redirect = field_to_delete.form_id
    if field_to_delete.form.author != current_user:
        flash('You do not have permission.', 'danger'); return redirect(url_for('dashboard'))
    try:
        field_label = field_to_delete.label
        db.session.delete(field_to_delete)
        db.session.commit()
        flash(f'Field "{field_label}" deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback(); flash(f'Error deleting field: {e}', 'danger'); print(f"Error deleting field: {e}")
    return redirect(url_for('edit_form', form_id=form_id_redirect))

# --- DELETE FORM Route --- (Keep CSRF Check)
@app.route('/delete_form/<int:form_id>', methods=['POST'])
@login_required
def delete_form(form_id):
    try: validate_csrf(request.form.get('csrf_token'))
    except ValidationError: flash('Invalid CSRF token.', 'danger'); return redirect(url_for('dashboard'))

    form_to_delete = Form.query.get_or_404(form_id)
    if form_to_delete.author != current_user:
        flash('You do not have permission.', 'danger'); return redirect(url_for('dashboard'))
    try:
        form_title = form_to_delete.title
        db.session.delete(form_to_delete)
        db.session.commit()
        flash(f'Form "{form_title}" deleted.', 'success')
    except Exception as e:
        db.session.rollback(); flash(f'Error deleting form: {e}', 'danger'); print(f"Error deleting form: {e}")
    return redirect(url_for('dashboard'))

# --- PUBLIC FORM DISPLAY & SUBMISSION Route ---
@app.route('/form/<string:form_key>', methods=['GET', 'POST'])
@limiter.limit("60 per hour", methods=['POST']) # <-- Re-add Rate Limiter decorator
def public_form(form_key):
    form = Form.query.filter_by(unique_key=form_key).first_or_404()
    fields = Field.query.filter_by(form_id=form.id).order_by(Field.id).all()

    if request.method == 'POST':
        try: validate_csrf(request.form.get('csrf_token')) # Keep CSRF Check
        except ValidationError: flash('Invalid submission token.', 'warning'); return render_template('public_form.html', form=form, fields=fields, errors={}, submitted_data=request.form)

        submitted_data = request.form
        errors = {}
        # Server-Side Validation
        for field in fields:
            field_name = f"field_{field.id}"; value = submitted_data.get(field_name)
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
            db.session.rollback(); flash(f'Error saving submission: {e}', 'danger'); print(f"Error saving submission form {form.id}: {e}")
            return render_template('public_form.html', form=form, fields=fields, errors={"_save_error": "Could not save submission."}, submitted_data=submitted_data)

    # GET request
    return render_template('public_form.html', form=form, fields=fields, errors={}, submitted_data={})

# --- VIEW SUBMISSIONS Route ---
@app.route('/form/<int:form_id>/submissions')
@login_required
def view_submissions(form_id):
    form = Form.query.get_or_404(form_id)
    if form.author != current_user:
        flash('You do not have permission.', 'danger'); return redirect(url_for('dashboard'))

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
    print("Other routes defined.") # Check 18

# --- Run Application ---
if __name__ == '__main__':
    # This block likely won't run under Gunicorn, but good practice
    port = int(os.environ.get('PORT', 81))
    print(f"Starting Flask dev server on 0.0.0.0:{port} (Should NOT happen on Railway)...") # Check 19
    app.run(host='0.0.0.0', port=port)

print("===> END of main.py execution (definitions complete) <===") # Check 20
