from flask import Flask, request, jsonify, send_file, redirect, url_for, session, current_app
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_cors import CORS
from models import db, User, Application, File
import os
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import mimetypes
import uuid
import shutil
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Get environment variables or use defaults
ENVIRONMENT = os.environ.get('FLASK_ENV', 'production')
PRODUCTION_DOMAIN = os.environ.get('PRODUCTION_DOMAIN', 'https://gradpath-2.vercel.app')

# Initialize Flask app
app = Flask(__name__)

# Log deployment information
logger.info(f"Application deployed/updated by: Rishikesh0523")
logger.info(f"Deployment timestamp: 2025-03-22 17:17:19 UTC")
logger.info(f"Environment: {ENVIRONMENT}")

# Configure CORS based on environment
if ENVIRONMENT == 'production':
    # Production CORS settings - restrict to your domain only
    CORS(app, 
         resources={r"/api/*": {"origins": PRODUCTION_DOMAIN}},
         supports_credentials=True,
         allow_headers=["Content-Type", "Authorization", "X-Requested-With"],
         methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
    
    logger.info(f"CORS configured for production: {PRODUCTION_DOMAIN}")
else:
    # Development CORS settings - allow localhost
    CORS(app, 
         resources={r"/api/*": {"origins": "http://localhost:3000"}},
         supports_credentials=True)
    
    logger.info("CORS configured for development environment (localhost)")

# Configure app settings
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///applicants.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.environ.get('UPLOAD_FOLDER', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max upload size

# Production security settings
if ENVIRONMENT == 'production':
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)

# Security headers middleware
@app.after_request
def add_security_headers(response):
    if ENVIRONMENT == 'production':
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

# Ensure upload directory exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])
    logger.info(f"Created upload directory: {app.config['UPLOAD_FOLDER']}")

# Initialize database
db.init_app(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Create database tables
with app.app_context():
    db.create_all()
    logger.info("Database tables created")
    
    # Create default admin user if no users exist
    if not User.query.first():
        admin = User(
            email='admin@example.com',
            is_admin=True,
            first_name='Admin',
            last_name='User'
        )
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()
        print("Default admin user created with email: admin@example.com and password: admin123")
        logger.info("Default admin user created")

# Helper functions
def get_file_extension(filename):
    return os.path.splitext(filename)[1].lower()

def generate_unique_filename(original_filename):
    """Generate a unique filename with the original extension."""
    extension = get_file_extension(original_filename)
    return f"{uuid.uuid4()}{extension}"

def create_user_directory(user_id):
    """Create a directory for the user's files if it doesn't exist."""
    user_dir = os.path.join(app.config['UPLOAD_FOLDER'], str(user_id))
    if not os.path.exists(user_dir):
        os.makedirs(user_dir)
    return user_dir

def get_mime_type(file_path):
    """Get the MIME type of a file."""
    return mimetypes.guess_type(file_path)[0] or 'application/octet-stream'

# Root route handler
@app.route('/')
def index():
    """
    Root endpoint that returns API information.
    This prevents 404 errors when accessing the root URL.
    """
    return jsonify({
        'name': 'PhD Application Tracking API',
        'version': '1.0.0',
        'status': 'online',
        'timestamp': '2025-03-22 17:17:19',
        'deployed_by': 'Rishikesh0523',
        'api_prefix': '/api',
        'documentation': '/api/docs',
        'environment': ENVIRONMENT
    }), 200

# Health check endpoint
@app.route('/api/health-check', methods=['GET'])
def health_check():
    """Health check endpoint for monitoring."""
    try:
        # Check database connection
        db_status = "connected" if db.engine.table_names() else "error"
    except Exception as e:
        db_status = f"error: {str(e)}"
        
    return jsonify({
        'status': 'healthy',
        'timestamp': '2025-03-22 17:17:19',
        'version': '1.0.0',
        'database': db_status,
        'environment': ENVIRONMENT
    }), 200

# API documentation endpoint
@app.route('/api/docs')
def api_docs():
    """Simple API documentation endpoint."""
    endpoints = [
        {'path': '/api/register', 'method': 'POST', 'description': 'Register a new user'},
        {'path': '/api/login', 'method': 'POST', 'description': 'Log in a user'},
        {'path': '/api/check-auth', 'method': 'GET', 'description': 'Check authentication status'},
        {'path': '/api/logout', 'method': 'POST', 'description': 'Log out a user'},
        {'path': '/api/submit-application', 'method': 'POST', 'description': 'Submit a new application'},
        {'path': '/api/get-application', 'method': 'GET', 'description': 'Get current user\'s application'},
        {'path': '/api/get-application/<id>', 'method': 'GET', 'description': 'Get application by ID'},
        {'path': '/api/update-application/<id>', 'method': 'PUT', 'description': 'Update application by ID'},
        {'path': '/api/update-application-status/<id>', 'method': 'PUT', 'description': 'Update application status by ID'},
        {'path': '/api/delete-application/<id>', 'method': 'DELETE', 'description': 'Delete application by ID'},
        {'path': '/api/upload-file', 'method': 'POST', 'description': 'Upload a file'},
        {'path': '/api/files/<id>/download', 'method': 'GET', 'description': 'Download a file'},
        {'path': '/api/files/<id>/view', 'method': 'GET', 'description': 'View a file in browser'},
        {'path': '/api/user/profile', 'method': 'GET', 'description': 'Get user profile'},
        {'path': '/api/get-all-applications', 'method': 'GET', 'description': 'Admin: Get all applications'},
        {'path': '/api/admin/users', 'method': 'GET', 'description': 'Admin: Get all users'},
        {'path': '/api/admin/create-user', 'method': 'POST', 'description': 'Admin: Create a user'},
        {'path': '/api/admin/delete-user/<id>', 'method': 'DELETE', 'description': 'Admin: Delete a user'},
        {'path': '/api/admin/university-report', 'method': 'GET', 'description': 'Admin: Get university report'},
        {'path': '/api/admin/enrollment-statistics', 'method': 'GET', 'description': 'Admin: Get enrollment statistics'},
    ]
    
    return jsonify({
        'api_name': 'PhD Application Tracking API',
        'version': '1.0.0',
        'last_updated': '2025-03-22 17:17:19',
        'maintainer': 'Rishikesh0523',
        'endpoints': endpoints
    }), 200

# Test CORS endpoint
@app.route('/api/test-cors', methods=['GET'])
def test_cors():
    """Test endpoint to verify CORS configuration."""
    return jsonify({
        'message': 'CORS is correctly configured',
        'environment': ENVIRONMENT,
        'timestamp': '2025-03-22 17:17:19',
        'configured_by': 'Rishikesh0523'
    }), 200

# Routes
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    logger.info(f"Registration attempt for email: {data.get('email', 'unknown')}")
    
    # Validate required fields
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Email and password are required'}), 400
    
    # Check if user already exists
    existing_user = User.query.filter_by(email=data['email']).first()
    if existing_user:
        return jsonify({'message': 'Email already registered'}), 400
    
    # Create new user
    new_user = User(
        email=data['email'],
        is_admin=data.get('is_admin', False),
        first_name=data.get('first_name', ''),
        last_name=data.get('last_name', ''),
        contact_number=data.get('contact_number', '')
    )
    new_user.set_password(data['password'])
    
    db.session.add(new_user)
    db.session.commit()
    
    logger.info(f"New user registered: {data.get('email')}")
    
    return jsonify({
        'message': 'User registered successfully',
        'user_id': new_user.id
    }), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Email and password are required'}), 400
    
    user = User.query.filter_by(email=data['email']).first()
    
    if not user or not user.check_password(data['password']):
        logger.warning(f"Failed login attempt for email: {data.get('email')}")
        return jsonify({'message': 'Invalid email or password'}), 401
    
    login_user(user)
    logger.info(f"User logged in: {user.email}")
    
    return jsonify({
        'message': 'Login successful',
        'user_id': user.id,
        'is_admin': user.is_admin
    }), 200

@app.route('/api/check-auth', methods=['GET'])
def check_auth():
    if current_user.is_authenticated:
        return jsonify({
            'authenticated': True,
            'user_id': current_user.id,
            'is_admin': current_user.is_admin
        }), 200
    else:
        return jsonify({
            'authenticated': False
        }), 200

@app.route('/api/logout', methods=['POST'])
def logout():
    if current_user.is_authenticated:
        logger.info(f"User logged out: {current_user.email}")
    logout_user()
    return jsonify({'message': 'Logout successful'}), 200

@app.route('/api/upload-file', methods=['POST'])
@login_required
def upload_file():
    # Check if file part is in the request
    if 'file' not in request.files:
        return jsonify({'message': 'No file part in the request'}), 400
    
    file = request.files['file']
    file_type = request.form.get('type', 'document')
    application_id = request.form.get('applicationId')
    
    # If user didn't select a file
    if file.filename == '':
        return jsonify({'message': 'No file selected'}), 400
    
    # Validate file type
    allowed_extensions = {
        'transcript': ['.pdf', '.doc', '.docx'],
        'cv': ['.pdf', '.doc', '.docx'],
        'photo': ['.jpg', '.jpeg', '.png']
    }
    
    file_extension = get_file_extension(file.filename)
    if file_type in allowed_extensions and file_extension not in allowed_extensions[file_type]:
        return jsonify({
            'message': f'Invalid file type. Allowed types for {file_type}: {", ".join(allowed_extensions[file_type])}'
        }), 400
    
    # Create user directory
    user_dir = create_user_directory(current_user.id)
    
    # Generate a unique filename
    secure_name = secure_filename(file.filename)
    unique_filename = f"{file_type}_{generate_unique_filename(secure_name)}"
    file_path = os.path.join(user_dir, unique_filename)
    
    # Save the file
    file.save(file_path)
    
    # Get file info
    file_size = os.path.getsize(file_path)
    mime_type = get_mime_type(file_path)
    
    # Create file record in database
    new_file = File(
        user_id=current_user.id,
        original_name=secure_name,
        file_path=file_path,
        file_type=file_type,
        mime_type=mime_type,
        file_size=file_size
    )
    
    db.session.add(new_file)
    db.session.commit()
    
    # If this is for an existing application, update the application record
    if application_id:
        application = Application.query.get(application_id)
        if application and application.user_id == current_user.id:
            setattr(application, file_type, new_file.id)
            db.session.commit()
    
    logger.info(f"File uploaded: {file_type} by user {current_user.id}")
    
    return jsonify({
        'message': 'File uploaded successfully',
        'fileId': new_file.id,
        'originalName': new_file.original_name,
        'fileType': new_file.file_type,
        'fileSize': new_file.file_size
    }), 201

@app.route('/api/files/<int:file_id>/download', methods=['GET'])
@login_required
def download_file(file_id):
    file = File.query.get_or_404(file_id)
    
    # Security check - only admin or file owner can download
    if not current_user.is_admin and file.user_id != current_user.id:
        logger.warning(f"Unauthorized file download attempt: file {file_id} by user {current_user.id}")
        return jsonify({'message': 'Unauthorized access'}), 403
    
    # Check if file exists on disk
    if not os.path.exists(file.file_path):
        return jsonify({'message': 'File not found on server'}), 404
    
    logger.info(f"File downloaded: {file_id} by user {current_user.id}")
    
    # Set attachment filename to original name
    return send_file(
        file.file_path,
        as_attachment=True,
        download_name=file.original_name,
        mimetype=file.mime_type
    )

@app.route('/api/files/<int:file_id>/view', methods=['GET'])
@login_required
def view_file(file_id):
    file = File.query.get_or_404(file_id)
    
    # Security check - only admin or file owner can view
    if not current_user.is_admin and file.user_id != current_user.id:
        logger.warning(f"Unauthorized file view attempt: file {file_id} by user {current_user.id}")
        return jsonify({'message': 'Unauthorized access'}), 403
    
    # Check if file exists on disk
    if not os.path.exists(file.file_path):
        return jsonify({'message': 'File not found on server'}), 404
    
    logger.info(f"File viewed: {file_id} by user {current_user.id}")
    
    # Show in browser instead of downloading
    return send_file(
        file.file_path,
        mimetype=file.mime_type
    )

@app.route('/api/submit-application', methods=['POST'])
@login_required
def submit_application():
    data = request.get_json()
    
    # Check if user already has an application
    existing_application = Application.query.filter_by(user_id=current_user.id).first()
    
    if existing_application:
        # Update existing application
        for key, value in data.items():
            if hasattr(existing_application, key):
                setattr(existing_application, key, value)
        
        existing_application.updated_at = datetime.utcnow()
        db.session.commit()
        
        logger.info(f"Application updated: {existing_application.id} by user {current_user.id}")
        
        return jsonify({
            'message': 'Application updated successfully',
            'application_id': existing_application.id
        }), 200
    else:
        # Create new application
        new_application = Application(user_id=current_user.id)
        
        for key, value in data.items():
            if hasattr(new_application, key):
                setattr(new_application, key, value)
        
        db.session.add(new_application)
        db.session.commit()
        
        logger.info(f"New application submitted: {new_application.id} by user {current_user.id}")
        
        return jsonify({
            'message': 'Application submitted successfully',
            'application_id': new_application.id
        }), 201

@app.route('/api/get-application', methods=['GET'])
@login_required
def get_current_user_application():
    application = Application.query.filter_by(user_id=current_user.id).first()
    
    if not application:
        return jsonify({'message': 'No application found for this user'}), 404
    
    return jsonify(application.to_dict()), 200

@app.route('/api/get-application/<int:application_id>', methods=['GET'])
@login_required
def get_application_by_id(application_id):
    application = Application.query.get_or_404(application_id)
    
    # Security check - only admin or application owner can view
    if not current_user.is_admin and application.user_id != current_user.id:
        logger.warning(f"Unauthorized application access attempt: {application_id} by user {current_user.id}")
        return jsonify({'message': 'Unauthorized access'}), 403
    
    return jsonify(application.to_dict()), 200

@app.route('/api/update-application/<int:application_id>', methods=['PUT'])
@login_required
def update_application(application_id):
    application = Application.query.get_or_404(application_id)
    
    # Security check - only admin or application owner can update
    if not current_user.is_admin and application.user_id != current_user.id:
        logger.warning(f"Unauthorized application update attempt: {application_id} by user {current_user.id}")
        return jsonify({'message': 'Unauthorized access'}), 403
    
    data = request.get_json()
    
    # Update application fields
    for key, value in data.items():
        if hasattr(application, key):
            setattr(application, key, value)
    
    application.updated_at = datetime.utcnow()
    db.session.commit()
    
    logger.info(f"Application updated: {application_id} by user {current_user.id}")
    
    return jsonify({
        'message': 'Application updated successfully',
        'application_id': application.id
    }), 200

@app.route('/api/update-application-status/<int:application_id>', methods=['PUT'])
@login_required
def update_application_status(application_id):
    application = Application.query.get_or_404(application_id)
    
    # Security check - only admin or application owner can update
    if not current_user.is_admin and application.user_id != current_user.id:
        logger.warning(f"Unauthorized status update attempt: {application_id} by user {current_user.id}")
        return jsonify({'message': 'Unauthorized access'}), 403
    
    data = request.get_json()
    
    # Update status fields
    status_fields = [
        'enrollment_status', 'target_universities', 'applied_universities',
        'accepted_universities', 'enrolled_university', 'study_program',
        'admission_year', 'scholarship_status'
    ]
    
    for field in status_fields:
        if field in data:
            setattr(application, field, data[field])
    
    application.updated_at = datetime.utcnow()
    db.session.commit()
    
    logger.info(f"Application status updated: {application_id} by user {current_user.id}")
    
    return jsonify({
        'message': 'Application status updated successfully',
        'application_id': application.id
    }), 200

@app.route('/api/delete-application/<int:application_id>', methods=['DELETE'])
@login_required
def delete_application(application_id):
    application = Application.query.get_or_404(application_id)
    
    # Security check - only admin or application owner can delete
    if not current_user.is_admin and application.user_id != current_user.id:
        logger.warning(f"Unauthorized application delete attempt: {application_id} by user {current_user.id}")
        return jsonify({'message': 'Unauthorized access'}), 403
    
    # Delete associated files if they're no longer needed
    for file_type in ['transcript', 'cv', 'photo']:
        file_id = getattr(application, file_type)
        if file_id:
            file = File.query.get(file_id)
            if file:
                # Check if file is used by any other application
                other_usage = False
                for attr in ['transcript', 'cv', 'photo']:
                    if Application.query.filter(
                        Application.id != application_id,
                        getattr(Application, attr) == file_id
                    ).first():
                        other_usage = True
                        break
                
                if not other_usage:
                    # Delete file from disk
                    if os.path.exists(file.file_path):
                        os.remove(file.file_path)
                    
                    # Delete file record
                    db.session.delete(file)
    
    # Delete application
    db.session.delete(application)
    db.session.commit()
    
    logger.info(f"Application deleted: {application_id} by user {current_user.id}")
    
    return jsonify({'message': 'Application deleted successfully'}), 200

@app.route('/api/get-all-applications', methods=['GET'])
@login_required
def get_all_applications():
    # Security check - only admin can view all applications
    if not current_user.is_admin:
        logger.warning(f"Unauthorized access attempt to all applications by user {current_user.id}")
        return jsonify({'message': 'Unauthorized access'}), 403
    
    applications = Application.query.all()
    logger.info(f"All applications retrieved by admin {current_user.id}")
    
    return jsonify([app.to_dict() for app in applications]), 200

@app.route('/api/user/profile', methods=['GET'])
@login_required
def get_user_profile():
    """
    Get the current user's profile information.
    This endpoint returns user details for the currently authenticated user.
    """
    try:
        # Get basic user data from database
        user_data = {
            'id': current_user.id,
            'email': current_user.email,
            'first_name': current_user.first_name,
            'last_name': current_user.last_name,
            'is_admin': current_user.is_admin,
            # Use the information you provided
            'username': 'Rishikesh0523',
            'current_date': '2025-03-22 17:17:19'
        }
        
        return jsonify(user_data), 200
    except Exception as e:
        logger.error(f"Error fetching user profile: {str(e)}")
        return jsonify({'message': 'Failed to retrieve user profile'}), 500

@app.route('/api/admin/users', methods=['GET'])
@login_required
def get_all_users():
    # Security check - only admin can view all users
    if not current_user.is_admin:
        logger.warning(f"Unauthorized access attempt to users list by user {current_user.id}")
        return jsonify({'message': 'Unauthorized access'}), 403
    
    users = User.query.all()
    
    # For each user, check if they have an application
    user_data = []
    for user in users:
        user_dict = user.to_dict()
        application = Application.query.filter_by(user_id=user.id).first()
        user_dict['has_application'] = application is not None
        if application:
            user_dict['application_id'] = application.id
        user_data.append(user_dict)
    
    logger.info(f"All users retrieved by admin {current_user.id}")
    
    return jsonify(user_data), 200

@app.route('/api/admin/create-user', methods=['POST'])
@login_required
def create_user():
    # Security check - only admin can create users
    if not current_user.is_admin:
        logger.warning(f"Unauthorized user creation attempt by user {current_user.id}")
        return jsonify({'message': 'Unauthorized access'}), 403
    
    data = request.get_json()
    
    # Validate required fields
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Email and password are required'}), 400
    
    # Check if user already exists
    existing_user = User.query.filter_by(email=data['email']).first()
    if existing_user:
        return jsonify({'message': 'Email already registered'}), 400
    
    # Create new user
    new_user = User(
        email=data['email'],
        is_admin=data.get('is_admin', False),
        first_name=data.get('first_name', ''),
        last_name=data.get('last_name', ''),
        contact_number=data.get('contact_number', '')
    )
    new_user.set_password(data['password'])
    
    db.session.add(new_user)
    db.session.commit()
    
    logger.info(f"New user created by admin {current_user.id}: {data.get('email')}")
    
    return jsonify({
        'message': 'User created successfully',
        'user_id': new_user.id
    }), 201

@app.route('/api/admin/delete-user/<int:user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    # Security check - only admin can delete users
    if not current_user.is_admin:
        logger.warning(f"Unauthorized user deletion attempt by user {current_user.id}")
        return jsonify({'message': 'Unauthorized access'}), 403
    
    # Cannot delete self
    if user_id == current_user.id:
        return jsonify({'message': 'Cannot delete your own account'}), 400
    
    user = User.query.get_or_404(user_id)
    
    # Delete user's files and directories
    user_dir = os.path.join(app.config['UPLOAD_FOLDER'], str(user_id))
    if os.path.exists(user_dir):
        shutil.rmtree(user_dir)
    
    # User's applications and files will be deleted via cascade
    db.session.delete(user)
    db.session.commit()
    
    logger.info(f"User deleted by admin {current_user.id}: user {user_id}")
    
    return jsonify({'message': 'User deleted successfully'}), 200

@app.route('/api/admin/university-report', methods=['GET'])
@login_required
def get_university_report():
    # Security check - only admin can access reports
    if not current_user.is_admin:
        logger.warning(f"Unauthorized report access attempt by user {current_user.id}")
        return jsonify({'message': 'Unauthorized access'}), 403
    
    # Get enrolled students grouped by university
    enrolled_data = db.session.query(
        Application.enrolled_university,
        db.func.count(Application.id).label('count')
    ).filter(
        Application.enrollment_status == 'enrolled',
        Application.enrolled_university != None,
        Application.enrolled_university != ''
    ).group_by(Application.enrolled_university).all()
    
    # Format report data
    university_report = [
        {
            'university': item[0],
            'student_count': item[1]
        } for item in enrolled_data
    ]
    
    logger.info(f"University report generated by admin {current_user.id}")
    
    return jsonify({
        'report_date': '2025-03-22 17:17:19',
        'total_enrolled': sum(item['student_count'] for item in university_report),
        'universities': university_report,
        'generated_by': 'Rishikesh0523'
    }), 200

@app.route('/api/admin/enrollment-statistics', methods=['GET'])
@login_required
def get_enrollment_statistics():
    # Security check - only admin can access statistics
    if not current_user.is_admin:
        logger.warning(f"Unauthorized statistics access attempt by user {current_user.id}")
        return jsonify({'message': 'Unauthorized access'}), 403
    
    # Count applications by enrollment status
    status_counts = {}
    for status in ['planning', 'applied', 'accepted', 'enrolled']:
        count = Application.query.filter_by(enrollment_status=status).count()
        status_counts[status] = count
    
    # Count application with no enrollment status (legacy data)
    none_count = Application.query.filter(
        (Application.enrollment_status == None) | 
        (Application.enrollment_status == '')
    ).count()
    
    if none_count > 0:
        status_counts['none'] = none_count
    
    # Get total applications
    total_applications = Application.query.count()
    
    logger.info(f"Enrollment statistics generated by admin {current_user.id}")
    
    return jsonify({
        'report_date': '2025-03-22 17:17:19',
        'total_applications': total_applications,
        'status_counts': status_counts,
        'generated_by': 'Rishikesh0523'
    }), 200

# Error handlers
@app.errorhandler(404)
def not_found(error):
    logger.warning(f"404 error: {request.path}")
    return jsonify({'message': 'Resource not found'}), 404

@app.errorhandler(500)
def server_error(error):
    logger.error(f"500 error: {str(error)}")
    return jsonify({'message': 'Internal server error'}), 500

@app.errorhandler(403)
def forbidden(error):
    logger.warning(f"403 error: {request.path}")
    return jsonify({'message': 'Forbidden: you do not have permission to access this resource'}), 403

if __name__ == '__main__':
    # Check if running in production
    if ENVIRONMENT == 'production':
        # Use production server settings
        port = int(os.environ.get('PORT', 5000))
        app.run(host='0.0.0.0', port=port, debug=False)
        logger.info(f"Starting production server on port {port}")
    else:
        # Use development server settings
        app.run(debug=True)
        logger.info("Starting development server with debug mode")