from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

db = SQLAlchemy()

class User(db.Model, UserMixin):  # Added UserMixin for flask-login
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    contact_number = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    applications = db.relationship('Application', backref='user', lazy=True, cascade="all, delete-orphan")
    files = db.relationship('File', backref='user', lazy=True, cascade="all, delete-orphan")
    
    def set_password(self, password):
        self.password = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password, password)
    
    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'is_admin': self.is_admin,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'contact_number': self.contact_number,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }

class Application(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Personal Details
    first_name = db.Column(db.String(100))
    middle_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    contact_number = db.Column(db.String(20))
    gender = db.Column(db.String(10))
    email = db.Column(db.String(120))
    
    # Academic Details
    final_percentage = db.Column(db.Float)
    tentative_ranking = db.Column(db.String(20))
    final_year_project = db.Column(db.Text)
    other_projects = db.Column(db.Text)
    publications = db.Column(db.Text)
    
    # University Status Fields (new)
    target_universities = db.Column(db.Text)
    applied_universities = db.Column(db.Text)
    accepted_universities = db.Column(db.Text)
    enrolled_university = db.Column(db.String(200))
    enrollment_status = db.Column(db.String(50), default='planning')  # 'planning', 'applied', 'accepted', 'enrolled'
    study_program = db.Column(db.String(200))
    admission_year = db.Column(db.Integer)
    scholarship_status = db.Column(db.String(50))
    
    # Additional Information
    extracurricular = db.Column(db.Text)
    professional_experience = db.Column(db.Text)
    strong_points = db.Column(db.Text)
    weak_points = db.Column(db.Text)
    
    # File Uploads (store file IDs instead of paths)
    transcript = db.Column(db.Integer, db.ForeignKey('file.id', ondelete='SET NULL'), nullable=True)
    cv = db.Column(db.Integer, db.ForeignKey('file.id', ondelete='SET NULL'), nullable=True)
    photo = db.Column(db.Integer, db.ForeignKey('file.id', ondelete='SET NULL'), nullable=True)
    
    # Additional Fields
    preferred_programs = db.Column(db.Text)
    references = db.Column(db.Text)
    statement_of_purpose = db.Column(db.Text)
    intended_research_areas = db.Column(db.Text)
    english_proficiency = db.Column(db.String(50))
    leadership_experience = db.Column(db.Text)
    availability_to_start = db.Column(db.String(50))
    additional_certifications = db.Column(db.Text)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'first_name': self.first_name,
            'middle_name': self.middle_name,
            'last_name': self.last_name,
            'contact_number': self.contact_number,
            'gender': self.gender,
            'email': self.email,
            'final_percentage': self.final_percentage,
            'tentative_ranking': self.tentative_ranking,
            'final_year_project': self.final_year_project,
            'other_projects': self.other_projects,
            'publications': self.publications,
            'target_universities': self.target_universities,
            'applied_universities': self.applied_universities,
            'accepted_universities': self.accepted_universities,
            'enrolled_university': self.enrolled_university,
            'enrollment_status': self.enrollment_status,
            'study_program': self.study_program,
            'admission_year': self.admission_year,
            'scholarship_status': self.scholarship_status,
            'extracurricular': self.extracurricular,
            'professional_experience': self.professional_experience,
            'strong_points': self.strong_points,
            'weak_points': self.weak_points,
            'transcript': self.transcript,
            'cv': self.cv,
            'photo': self.photo,
            'preferred_programs': self.preferred_programs,
            'references': self.references,
            'statement_of_purpose': self.statement_of_purpose,
            'intended_research_areas': self.intended_research_areas,
            'english_proficiency': self.english_proficiency,
            'leadership_experience': self.leadership_experience,
            'availability_to_start': self.availability_to_start,
            'additional_certifications': self.additional_certifications,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'updated_at': self.updated_at.strftime('%Y-%m-%d %H:%M:%S')
        }

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    original_name = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    file_type = db.Column(db.String(50), nullable=False)  # 'transcript', 'cv', 'photo', etc.
    mime_type = db.Column(db.String(100))
    file_size = db.Column(db.Integer)  # Size in bytes
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'original_name': self.original_name,
            'file_type': self.file_type,
            'mime_type': self.mime_type,
            'file_size': self.file_size,
            'upload_date': self.upload_date.strftime('%Y-%m-%d %H:%M:%S')
        }