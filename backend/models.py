from flask_pymongo import PyMongo
from pymongo import IndexModel, ASCENDING
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from bson.objectid import ObjectId
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize PyMongo (will be configured with the app later)
mongo = PyMongo()


class User(UserMixin):
    """User model for MongoDB"""
    
    def __init__(self, user_data=None):
        self._id = None
        self.email = None
        self.password = None
        self.is_admin = False
        self.first_name = None
        self.last_name = None
        self.contact_number = None
        self.created_at = datetime.utcnow()
        
        if user_data:
            self._id = user_data.get('_id')
            self.email = user_data.get('email')
            self.password = user_data.get('password')
            self.is_admin = user_data.get('is_admin', False)
            self.first_name = user_data.get('first_name')
            self.last_name = user_data.get('last_name')
            self.contact_number = user_data.get('contact_number')
            self.created_at = user_data.get('created_at', datetime.utcnow())
    
    def get_id(self):
        return str(self._id) if self._id else None
    
    @property
    def id(self):
        return str(self._id) if self._id else None
    
    def set_password(self, password):
        self.password = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password, password)
    
    def save(self):
        if not self._id:
            # Insert new user
            result = mongo.db.users.insert_one({
                'email': self.email,
                'password': self.password,
                'is_admin': self.is_admin,
                'first_name': self.first_name,
                'last_name': self.last_name,
                'contact_number': self.contact_number,
                'created_at': self.created_at
            })
            self._id = result.inserted_id
        else:
            # Update existing user
            mongo.db.users.update_one(
                {'_id': self._id},
                {'$set': {
                    'email': self.email,
                    'password': self.password,
                    'is_admin': self.is_admin,
                    'first_name': self.first_name,
                    'last_name': self.last_name,
                    'contact_number': self.contact_number
                }}
            )
        return self
    
    @classmethod
    def find_by_id(cls, user_id):
        try:
            user_data = mongo.db.users.find_one({'_id': ObjectId(user_id)})
            return cls(user_data) if user_data else None
        except:
            return None
    
    @classmethod
    def find_by_email(cls, email):
        user_data = mongo.db.users.find_one({'email': email})
        return cls(user_data) if user_data else None
    
    @classmethod
    def get_all(cls):
        users = list(mongo.db.users.find())
        return [cls(user) for user in users]
    
    def delete(self):
        if self._id:
            # Delete applications associated with this user
            mongo.db.applications.delete_many({'user_id': str(self._id)})
            
            # Delete files associated with this user
            mongo.db.files.delete_many({'user_id': str(self._id)})
            
            # Delete the user
            mongo.db.users.delete_one({'_id': self._id})
            return True
        return False
    
    def to_dict(self):
        return {
            'id': str(self._id),
            'email': self.email,
            'is_admin': self.is_admin,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'contact_number': self.contact_number,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S') if self.created_at else None
        }


class Application:
    """Application model for MongoDB"""
    
    def __init__(self, app_data=None):
        self._id = None
        self.user_id = None
        
        # Personal Details
        self.first_name = None
        self.middle_name = None
        self.last_name = None
        self.contact_number = None
        self.gender = None
        self.email = None
        
        # Academic Details
        self.final_percentage = None
        self.tentative_ranking = None
        self.final_year_project = None
        self.other_projects = None
        self.publications = None
        
        # University Status Fields
        self.target_universities = None
        self.applied_universities = None
        self.accepted_universities = None
        self.enrolled_university = None
        self.enrollment_status = 'planning'
        self.study_program = None
        self.admission_year = None
        self.scholarship_status = None
        
        # Additional Information
        self.extracurricular = None
        self.professional_experience = None
        self.strong_points = None
        self.weak_points = None
        
        # File Uploads
        self.transcript = None
        self.cv = None
        self.photo = None
        
        # Additional Fields
        self.preferred_programs = None
        self.references = None
        self.statement_of_purpose = None
        self.intended_research_areas = None
        self.english_proficiency = None
        self.leadership_experience = None
        self.availability_to_start = None
        self.additional_certifications = None
        
        # Timestamps
        self.created_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()
        
        if app_data:
            self._id = app_data.get('_id')
            self.user_id = app_data.get('user_id')
            
            # Personal Details
            self.first_name = app_data.get('first_name')
            self.middle_name = app_data.get('middle_name')
            self.last_name = app_data.get('last_name')
            self.contact_number = app_data.get('contact_number')
            self.gender = app_data.get('gender')
            self.email = app_data.get('email')
            
            # Academic Details
            self.final_percentage = app_data.get('final_percentage')
            self.tentative_ranking = app_data.get('tentative_ranking')
            self.final_year_project = app_data.get('final_year_project')
            self.other_projects = app_data.get('other_projects')
            self.publications = app_data.get('publications')
            
            # University Status Fields
            self.target_universities = app_data.get('target_universities')
            self.applied_universities = app_data.get('applied_universities')
            self.accepted_universities = app_data.get('accepted_universities')
            self.enrolled_university = app_data.get('enrolled_university')
            self.enrollment_status = app_data.get('enrollment_status', 'planning')
            self.study_program = app_data.get('study_program')
            self.admission_year = app_data.get('admission_year')
            self.scholarship_status = app_data.get('scholarship_status')
            
            # Additional Information
            self.extracurricular = app_data.get('extracurricular')
            self.professional_experience = app_data.get('professional_experience')
            self.strong_points = app_data.get('strong_points')
            self.weak_points = app_data.get('weak_points')
            
            # File Uploads
            self.transcript = app_data.get('transcript')
            self.cv = app_data.get('cv')
            self.photo = app_data.get('photo')
            
            # Additional Fields
            self.preferred_programs = app_data.get('preferred_programs')
            self.references = app_data.get('references')
            self.statement_of_purpose = app_data.get('statement_of_purpose')
            self.intended_research_areas = app_data.get('intended_research_areas')
            self.english_proficiency = app_data.get('english_proficiency')
            self.leadership_experience = app_data.get('leadership_experience')
            self.availability_to_start = app_data.get('availability_to_start')
            self.additional_certifications = app_data.get('additional_certifications')
            
            # Timestamps
            self.created_at = app_data.get('created_at', datetime.utcnow())
            self.updated_at = app_data.get('updated_at', datetime.utcnow())
    
    @property
    def id(self):
        return str(self._id) if self._id else None
    
    def save(self):
        app_data = {
            'user_id': self.user_id,
            
            # Personal Details
            'first_name': self.first_name,
            'middle_name': self.middle_name,
            'last_name': self.last_name,
            'contact_number': self.contact_number,
            'gender': self.gender,
            'email': self.email,
            
            # Academic Details
            'final_percentage': self.final_percentage,
            'tentative_ranking': self.tentative_ranking,
            'final_year_project': self.final_year_project,
            'other_projects': self.other_projects,
            'publications': self.publications,
            
            # University Status Fields
            'target_universities': self.target_universities,
            'applied_universities': self.applied_universities,
            'accepted_universities': self.accepted_universities,
            'enrolled_university': self.enrolled_university,
            'enrollment_status': self.enrollment_status,
            'study_program': self.study_program,
            'admission_year': self.admission_year,
            'scholarship_status': self.scholarship_status,
            
            # Additional Information
            'extracurricular': self.extracurricular,
            'professional_experience': self.professional_experience,
            'strong_points': self.strong_points,
            'weak_points': self.weak_points,
            
            # File Uploads
            'transcript': self.transcript,
            'cv': self.cv,
            'photo': self.photo,
            
            # Additional Fields
            'preferred_programs': self.preferred_programs,
            'references': self.references,
            'statement_of_purpose': self.statement_of_purpose,
            'intended_research_areas': self.intended_research_areas,
            'english_proficiency': self.english_proficiency,
            'leadership_experience': self.leadership_experience,
            'availability_to_start': self.availability_to_start,
            'additional_certifications': self.additional_certifications,
            
            # Update the updated_at timestamp
            'updated_at': datetime.utcnow()
        }
        
        if not self._id:
            # Add created_at for new applications
            app_data['created_at'] = datetime.utcnow()
            
            # Insert new application
            result = mongo.db.applications.insert_one(app_data)
            self._id = result.inserted_id
        else:
            # Update existing application
            mongo.db.applications.update_one(
                {'_id': self._id},
                {'$set': app_data}
            )
        
        return self
    
    @classmethod
    def find_by_id(cls, app_id):
        try:
            app_data = mongo.db.applications.find_one({'_id': ObjectId(app_id)})
            return cls(app_data) if app_data else None
        except:
            return None
    
    @classmethod
    def find_by_user_id(cls, user_id):
        app_data = mongo.db.applications.find_one({'user_id': user_id})
        return cls(app_data) if app_data else None
    
    @classmethod
    def get_all(cls):
        applications = list(mongo.db.applications.find())
        return [cls(app) for app in applications]
    
    @classmethod
    def get_by_enrollment_status(cls, status):
        """Get applications filtered by enrollment status"""
        applications = list(mongo.db.applications.find({'enrollment_status': status}))
        return [cls(app) for app in applications]
    
    @classmethod
    def count_by_enrollment_status(cls, status=None):
        """Count applications by enrollment status"""
        if status:
            return mongo.db.applications.count_documents({'enrollment_status': status})
        else:
            return mongo.db.applications.count_documents({})
    
    @classmethod
    def get_enrollment_statistics(cls):
        """Get enrollment statistics for administrative reports"""
        pipeline = [
            {
                '$group': {
                    '_id': '$enrollment_status', 
                    'count': {'$sum': 1}
                }
            }
        ]
        stats = list(mongo.db.applications.aggregate(pipeline))
        return {item['_id'] or 'none': item['count'] for item in stats}
        
    @classmethod
    def get_university_statistics(cls):
        """Get statistics on enrolled universities"""
        pipeline = [
            {
                '$match': {
                    'enrollment_status': 'enrolled',
                    'enrolled_university': {'$exists': True, '$ne': None, '$ne': ''}
                }
            },
            {
                '$group': {
                    '_id': '$enrolled_university',
                    'count': {'$sum': 1}
                }
            }
        ]
        stats = list(mongo.db.applications.aggregate(pipeline))
        return [{'university': item['_id'], 'student_count': item['count']} for item in stats]
    
    def delete(self):
        if self._id:
            mongo.db.applications.delete_one({'_id': self._id})
            return True
        return False
    
    def to_dict(self):
        return {
            'id': str(self._id),
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
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S') if self.created_at else None,
            'updated_at': self.updated_at.strftime('%Y-%m-%d %H:%M:%S') if self.updated_at else None
        }


class File:
    """File model for MongoDB"""
    
    def __init__(self, file_data=None):
        self._id = None
        self.user_id = None
        self.original_name = None
        self.file_path = None
        self.file_type = None
        self.mime_type = None
        self.file_size = None
        self.upload_date = datetime.utcnow()
        
        if file_data:
            self._id = file_data.get('_id')
            self.user_id = file_data.get('user_id')
            self.original_name = file_data.get('original_name')
            self.file_path = file_data.get('file_path')
            self.file_type = file_data.get('file_type')
            self.mime_type = file_data.get('mime_type')
            self.file_size = file_data.get('file_size')
            self.upload_date = file_data.get('upload_date', datetime.utcnow())
    
    @property
    def id(self):
        return str(self._id) if self._id else None
    
    def save(self):
        file_data = {
            'user_id': self.user_id,
            'original_name': self.original_name,
            'file_path': self.file_path,
            'file_type': self.file_type,
            'mime_type': self.mime_type,
            'file_size': self.file_size,
            'upload_date': self.upload_date
        }
        
        if not self._id:
            result = mongo.db.files.insert_one(file_data)
            self._id = result.inserted_id
        else:
            mongo.db.files.update_one(
                {'_id': self._id},
                {'$set': file_data}
            )
        
        return self
    
    @classmethod
    def find_by_id(cls, file_id):
        try:
            file_data = mongo.db.files.find_one({'_id': ObjectId(file_id)})
            return cls(file_data) if file_data else None
        except:
            return None
    
    def delete(self):
        if self._id:
            mongo.db.files.delete_one({'_id': self._id})
            return True
        return False
    
    def to_dict(self):
        return {
            'id': str(self._id),
            'user_id': self.user_id,
            'original_name': self.original_name,
            'file_type': self.file_type,
            'mime_type': self.mime_type,
            'file_size': self.file_size,
            'upload_date': self.upload_date.strftime('%Y-%m-%d %H:%M:%S') if self.upload_date else None
        }


def init_db(app):
    """Initialize database with indexes"""
    with app.app_context():
        # Create indexes for users collection
        mongo.db.users.create_index('email', unique=True)
        
        # Create indexes for applications collection
        mongo.db.applications.create_index('user_id')
        mongo.db.applications.create_index('enrollment_status')
        
        # Create indexes for files collection
        mongo.db.files.create_index('user_id')
        
        # Create default admin user if no users exist
        if mongo.db.users.count_documents({}) == 0:
            admin = User({
                'email': 'admin@example.com',
                'is_admin': True,
                'first_name': 'Admin',
                'last_name': 'User',
                'created_at': datetime.utcnow()
            })
            admin.set_password('admin123')
            admin.save()
            print("Default admin user created with email: admin@example.com and password: admin123")