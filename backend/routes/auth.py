"""
Authentication routes
"""
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import (
    create_access_token, create_refresh_token, jwt_required, 
    get_jwt_identity, get_jwt, verify_jwt_in_request
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from marshmallow import Schema, fields, ValidationError
from email_validator import validate_email, EmailNotValidError
import bcrypt
import re
from datetime import datetime, timedelta
import redis

from models import db, User, UserActivity
from services.auth_service import AuthService
from utils.decorators import validate_json
from utils.helpers import generate_reset_token, send_reset_email

auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')

# Initialize rate limiter
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Redis client for token blacklist
redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)

# Validation schemas
class RegisterSchema(Schema):
    username = fields.Str(required=True, validate=lambda x: len(x) >= 3)
    email = fields.Email(required=True)
    password = fields.Str(required=True, validate=lambda x: len(x) >= 8)
    first_name = fields.Str(required=True)
    last_name = fields.Str(required=True)

class LoginSchema(Schema):
    email = fields.Email(required=True)
    password = fields.Str(required=True)

class ResetPasswordSchema(Schema):
    email = fields.Email(required=True)

class ConfirmResetSchema(Schema):
    token = fields.Str(required=True)
    new_password = fields.Str(required=True, validate=lambda x: len(x) >= 8)

# Initialize auth service
auth_service = AuthService()

@auth_bp.route('/register', methods=['POST'])
@limiter.limit("5 per minute")
@validate_json(RegisterSchema)
def register():
    """Register a new user"""
    try:
        data = request.get_json()
        
        # Validate password strength
        if not auth_service.validate_password_strength(data['password']):
            return jsonify({
                'error': 'Password must contain at least 8 characters, including uppercase, lowercase, numbers, and special characters'
            }), 400
        
        # Check if user already exists
        if User.query.filter_by(email=data['email']).first():
            return jsonify({'error': 'Email already registered'}), 409
        
        if User.query.filter_by(username=data['username']).first():
            return jsonify({'error': 'Username already taken'}), 409
        
        # Create new user
        user = auth_service.create_user(
            username=data['username'],
            email=data['email'],
            password=data['password'],
            first_name=data['first_name'],
            last_name=data['last_name']
        )
        
        # Generate tokens
        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)
        
        # Log user activity
        activity = UserActivity(
            user_id=user.id,
            activity_type='register',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', ''),
            timestamp=datetime.utcnow()
        )
        db.session.add(activity)
        db.session.commit()
        
        return jsonify({
            'message': 'User registered successfully',
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'skill_level': user.skill_level,
                'created_at': user.created_at.isoformat()
            },
            'access_token': access_token,
            'refresh_token': refresh_token
        }), 201
        
    except ValidationError as e:
        return jsonify({'error': 'Validation error', 'details': e.messages}), 400
    except Exception as e:
        current_app.logger.error(f"Registration error: {str(e)}")
        return jsonify({'error': 'Registration failed'}), 500

@auth_bp.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
@validate_json(LoginSchema)
def login():
    """Login user"""
    try:
        data = request.get_json()
        
        # Find user by email
        user = User.query.filter_by(email=data['email']).first()
        
        if not user or not auth_service.verify_password(data['password'], user.password_hash):
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Check if account is active
        if not user.is_active:
            return jsonify({'error': 'Account is deactivated'}), 401
        
        # Update last login
        user.last_login = datetime.utcnow()
        db.session.commit()
        
        # Generate tokens
        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)
        
        # Log user activity
        activity = UserActivity(
            user_id=user.id,
            activity_type='login',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', ''),
            timestamp=datetime.utcnow()
        )
        db.session.add(activity)
        db.session.commit()
        
        return jsonify({
            'message': 'Login successful',
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'skill_level': user.skill_level,
                'last_login': user.last_login.isoformat() if user.last_login else None
            },
            'access_token': access_token,
            'refresh_token': refresh_token
        }), 200
        
    except ValidationError as e:
        return jsonify({'error': 'Validation error', 'details': e.messages}), 400
    except Exception as e:
        current_app.logger.error(f"Login error: {str(e)}")
        return jsonify({'error': 'Login failed'}), 500

@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """Refresh access token"""
    try:
        current_user_id = get_jwt_identity()
        
        # Check if refresh token is blacklisted
        jti = get_jwt()['jti']
        if redis_client.get(f"blacklist:{jti}"):
            return jsonify({'error': 'Token has been revoked'}), 401
        
        # Generate new access token
        new_access_token = create_access_token(identity=current_user_id)
        
        return jsonify({
            'access_token': new_access_token
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Token refresh error: {str(e)}")
        return jsonify({'error': 'Token refresh failed'}), 500

@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    """Logout user and blacklist token"""
    try:
        # Get current token
        jti = get_jwt()['jti']
        
        # Add token to blacklist
        redis_client.set(f"blacklist:{jti}", "true", ex=timedelta(hours=24))
        
        # Log user activity
        current_user_id = get_jwt_identity()
        activity = UserActivity(
            user_id=current_user_id,
            activity_type='logout',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', ''),
            timestamp=datetime.utcnow()
        )
        db.session.add(activity)
        db.session.commit()
        
        return jsonify({'message': 'Logout successful'}), 200
        
    except Exception as e:
        current_app.logger.error(f"Logout error: {str(e)}")
        return jsonify({'error': 'Logout failed'}), 500

@auth_bp.route('/profile', methods=['GET'])
@jwt_required()
def get_profile():
    """Get current user profile"""
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'skill_level': user.skill_level,
                'preferences': user.preferences,
                'created_at': user.created_at.isoformat(),
                'last_login': user.last_login.isoformat() if user.last_login else None
            }
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Profile fetch error: {str(e)}")
        return jsonify({'error': 'Failed to fetch profile'}), 500

@auth_bp.route('/profile', methods=['PUT'])
@jwt_required()
def update_profile():
    """Update user profile"""
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        data = request.get_json()
        
        # Update allowed fields
        if 'first_name' in data:
            user.first_name = data['first_name']
        if 'last_name' in data:
            user.last_name = data['last_name']
        if 'skill_level' in data:
            user.skill_level = data['skill_level']
        if 'preferences' in data:
            user.preferences = data['preferences']
        
        db.session.commit()
        
        return jsonify({
            'message': 'Profile updated successfully',
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'skill_level': user.skill_level,
                'preferences': user.preferences
            }
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Profile update error: {str(e)}")
        return jsonify({'error': 'Failed to update profile'}), 500

@auth_bp.route('/reset-password', methods=['POST'])
@limiter.limit("3 per minute")
@validate_json(ResetPasswordSchema)
def reset_password():
    """Request password reset"""
    try:
        data = request.get_json()
        user = User.query.filter_by(email=data['email']).first()
        
        if user:
            # Generate reset token
            reset_token = generate_reset_token()
            user.reset_token = reset_token
            user.reset_token_expires = datetime.utcnow() + timedelta(hours=1)
            db.session.commit()
            
            # Send reset email (implement email service)
            send_reset_email(user.email, reset_token)
        
        # Always return success to prevent email enumeration
        return jsonify({'message': 'Password reset email sent if account exists'}), 200
        
    except Exception as e:
        current_app.logger.error(f"Password reset error: {str(e)}")
        return jsonify({'error': 'Password reset failed'}), 500

@auth_bp.route('/reset-password/confirm', methods=['POST'])
@limiter.limit("5 per minute")
@validate_json(ConfirmResetSchema)
def confirm_reset_password():
    """Confirm password reset"""
    try:
        data = request.get_json()
        
        user = User.query.filter_by(reset_token=data['token']).first()
        
        if not user or not user.reset_token_expires or user.reset_token_expires < datetime.utcnow():
            return jsonify({'error': 'Invalid or expired reset token'}), 400
        
        # Validate new password
        if not auth_service.validate_password_strength(data['new_password']):
            return jsonify({
                'error': 'Password must contain at least 8 characters, including uppercase, lowercase, numbers, and special characters'
            }), 400
        
        # Update password
        user.password_hash = auth_service.hash_password(data['new_password'])
        user.reset_token = None
        user.reset_token_expires = None
        db.session.commit()
        
        return jsonify({'message': 'Password reset successfully'}), 200
        
    except Exception as e:
        current_app.logger.error(f"Password reset confirmation error: {str(e)}")
        return jsonify({'error': 'Password reset confirmation failed'}), 500

@auth_bp.route('/change-password', methods=['POST'])
@jwt_required()
def change_password():
    """Change user password"""
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        data = request.get_json()
        
        # Verify current password
        if not auth_service.verify_password(data['current_password'], user.password_hash):
            return jsonify({'error': 'Current password is incorrect'}), 400
        
        # Validate new password
        if not auth_service.validate_password_strength(data['new_password']):
            return jsonify({
                'error': 'Password must contain at least 8 characters, including uppercase, lowercase, numbers, and special characters'
            }), 400
        
        # Update password
        user.password_hash = auth_service.hash_password(data['new_password'])
        db.session.commit()
        
        return jsonify({'message': 'Password changed successfully'}), 200
        
    except Exception as e:
        current_app.logger.error(f"Password change error: {str(e)}")
        return jsonify({'error': 'Password change failed'}), 500

@auth_bp.route('/activity', methods=['GET'])
@jwt_required()
def get_user_activity():
    """Get user activity log"""
    try:
        current_user_id = get_jwt_identity()
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        
        activities = UserActivity.query.filter_by(user_id=current_user_id)\
            .order_by(UserActivity.timestamp.desc())\
            .paginate(page=page, per_page=per_page, error_out=False)
        
        return jsonify({
            'activities': [{
                'id': activity.id,
                'activity_type': activity.activity_type,
                'ip_address': activity.ip_address,
                'user_agent': activity.user_agent,
                'timestamp': activity.timestamp.isoformat()
            } for activity in activities.items],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': activities.total,
                'pages': activities.pages
            }
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Activity fetch error: {str(e)}")
        return jsonify({'error': 'Failed to fetch activity'}), 500

# Token blacklist checker
@auth_bp.before_app_request
def check_if_token_revoked():
    """Check if JWT token is blacklisted"""
    try:
        verify_jwt_in_request(optional=True)
        jti = get_jwt().get('jti') if get_jwt() else None
        
        if jti and redis_client.get(f"blacklist:{jti}"):
            return jsonify({'error': 'Token has been revoked'}), 401
            
    except Exception:
        pass  # Token validation handled by JWT decorator