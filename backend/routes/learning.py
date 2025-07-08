from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from models import User, LearningModule, UserProgress, db
from services.learning_service import LearningService
from utils.decorators import handle_errors
import logging

learning_bp = Blueprint('learning', __name__)
learning_service = LearningService()

@learning_bp.route('/modules', methods=['GET'])
@handle_errors
def get_learning_modules():
    """Get all learning modules with optional filtering"""
    try:
        difficulty = request.args.get('difficulty')
        category = request.args.get('category')
        
        query = LearningModule.query
        
        if difficulty:
            query = query.filter(LearningModule.difficulty == difficulty)
        if category:
            query = query.filter(LearningModule.category == category)
            
        modules = query.all()
        
        return jsonify({
            'success': True,
            'modules': [{
                'id': module.id,
                'title': module.title,
                'description': module.description,
                'difficulty': module.difficulty,
                'category': module.category,
                'estimated_time': module.estimated_time,
                'prerequisites': module.prerequisites,
                'learning_objectives': module.learning_objectives,
                'created_at': module.created_at.isoformat()
            } for module in modules]
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Error fetching learning modules: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to fetch learning modules'}), 500

@learning_bp.route('/modules/<int:module_id>', methods=['GET'])
@handle_errors
def get_learning_module(module_id):
    """Get specific learning module details"""
    try:
        module = LearningModule.query.get_or_404(module_id)
        
        return jsonify({
            'success': True,
            'module': {
                'id': module.id,
                'title': module.title,
                'description': module.description,
                'difficulty': module.difficulty,
                'category': module.category,
                'estimated_time': module.estimated_time,
                'prerequisites': module.prerequisites,
                'learning_objectives': module.learning_objectives,
                'content': module.content,
                'exercises': module.exercises,
                'created_at': module.created_at.isoformat()
            }
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Error fetching learning module {module_id}: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to fetch learning module'}), 500

@learning_bp.route('/modules/<int:module_id>/progress', methods=['GET'])
@jwt_required()
@handle_errors
def get_user_progress(module_id):
    """Get user progress for a specific module"""
    try:
        user_id = get_jwt_identity()
        progress = UserProgress.query.filter_by(
            user_id=user_id,
            module_id=module_id
        ).first()
        
        if not progress:
            return jsonify({
                'success': True,
                'progress': {
                    'completion_percentage': 0,
                    'status': 'not_started',
                    'completed_exercises': [],
                    'last_accessed': None
                }
            }), 200
            
        return jsonify({
            'success': True,
            'progress': {
                'completion_percentage': progress.completion_percentage,
                'status': progress.status,
                'completed_exercises': progress.completed_exercises,
                'last_accessed': progress.last_accessed.isoformat() if progress.last_accessed else None,
                'time_spent': progress.time_spent
            }
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Error fetching user progress: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to fetch user progress'}), 500

@learning_bp.route('/modules/<int:module_id>/progress', methods=['POST'])
@jwt_required()
@handle_errors
def update_user_progress(module_id):
    """Update user progress for a specific module"""
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        
        # Validate input
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
            
        progress = UserProgress.query.filter_by(
            user_id=user_id,
            module_id=module_id
        ).first()
        
        if not progress:
            # Create new progress record
            progress = UserProgress(
                user_id=user_id,
                module_id=module_id,
                completion_percentage=data.get('completion_percentage', 0),
                status=data.get('status', 'in_progress'),
                completed_exercises=data.get('completed_exercises', []),
                time_spent=data.get('time_spent', 0)
            )
            db.session.add(progress)
        else:
            # Update existing progress
            if 'completion_percentage' in data:
                progress.completion_percentage = data['completion_percentage']
            if 'status' in data:
                progress.status = data['status']
            if 'completed_exercises' in data:
                progress.completed_exercises = data['completed_exercises']
            if 'time_spent' in data:
                progress.time_spent = data['time_spent']
                
        progress.last_accessed = db.func.now()
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Progress updated successfully',
            'progress': {
                'completion_percentage': progress.completion_percentage,
                'status': progress.status,
                'completed_exercises': progress.completed_exercises,
                'last_accessed': progress.last_accessed.isoformat(),
                'time_spent': progress.time_spent
            }
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Error updating user progress: {str(e)}")
        db.session.rollback()
        return jsonify({'success': False, 'error': 'Failed to update progress'}), 500

@learning_bp.route('/modules/<int:module_id>/complete', methods=['POST'])
@jwt_required()
@handle_errors
def complete_module(module_id):
    """Mark a module as completed"""
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        
        # Get or create progress record
        progress = UserProgress.query.filter_by(
            user_id=user_id,
            module_id=module_id
        ).first()
        
        if not progress:
            progress = UserProgress(
                user_id=user_id,
                module_id=module_id
            )
            db.session.add(progress)
        
        # Mark as completed
        progress.completion_percentage = 100
        progress.status = 'completed'
        progress.completed_at = db.func.now()
        progress.last_accessed = db.func.now()
        
        # Add final score if provided
        if 'final_score' in data:
            progress.final_score = data['final_score']
            
        db.session.commit()
        
        # Update user's overall progress
        user = User.query.get(user_id)
        completed_modules = UserProgress.query.filter_by(
            user_id=user_id,
            status='completed'
        ).count()
        
        total_modules = LearningModule.query.count()
        user.learning_streak = user.learning_streak + 1 if user.learning_streak else 1
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Module completed successfully',
            'progress': {
                'completion_percentage': 100,
                'status': 'completed',
                'completed_at': progress.completed_at.isoformat(),
                'final_score': progress.final_score
            },
            'user_stats': {
                'completed_modules': completed_modules,
                'total_modules': total_modules,
                'learning_streak': user.learning_streak
            }
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Error completing module: {str(e)}")
        db.session.rollback()
        return jsonify({'success': False, 'error': 'Failed to complete module'}), 500

@learning_bp.route('/dashboard', methods=['GET'])
@jwt_required()
@handle_errors
def get_learning_dashboard():
    """Get user's learning dashboard with progress overview"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        # Get user's progress across all modules
        progress_records = UserProgress.query.filter_by(user_id=user_id).all()
        
        # Calculate statistics
        total_modules = LearningModule.query.count()
        completed_modules = len([p for p in progress_records if p.status == 'completed'])
        in_progress_modules = len([p for p in progress_records if p.status == 'in_progress'])
        
        # Get recent activity
        recent_progress = UserProgress.query.filter_by(user_id=user_id)\
            .order_by(UserProgress.last_accessed.desc())\
            .limit(5)\
            .all()
        
        # Calculate total time spent
        total_time_spent = sum(p.time_spent for p in progress_records if p.time_spent)
        
        return jsonify({
            'success': True,
            'dashboard': {
                'user_stats': {
                    'total_modules': total_modules,
                    'completed_modules': completed_modules,
                    'in_progress_modules': in_progress_modules,
                    'learning_streak': user.learning_streak or 0,
                    'total_time_spent': total_time_spent,
                    'level': user.level or 1,
                    'experience_points': user.experience_points or 0
                },
                'recent_activity': [{
                    'module_id': p.module_id,
                    'module_title': p.module.title,
                    'completion_percentage': p.completion_percentage,
                    'status': p.status,
                    'last_accessed': p.last_accessed.isoformat() if p.last_accessed else None
                } for p in recent_progress],
                'recommendations': learning_service.get_recommendations(user_id)
            }
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Error fetching learning dashboard: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to fetch dashboard'}), 500

@learning_bp.route('/categories', methods=['GET'])
@handle_errors
def get_categories():
    """Get all learning categories"""
    try:
        categories = db.session.query(LearningModule.category)\
            .distinct()\
            .filter(LearningModule.category.isnot(None))\
            .all()
        
        category_list = [cat[0] for cat in categories if cat[0]]
        
        return jsonify({
            'success': True,
            'categories': category_list
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Error fetching categories: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to fetch categories'}), 500

@learning_bp.route('/search', methods=['GET'])
@handle_errors
def search_modules():
    """Search learning modules"""
    try:
        query = request.args.get('q', '')
        difficulty = request.args.get('difficulty')
        category = request.args.get('category')
        
        if not query:
            return jsonify({'success': False, 'error': 'Search query is required'}), 400
        
        # Build search query
        search_query = LearningModule.query.filter(
            db.or_(
                LearningModule.title.ilike(f'%{query}%'),
                LearningModule.description.ilike(f'%{query}%')
            )
        )
        
        if difficulty:
            search_query = search_query.filter(LearningModule.difficulty == difficulty)
        if category:
            search_query = search_query.filter(LearningModule.category == category)
        
        modules = search_query.all()
        
        return jsonify({
            'success': True,
            'modules': [{
                'id': module.id,
                'title': module.title,
                'description': module.description,
                'difficulty': module.difficulty,
                'category': module.category,
                'estimated_time': module.estimated_time
            } for module in modules]
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Error searching modules: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to search modules'}), 500