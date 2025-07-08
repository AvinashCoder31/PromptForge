from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from werkzeug.security import generate_password_hash
import os
import redis
from datetime import datetime, timedelta
import logging

# Import configurations and models
from config import Config
from models import db, User, Course, Lesson, Prompt, UserProgress, SecurityAnalysis
from routes import auth_bp, prompt_bp, learning_bp, security_bp
from utils.decorators import token_required, admin_required
from services.groq_service import GroqService

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)

# Initialize extensions
db.init_app(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)
cors = CORS(app, origins=["http://localhost:3000", "https://your-frontend-domain.com"])
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Initialize Redis for caching
try:
    redis_client = redis.Redis(
        host=os.getenv('REDIS_HOST', 'localhost'),
        port=int(os.getenv('REDIS_PORT', 6379)),
        db=0,
        decode_responses=True
    )
    redis_client.ping()
    print("✅ Redis connection successful")
except Exception as e:
    print(f"❌ Redis connection failed: {e}")
    redis_client = None

# Initialize Groq service
groq_service = GroqService()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Register blueprints
app.register_blueprint(auth_bp, url_prefix='/api/auth')
app.register_blueprint(prompt_bp, url_prefix='/api/prompts')
app.register_blueprint(learning_bp, url_prefix='/api/learning')
app.register_blueprint(security_bp, url_prefix='/api/security')

# Health check endpoint
@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint for monitoring"""
    try:
        # Check database connection
        db.session.execute('SELECT 1')
        db_status = "healthy"
    except Exception as e:
        db_status = f"unhealthy: {str(e)}"
    
    # Check Redis connection
    redis_status = "healthy" if redis_client else "unavailable"
    
    # Check Groq service
    groq_status = "healthy" if groq_service.is_healthy() else "unhealthy"
    
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'services': {
            'database': db_status,
            'redis': redis_status,
            'groq': groq_status
        }
    })

# WebSocket Events
@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    print(f"Client connected: {request.sid}")
    emit('connected', {'message': 'Connected to Prompt Engineering Platform'})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    print(f"Client disconnected: {request.sid}")

@socketio.on('join_room')
def handle_join_room(data):
    """Join a specific room for real-time updates"""
    room = data.get('room')
    if room:
        join_room(room)
        emit('room_joined', {'room': room})

@socketio.on('leave_room')
def handle_leave_room(data):
    """Leave a specific room"""
    room = data.get('room')
    if room:
        leave_room(room)
        emit('room_left', {'room': room})

@socketio.on('real_time_prompt_test')
def handle_real_time_prompt_test(data):
    """Handle real-time prompt testing"""
    try:
        prompt_text = data.get('prompt')
        model = data.get('model', 'llama-3.3-70b-versatile')
        
        if not prompt_text:
            emit('prompt_error', {'error': 'Prompt text is required'})
            return
        
        # Test prompt with Groq
        result = groq_service.test_prompt(prompt_text, model)
        
        # Emit result back to client
        emit('prompt_result', {
            'prompt': prompt_text,
            'response': result.get('response'),
            'tokens_used': result.get('tokens_used'),
            'response_time': result.get('response_time'),
            'model': model,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        emit('prompt_error', {'error': str(e)})

@socketio.on('analyze_prompt_security')
def handle_analyze_prompt_security(data):
    """Handle real-time prompt security analysis"""
    try:
        prompt_text = data.get('prompt')
        
        if not prompt_text:
            emit('security_error', {'error': 'Prompt text is required'})
            return
        
        # Analyze prompt security
        analysis = groq_service.analyze_prompt_security(prompt_text)
        
        # Emit analysis result
        emit('security_analysis', {
            'prompt': prompt_text,
            'analysis': analysis,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        emit('security_error', {'error': str(e)})

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(ValidationError)
def validation_error(error):
    return jsonify({'error': 'Validation error', 'details': str(error)}), 400

# Initialize database
@app.before_first_request
def create_tables():
    """Create database tables and seed initial data"""
    db.create_all()
    
    # Create admin user if not exists
    admin_user = User.query.filter_by(email='admin@promptengineering.com').first()
    if not admin_user:
        admin_user = User(
            username='admin',
            email='admin@promptengineering.com',
            password_hash=generate_password_hash('admin123'),
            role='admin',
            is_active=True
        )
        db.session.add(admin_user)
        db.session.commit()
        print("✅ Admin user created")
    
    # Seed initial courses if not exists
    if Course.query.count() == 0:
        seed_initial_courses()

def seed_initial_courses():
    """Seed initial course data"""
    courses_data = [
        {
            'title': 'Prompt Engineering Fundamentals',
            'description': 'Learn the basics of prompt engineering with practical examples',
            'difficulty': 'beginner',
            'category': 'fundamentals',
            'lessons': [
                {
                    'title': 'Introduction to Prompt Engineering',
                    'content': 'What is prompt engineering and why it matters...',
                    'order': 1
                },
                {
                    'title': 'Basic Prompt Structure',
                    'content': 'Understanding the anatomy of effective prompts...',
                    'order': 2
                }
            ]
        },
        {
            'title': 'Advanced Prompt Techniques',
            'description': 'Master advanced prompt engineering techniques',
            'difficulty': 'advanced',
            'category': 'techniques',
            'lessons': [
                {
                    'title': 'Chain of Thought Prompting',
                    'content': 'Learn to guide AI through step-by-step reasoning...',
                    'order': 1
                },
                {
                    'title': 'Few-Shot Learning',
                    'content': 'Provide examples to improve AI performance...',
                    'order': 2
                }
            ]
        }
    ]
    
    for course_data in courses_data:
        course = Course(
            title=course_data['title'],
            description=course_data['description'],
            difficulty=course_data['difficulty'],
            category=course_data['category']
        )
        db.session.add(course)
        db.session.flush()
        
        for lesson_data in course_data['lessons']:
            lesson = Lesson(
                title=lesson_data['title'],
                content=lesson_data['content'],
                order=lesson_data['order'],
                course_id=course.id
            )
            db.session.add(lesson)
    
    db.session.commit()
    print("✅ Initial courses seeded")

# Context processor for templates
@app.context_processor
def inject_config():
    return dict(
        app_name=app.config.get('APP_NAME', 'Prompt Engineering Platform'),
        version=app.config.get('VERSION', '1.0.0')
    )

# Make app available globally
def create_app():
    return app

if __name__ == '__main__':
    # Development server
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_ENV') == 'development'
    
    print(f"🚀 Starting Prompt Engineering Platform on port {port}")
    print(f"📊 Debug mode: {debug}")
    
    socketio.run(
        app,
        host='0.0.0.0',
        port=port,
        debug=debug,
        use_reloader=debug
    )