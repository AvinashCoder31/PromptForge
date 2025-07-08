from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import json
import uuid
from enum import Enum
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy import func, Index

# Initialize SQLAlchemy
db = SQLAlchemy()

# Enums for better type safety
class UserRole(Enum):
    USER = "user"
    ADMIN = "admin"
    MODERATOR = "moderator"

class DifficultyLevel(Enum):
    BEGINNER = "beginner"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    EXPERT = "expert"

class PromptStatus(Enum):
    DRAFT = "draft"
    PUBLISHED = "published"
    ARCHIVED = "archived"

class SecurityThreatLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

# Association tables for many-to-many relationships
user_courses = db.Table('user_courses',
    db.Column('user_id', UUID(as_uuid=True), db.ForeignKey('users.id'), primary_key=True),
    db.Column('course_id', UUID(as_uuid=True), db.ForeignKey('courses.id'), primary_key=True),
    db.Column('enrolled_at', db.DateTime, default=datetime.utcnow)
)

prompt_tags = db.Table('prompt_tags',
    db.Column('prompt_id', UUID(as_uuid=True), db.ForeignKey('prompts.id'), primary_key=True),
    db.Column('tag_id', UUID(as_uuid=True), db.ForeignKey('tags.id'), primary_key=True)
)

# Base model with common fields
class BaseModel(db.Model):
    __abstract__ = True
    
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    def to_dict(self):
        """Convert model to dictionary"""
        return {
            'id': str(self.id),
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }

# User model
class User(BaseModel):
    __tablename__ = 'users'
    
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    role = db.Column(db.Enum(UserRole), default=UserRole.USER, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    is_verified = db.Column(db.Boolean, default=False, nullable=False)
    last_login = db.Column(db.DateTime)
    profile_image = db.Column(db.String(255))
    bio = db.Column(db.Text)
    experience_level = db.Column(db.Enum(DifficultyLevel), default=DifficultyLevel.BEGINNER)
    preferences = db.Column(JSONB, default=dict)
    
    # Relationships
    courses = db.relationship('Course', secondary=user_courses, backref='students')
    prompts = db.relationship('Prompt', backref='author', lazy='dynamic')
    progress = db.relationship('UserProgress', backref='user', lazy='dynamic')
    security_analyses = db.relationship('SecurityAnalysis', backref='user', lazy='dynamic')
    achievements = db.relationship('Achievement', secondary='user_achievements', backref='users')
    
    # Indexes
    __table_args__ = (
        Index('idx_user_email_active', 'email', 'is_active'),
        Index('idx_user_username_active', 'username', 'is_active'),
    )
    
    def set_password(self, password):
        """Set password hash"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Check password against hash"""
        return check_password_hash(self.password_hash, password)
    
    @hybrid_property
    def full_name(self):
        """Get full name"""
        return f"{self.first_name} {self.last_name}".strip()
    
    def get_progress_percentage(self, course_id):
        """Get progress percentage for a course"""
        course = Course.query.get(course_id)
        if not course:
            return 0
        
        total_lessons = course.lessons.count()
        completed_lessons = UserProgress.query.filter_by(
            user_id=self.id,
            course_id=course_id,
            completed=True
        ).count()
        
        return (completed_lessons / total_lessons) * 100 if total_lessons > 0 else 0
    
    def to_dict(self):
        """Convert user to dictionary"""
        data = super().to_dict()
        data.update({
            'username': self.username,
            'email': self.email,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'full_name': self.full_name,
            'role': self.role.value,
            'is_active': self.is_active,
            'is_verified': self.is_verified,
            'experience_level': self.experience_level.value,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'profile_image': self.profile_image,
            'bio': self.bio,
            'preferences': self.preferences or {}
        })
        return data

# Course model
class Course(BaseModel):
    __tablename__ = 'courses'
    
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    difficulty = db.Column(db.Enum(DifficultyLevel), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    thumbnail = db.Column(db.String(255))
    duration_minutes = db.Column(db.Integer, default=0)
    is_published = db.Column(db.Boolean, default=False)
    prerequisites = db.Column(JSONB, default=list)
    learning_objectives = db.Column(JSONB, default=list)
    tags = db.Column(JSONB, default=list)
    
    # Relationships
    lessons = db.relationship('Lesson', backref='course', lazy='dynamic', cascade='all, delete-orphan')
    progress = db.relationship('UserProgress', backref='course', lazy='dynamic')
    
    # Indexes
    __table_args__ = (
        Index('idx_course_category_difficulty', 'category', 'difficulty'),
        Index('idx_course_published', 'is_published'),
    )
    
    def get_completion_rate(self):
        """Get overall completion rate for the course"""
        total_enrollments = len(self.students)
        if total_enrollments == 0:
            return 0
        
        completed_enrollments = sum(1 for user in self.students 
                                  if user.get_progress_percentage(self.id) >= 100)
        
        return (completed_enrollments / total_enrollments) * 100
    
    def to_dict(self):
        """Convert course to dictionary"""
        data = super().to_dict()
        data.update({
            'title': self.title,
            'description': self.description,
            'difficulty': self.difficulty.value,
            'category': self.category,
            'thumbnail': self.thumbnail,
            'duration_minutes': self.duration_minutes,
            'is_published': self.is_published,
            'prerequisites': self.prerequisites or [],
            'learning_objectives': self.learning_objectives or [],
            'tags': self.tags or [],
            'lesson_count': self.lessons.count(),
            'student_count': len(self.students),
            'completion_rate': self.get_completion_rate()
        })
        return data

# Lesson model
class Lesson(BaseModel):
    __tablename__ = 'lessons'
    
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text)
    order = db.Column(db.Integer, nullable=False)
    duration_minutes = db.Column(db.Integer, default=0)
    is_published = db.Column(db.Boolean, default=False)
    lesson_type = db.Column(db.String(50), default='text')  # text, video, interactive, quiz
    resources = db.Column(JSONB, default=list)
    exercises = db.Column(JSONB, default=list)
    
    # Foreign keys
    course_id = db.Column(UUID(as_uuid=True), db.ForeignKey('courses.id'), nullable=False)
    
    # Relationships
    progress = db.relationship('UserProgress', backref='lesson', lazy='dynamic')
    
    # Indexes
    __table_args__ = (
        Index('idx_lesson_course_order', 'course_id', 'order'),
        Index('idx_lesson_published', 'is_published'),
    )
    
    def to_dict(self):
        """Convert lesson to dictionary"""
        data = super().to_dict()
        data.update({
            'title': self.title,
            'content': self.content,
            'order': self.order,
            'duration_minutes': self.duration_minutes,
            'is_published': self.is_published,
            'lesson_type': self.lesson_type,
            'resources': self.resources or [],
            'exercises': self.exercises or [],
            'course_id': str(self.course_id)
        })
        return data

# Prompt model
class Prompt(BaseModel):
    __tablename__ = 'prompts'
    
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    description = db.Column(db.Text)
    category = db.Column(db.String(100), nullable=False)
    difficulty = db.Column(db.Enum(DifficultyLevel), nullable=False)
    status = db.Column(db.Enum(PromptStatus), default=PromptStatus.DRAFT)
    is_public = db.Column(db.Boolean, default=False)
    use_cases = db.Column(JSONB, default=list)
    parameters = db.Column(JSONB, default=dict)
    expected_output = db.Column(db.Text)
    model_compatibility = db.Column(JSONB, default=list)
    performance_metrics = db.Column(JSONB, default=dict)
    version = db.Column(db.Integer, default=1)
    
    # Statistics
    usage_count = db.Column(db.Integer, default=0)
    likes_count = db.Column(db.Integer, default=0)
    shares_count = db.Column(db.Integer, default=0)
    
    # Foreign keys
    author_id = db.Column(UUID(as_uuid=True), db.ForeignKey('users.id'), nullable=False)
    
    # Relationships
    tags = db.relationship('Tag', secondary=prompt_tags, backref='prompts')
    tests = db.relationship('PromptTest', backref='prompt', lazy='dynamic', cascade='all, delete-orphan')
    security_analyses = db.relationship('SecurityAnalysis', backref='prompt', lazy='dynamic')
    
    # Indexes
    __table_args__ = (
        Index('idx_prompt_category_difficulty', 'category', 'difficulty'),
        Index('idx_prompt_status_public', 'status', 'is_public'),
        Index('idx_prompt_author_status', 'author_id', 'status'),
    )
    
    def increment_usage(self):
        """Increment usage count"""
        self.usage_count += 1
        db.session.commit()
    
    def to_dict(self):
        """Convert prompt to dictionary"""
        data = super().to_dict()
        data.update({
            'title': self.title,
            'content': self.content,
            'description': self.description,
            'category': self.category,
            'difficulty': self.difficulty.value,
            'status': self.status.value,
            'is_public': self.is_public,
            'use_cases': self.use_cases or [],
            'parameters': self.parameters or {},
            'expected_output': self.expected_output,
            'model_compatibility': self.model_compatibility or [],
            'performance_metrics': self.performance_metrics or {},
            'version': self.version,
            'usage_count': self.usage_count,
            'likes_count': self.likes_count,
            'shares_count': self.shares_count,
            'author_id': str(self.author_id),
            'tags': [tag.to_dict() for tag in self.tags]
        })
        return data

# Tag model
class Tag(BaseModel):
    __tablename__ = 'tags'
    
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.Text)
    color = db.Column(db.String(7), default='#3B82F6')  # Hex color
    usage_count = db.Column(db.Integer, default=0)
    
    # Indexes
    __table_args__ = (
        Index('idx_tag_name', 'name'),
    )
    
    def to_dict(self):
        """Convert tag to dictionary"""
        data = super().to_dict()
        data.update({
            'name': self.name,
            'description': self.description,
            'color': self.color,
            'usage_count': self.usage_count
        })
        return data

# User Progress model
class UserProgress(BaseModel):
    __tablename__ = 'user_progress'
    
    completed = db.Column(db.Boolean, default=False)
    completion_date = db.Column(db.DateTime)
    time_spent_minutes = db.Column(db.Integer, default=0)
    score = db.Column(db.Float)
    attempts = db.Column(db.Integer, default=0)
    notes = db.Column(db.Text)
    
    # Foreign keys
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey('users.id'), nullable=False)
    course_id = db.Column(UUID(as_uuid=True), db.ForeignKey('courses.id'), nullable=False)
    lesson_id = db.Column(UUID(as_uuid=True), db.ForeignKey('lessons.id'))
    
    # Unique constraint to prevent duplicate progress entries
    __table_args__ = (
        db.UniqueConstraint('user_id', 'course_id', 'lesson_id', name='unique_user_progress'),
        Index('idx_progress_user_course', 'user_id', 'course_id'),
    )
    
    def mark_completed(self):
        """Mark progress as completed"""
        self.completed = True
        self.completion_date = datetime.utcnow()
        db.session.commit()
    
    def to_dict(self):
        """Convert progress to dictionary"""
        data = super().to_dict()
        data.update({
            'completed': self.completed,
            'completion_date': self.completion_date.isoformat() if self.completion_date else None,
            'time_spent_minutes': self.time_spent_minutes,
            'score': self.score,
            'attempts': self.attempts,
            'notes': self.notes,
            'user_id': str(self.user_id),
            'course_id': str(self.course_id),
            'lesson_id': str(self.lesson_id) if self.lesson_id else None
        })
        return data

# Prompt Test model
class PromptTest(BaseModel):
    __tablename__ = 'prompt_tests'
    
    test_input = db.Column(db.Text, nullable=False)
    expected_output = db.Column(db.Text)
    actual_output = db.Column(db.Text)
    model_used = db.Column(db.String(100), nullable=False)
    tokens_used = db.Column(db.Integer)
    response_time_ms = db.Column(db.Integer)
    success = db.Column(db.Boolean)
    error_message = db.Column(db.Text)
    parameters = db.Column(JSONB, default=dict)
    
    # Foreign keys
    prompt_id = db.Column(UUID(as_uuid=True), db.ForeignKey('prompts.id'), nullable=False)
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey('users.id'), nullable=False)
    
    # Indexes
    __table_args__ = (
        Index('idx_test_prompt_success', 'prompt_id', 'success'),
        Index('idx_test_user_created', 'user_id', 'created_at'),
    )
    
    def to_dict(self):
        """Convert test to dictionary"""
        data = super().to_dict()
        data.update({
            'test_input': self.test_input,
            'expected_output': self.expected_output,
            'actual_output': self.actual_output,
            'model_used': self.model_used,
            'tokens_used': self.tokens_used,
            'response_time_ms': self.response_time_ms,
            'success': self.success,
            'error_message': self.error_message,
            'parameters': self.parameters or {},
            'prompt_id': str(self.prompt_id),
            'user_id': str(self.user_id)
        })
        return data

# Security Analysis model
class SecurityAnalysis(BaseModel):
    __tablename__ = 'security_analyses'
    
    threat_level = db.Column(db.Enum(SecurityThreatLevel), nullable=False)
    jailbreak_detected = db.Column(db.Boolean, default=False)
    prompt_injection_detected = db.Column(db.Boolean, default=False)
    pii_detected = db.Column(db.Boolean, default=False)
    toxicity_score = db.Column(db.Float, default=0.0)
    bias_score = db.Column(db.Float, default=0.0)
    issues_found = db.Column(JSONB, default=list)
    recommendations = db.Column(JSONB, default=list)
    analysis_details = db.Column(JSONB, default=dict)
    
    # Foreign keys
    prompt_id = db.Column(UUID(as_uuid=True), db.ForeignKey('prompts.id'))
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey('users.id'), nullable=False)
    
    # Indexes
    __table_args__ = (
        Index('idx_security_threat_level', 'threat_level'),
        Index('idx_security_user_created', 'user_id', 'created_at'),
    )
    
    def to_dict(self):
        """Convert security analysis to dictionary"""
        data = super().to_dict()
        data.update({
            'threat_level': self.threat_level.value,
            'jailbreak_detected': self.jailbreak_detected,
            'prompt_injection_detected': self.prompt_injection_detected,
            'pii_detected': self.pii_detected,
            'toxicity_score': self.toxicity_score,
            'bias_score': self.bias_score,
            'issues_found': self.issues_found or [],
            'recommendations': self.recommendations or [],
            'analysis_details': self.analysis_details or {},
            'prompt_id': str(self.prompt_id) if self.prompt_id else None,
            'user_id': str(self.user_id)
        })
        return data

# Achievement model
class Achievement(BaseModel):
    __tablename__ = 'achievements'
    
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    icon = db.Column(db.String(255))
    points = db.Column(db.Integer, default=0)
    category = db.Column(db.String(50), nullable=False)
    requirements = db.Column(JSONB, default=dict)
    is_active = db.Column(db.Boolean, default=True)
    
    def to_dict(self):
        """Convert achievement to dictionary"""
        data = super().to_dict()
        data.update({
            'name': self.name,
            'description': self.description,
            'icon': self.icon,
            'points': self.points,
            'category': self.category,
            'requirements': self.requirements or {},
            'is_active': self.is_active
        })
        return data

# User Achievement association table
user_achievements = db.Table('user_achievements',
    db.Column('user_id', UUID(as_uuid=True), db.ForeignKey('users.id'), primary_key=True),
    db.Column('achievement_id', UUID(as_uuid=True), db.ForeignKey('achievements.id'), primary_key=True),
    db.Column('earned_at', db.DateTime, default=datetime.utcnow)
)

# Analytics model
class Analytics(BaseModel):
    __tablename__ = 'analytics'
    
    event_type = db.Column(db.String(50), nullable=False)
    event_data = db.Column(JSONB, default=dict)
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey('users.id'))
    session_id = db.Column(db.String(255))
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(500))
    
    # Indexes
    __table_args__ = (
        Index('idx_analytics_event_type', 'event_type'),
        Index('idx_analytics_user_created', 'user_id', 'created_at'),
        Index('idx_analytics_session', 'session_id'),
    )
    
    def to_dict(self):
        """Convert analytics to dictionary"""
        data = super().to_dict()
        data.update({
            'event_type': self.event_type,
            'event_data': self.event_data or {},
            'user_id': str(self.user_id) if self.user_id else None,
            'session_id': self.session_id,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent
        })
        return data

# Notification model
class Notification(BaseModel):
    __tablename__ = 'notifications'
    
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(50), nullable=False)  # info, success, warning, error
    is_read = db.Column(db.Boolean, default=False)
    action_url = db.Column(db.String(255))
    metadata = db.Column(JSONB, default=dict)
    
    # Foreign keys
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey('users.id'), nullable=False)
    
    # Indexes
    __table_args__ = (
        Index('idx_notification_user_read', 'user_id', 'is_read'),
        Index('idx_notification_created', 'created_at'),
    )
    
    def mark_as_read(self):
        """Mark notification as read"""
        self.is_read = True
        db.session.commit()
    
    def to_dict(self):
        """Convert notification to dictionary"""
        data = super().to_dict()
        data.update({
            'title': self.title,
            'message': self.message,
            'type': self.type,
            'is_read': self.is_read,
            'action_url': self.action_url,
            'metadata': self.metadata or {},
            'user_id': str(self.user_id)
        })
        return data

# API Key model for external integrations
class APIKey(BaseModel):
    __tablename__ = 'api_keys'
    
    name = db.Column(db.String(100), nullable=False)
    key_hash = db.Column(db.String(255), nullable=False, unique=True)
    permissions = db.Column(JSONB, default=list)
    is_active = db.Column(db.Boolean, default=True)
    expires_at = db.Column(db.DateTime)
    last_used = db.Column(db.DateTime)
    usage_count = db.Column(db.Integer, default=0)
    
    # Foreign keys
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey('users.id'), nullable=False)
    
    # Indexes
    __table_args__ = (
        Index('idx_api_key_hash', 'key_hash'),
        Index('idx_api_key_user_active', 'user_id', 'is_active'),
    )
    
    def is_expired(self):
        """Check if API key is expired"""
        return self.expires_at and self.expires_at < datetime.utcnow()
    
    def increment_usage(self):
        """Increment usage count and update last used"""
        self.usage_count += 1
        self.last_used = datetime.utcnow()
        db.session.commit()
    
    def to_dict(self):
        """Convert API key to dictionary"""
        data = super().to_dict()
        data.update({
            'name': self.name,
            'permissions': self.permissions or [],
            'is_active': self.is_active,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'last_used': self.last_used.isoformat() if self.last_used else None,
            'usage_count': self.usage_count,
            'user_id': str(self.user_id),
            'is_expired': self.is_expired()
        })
        return data