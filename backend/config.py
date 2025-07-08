import os
from datetime import timedelta

class Config:
    """Base configuration class"""
    
    # Basic Flask Configuration
    SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key-change-in-production')
    APP_NAME = os.getenv('APP_NAME', 'Prompt Engineering Platform')
    VERSION = os.getenv('VERSION', '1.0.0')
    
    # Database Configuration
    SQLALCHEMY_DATABASE_URI = os.getenv(
        'DATABASE_URL',
        'postgresql://username:password@localhost/promptengineering'
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
        'pool_timeout': 20,
        'max_overflow': 0
    }
    
    # JWT Configuration
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'jwt-secret-string')
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=24)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    JWT_ALGORITHM = 'HS256'
    JWT_BLACKLIST_ENABLED = True
    JWT_BLACKLIST_TOKEN_CHECKS = ['access', 'refresh']
    
    # Redis Configuration
    REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
    REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
    REDIS_DB = int(os.getenv('REDIS_DB', 0))
    REDIS_PASSWORD = os.getenv('REDIS_PASSWORD')
    
    # Groq AI Configuration
    GROQ_API_KEY = os.getenv('GROQ_API_KEY')
    GROQ_BASE_URL = os.getenv('GROQ_BASE_URL', 'https://api.groq.com/openai/v1')
    GROQ_DEFAULT_MODEL = os.getenv('GROQ_DEFAULT_MODEL', 'llama-3.3-70b-versatile')
    GROQ_MAX_TOKENS = int(os.getenv('GROQ_MAX_TOKENS', 4096))
    GROQ_TEMPERATURE = float(os.getenv('GROQ_TEMPERATURE', 0.7))
    
    # Rate Limiting Configuration
    RATE_LIMIT_STORAGE_URL = os.getenv('RATE_LIMIT_STORAGE_URL', 'redis://localhost:6379')
    RATE_LIMIT_DEFAULT = os.getenv('RATE_LIMIT_DEFAULT', '1000 per hour')
    RATE_LIMIT_HEADERS_ENABLED = True
    
    # CORS Configuration
    CORS_ORIGINS = os.getenv('CORS_ORIGINS', 'http://localhost:3000').split(',')
    CORS_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
    CORS_HEADERS = ['Content-Type', 'Authorization']
    
    # Email Configuration (for notifications)
    MAIL_SERVER = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.getenv('MAIL_PORT', 587))
    MAIL_USE_TLS = os.getenv('MAIL_USE_TLS', 'true').lower() in ['true', '1']
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_DEFAULT_SENDER', 'noreply@promptengineering.com')
    
    # File Upload Configuration
    UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER', 'uploads')
    MAX_CONTENT_LENGTH = int(os.getenv('MAX_CONTENT_LENGTH', 16 * 1024 * 1024))  # 16MB
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'csv', 'json'}
    
    # Security Configuration
    BCRYPT_LOG_ROUNDS = int(os.getenv('BCRYPT_LOG_ROUNDS', 12))
    PASSWORD_MIN_LENGTH = int(os.getenv('PASSWORD_MIN_LENGTH', 8))
    PASSWORD_REQUIRE_UPPERCASE = os.getenv('PASSWORD_REQUIRE_UPPERCASE', 'true').lower() in ['true', '1']
    PASSWORD_REQUIRE_LOWERCASE = os.getenv('PASSWORD_REQUIRE_LOWERCASE', 'true').lower() in ['true', '1']
    PASSWORD_REQUIRE_NUMBERS = os.getenv('PASSWORD_REQUIRE_NUMBERS', 'true').lower() in ['true', '1']
    PASSWORD_REQUIRE_SYMBOLS = os.getenv('PASSWORD_REQUIRE_SYMBOLS', 'true').lower() in ['true', '1']
    
    # API Configuration
    API_VERSION = os.getenv('API_VERSION', 'v1')
    API_TITLE = os.getenv('API_TITLE', 'Prompt Engineering Platform API')
    API_DESCRIPTION = os.getenv('API_DESCRIPTION', 'RESTful API for prompt engineering learning platform')
    
    # Pagination Configuration
    POSTS_PER_PAGE = int(os.getenv('POSTS_PER_PAGE', 20))
    MAX_SEARCH_RESULTS = int(os.getenv('MAX_SEARCH_RESULTS', 100))
    
    # Cache Configuration
    CACHE_TYPE = os.getenv('CACHE_TYPE', 'redis')
    CACHE_DEFAULT_TIMEOUT = int(os.getenv('CACHE_DEFAULT_TIMEOUT', 300))
    CACHE_KEY_PREFIX = os.getenv('CACHE_KEY_PREFIX', 'prompteng_')
    
    # WebSocket Configuration
    SOCKETIO_ASYNC_MODE = os.getenv('SOCKETIO_ASYNC_MODE', 'threading')
    SOCKETIO_CORS_ALLOWED_ORIGINS = os.getenv('SOCKETIO_CORS_ALLOWED_ORIGINS', '*').split(',')
    
    # Logging Configuration
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FORMAT = os.getenv('LOG_FORMAT', '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    LOG_FILE = os.getenv('LOG_FILE', 'app.log')
    
    # AI Model Configuration
    SUPPORTED_MODELS = [
        'llama-3.3-70b-versatile',
        'llama-3.1-70b-versatile',
        'llama-3.1-8b-instant',
        'mixtral-8x7b-32768',
        'gemma-7b-it',
        'gemma2-9b-it'
    ]
    
    # Prompt Analysis Configuration
    SECURITY_ANALYSIS_ENABLED = os.getenv('SECURITY_ANALYSIS_ENABLED', 'true').lower() in ['true', '1']
    JAILBREAK_DETECTION_ENABLED = os.getenv('JAILBREAK_DETECTION_ENABLED', 'true').lower() in ['true', '1']
    PROMPT_INJECTION_DETECTION_ENABLED = os.getenv('PROMPT_INJECTION_DETECTION_ENABLED', 'true').lower() in ['true', '1']
    
    # Feature Flags
    FEATURE_REAL_TIME_COLLABORATION = os.getenv('FEATURE_REAL_TIME_COLLABORATION', 'true').lower() in ['true', '1']
    FEATURE_PROMPT_SHARING = os.getenv('FEATURE_PROMPT_SHARING', 'true').lower() in ['true', '1']
    FEATURE_ANALYTICS = os.getenv('FEATURE_ANALYTICS', 'true').lower() in ['true', '1']
    FEATURE_GAMIFICATION = os.getenv('FEATURE_GAMIFICATION', 'true').lower() in ['true', '1']
    
    # Monitoring Configuration
    SENTRY_DSN = os.getenv('SENTRY_DSN')
    DATADOG_API_KEY = os.getenv('DATADOG_API_KEY')
    
    # Performance Configuration
    SLOW_QUERY_THRESHOLD = float(os.getenv('SLOW_QUERY_THRESHOLD', 0.5))
    REQUEST_TIMEOUT = int(os.getenv('REQUEST_TIMEOUT', 30))
    
    @staticmethod
    def init_app(app):
        """Initialize application with configuration"""
        pass

class DevelopmentConfig(Config):
    """Development configuration"""
    
    DEBUG = True
    TESTING = False
    
    # Use SQLite for development if no DATABASE_URL is provided
    if not os.getenv('DATABASE_URL'):
        SQLALCHEMY_DATABASE_URI = 'sqlite:///promptengineering_dev.db'
    
    # Disable some security features for development
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=24)
    BCRYPT_LOG_ROUNDS = 4  # Faster for development
    
    # Enable debug features
    SQLALCHEMY_ECHO = True
    MAIL_SUPPRESS_SEND = True
    
    @classmethod
    def init_app(cls, app):
        Config.init_app(app)
        
        # Log to console in development
        import logging
        logging.basicConfig(level=logging.DEBUG)

class ProductionConfig(Config):
    """Production configuration"""
    
    DEBUG = False
    TESTING = False
    
    # Enhanced security for production
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    BCRYPT_LOG_ROUNDS = 15
    
    # Disable debug features
    SQLALCHEMY_ECHO = False
    
    @classmethod
    def init_app(cls, app):
        Config.init_app(app)
        
        # Log to file in production
        import logging
        from logging.handlers import RotatingFileHandler
        
        if not app.debug:
            file_handler = RotatingFileHandler(
                'logs/promptengineering.log',
                maxBytes=10240000,
                backupCount=10
            )
            file_handler.setFormatter(logging.Formatter(
                '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
            ))
            file_handler.setLevel(logging.INFO)
            app.logger.addHandler(file_handler)
            app.logger.setLevel(logging.INFO)
            app.logger.info('Prompt Engineering Platform startup')

class TestingConfig(Config):
    """Testing configuration"""
    
    TESTING = True
    DEBUG = True
    
    # Use in-memory database for testing
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    
    # Disable security features for testing
    WTF_CSRF_ENABLED = False
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=5)
    BCRYPT_LOG_ROUNDS = 4
    
    # Disable external services for testing
    MAIL_SUPPRESS_SEND = True
    RATE_LIMIT_ENABLED = False

# Configuration mapping
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}

def get_config():
    """Get configuration based on environment"""
    return config[os.getenv('FLASK_ENV', 'default')]