"""
Routes module initialization
"""
from flask import Blueprint

# Import all route modules
from .auth import auth_bp
from .prompt import prompt_bp
from .learning import learning_bp
from .security import security_bp
from .websocket import websocket_bp

# Create a list of all blueprints for easy registration
all_blueprints = [
    auth_bp,
    prompt_bp,
    learning_bp,
    security_bp,
    websocket_bp
]

def register_blueprints(app):
    """Register all blueprints with the Flask app"""
    for blueprint in all_blueprints:
        app.register_blueprint(blueprint)