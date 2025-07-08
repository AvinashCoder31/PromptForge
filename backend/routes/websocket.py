from flask_socketio import SocketIO, emit, join_room, leave_room, disconnect
from flask_jwt_extended import decode_token
from models import User, db
from services.groq_service import GroqService
import json
import asyncio
import logging
from functools import wraps

# Initialize services
groq_service = GroqService()

# Store active connections
active_connections = {}

def authenticated_only(f):
    """Decorator to require authentication for socket events"""
    @wraps(f)
    def wrapped(*args, **kwargs):
        try:
            # Get token from auth data
            token = request.event.get('auth', {}).get('token')
            if not token:
                emit('error', {'message': 'Authentication required'})
                return
            
            # Decode token
            decoded_token = decode_token(token)
            user_id = decoded_token['sub']
            
            # Add user_id to kwargs
            kwargs['user_id'] = user_id
            return f(*args, **kwargs)
        except Exception as e:
            emit('error', {'message': 'Invalid authentication'})
            return
    return wrapped

def init_socketio(socketio):
    """Initialize socket.io event handlers"""
    
    @socketio.on('connect')
    def handle_connect(auth):
        """Handle client connection"""
        try:
            if not auth or 'token' not in auth:
                disconnect()
                return False
            
            # Verify token
            token = auth['token']
            decoded_token = decode_token(token)
            user_id = decoded_token['sub']
            
            # Store connection
            active_connections[request.sid] = {
                'user_id': user_id,
                'connected_at': datetime.utcnow()
            }
            
            # Join user's personal room
            join_room(f'user_{user_id}')
            
            emit('connected', {
                'message': 'Connected successfully',
                'user_id': user_id,
                'session_id': request.sid
            })
            
            logging.info(f"User {user_id} connected with session {request.sid}")
            
        except Exception as e:
            logging.error(f"Connection error: {str(e)}")
            disconnect()
            return False
    
    @socketio.on('disconnect')
    def handle_disconnect():
        """Handle client disconnection"""
        try:
            if request.sid in active_connections:
                user_id = active_connections[request.sid]['user_id']
                leave_room(f'user_{user_id}')
                del active_connections[request.sid]
                logging.info(f"User {user_id} disconnected")
        except Exception as e:
            logging.error(f"Disconnect error: {str(e)}")
    
    @socketio.on('prompt_test')
    @authenticated_only
    def handle_prompt_test(data, user_id):
        """Handle real-time prompt testing"""
        try:
            prompt = data.get('prompt', '')
            model = data.get('model', 'llama-3.3-70b-versatile')
            temperature = data.get('temperature', 0.7)
            max_tokens = data.get('max_tokens', 1000)
            
            if not prompt:
                emit('prompt_test_error', {'message': 'Prompt is required'})
                return
            
            # Emit testing started
            emit('prompt_test_started', {
                'message': 'Testing prompt...',
                'prompt': prompt,
                'model': model
            })
            
            # Test prompt asynchronously
            socketio.start_background_task(
                target=_test_prompt_async,
                user_id=user_id,
                session_id=request.sid,
                prompt=prompt,
                model=model,
                temperature=temperature,
                max_tokens=max_tokens
            )
            
        except Exception as e:
            emit('prompt_test_error', {'message': str(e)})
    
    @socketio.on('prompt_optimize')
    @authenticated_only
    def handle_prompt_optimize(data, user_id):
        """Handle real-time prompt optimization"""
        try:
            prompt = data.get('prompt', '')
            objective = data.get('objective', 'general')
            
            if not prompt:
                emit('prompt_optimize_error', {'message': 'Prompt is required'})
                return
            
            # Emit optimization started
            emit('prompt_optimize_started', {
                'message': 'Optimizing prompt...',
                'prompt': prompt,
                'objective': objective
            })
            
            # Optimize prompt asynchronously
            socketio.start_background_task(
                target=_optimize_prompt_async,
                user_id=user_id,
                session_id=request.sid,
                prompt=prompt,
                objective=objective
            )
            
        except Exception as e:
            emit('prompt_optimize_error', {'message': str(e)})
    
    @socketio.on('security_scan')
    @authenticated_only
    def handle_security_scan(data, user_id):
        """Handle real-time security scanning"""
        try:
            prompt = data.get('prompt', '')
            
            if not prompt:
                emit('security_scan_error', {'message': 'Prompt is required'})
                return
            
            # Emit scan started
            emit('security_scan_started', {
                'message': 'Scanning prompt for security vulnerabilities...',
                'prompt': prompt
            })
            
            # Scan prompt asynchronously
            socketio.start_background_task(
                target=_security_scan_async,
                user_id=user_id,
                session_id=request.sid,
                prompt=prompt
            )
            
        except Exception as e:
            emit('security_scan_error', {'message': str(e)})
    
    @socketio.on('join_learning_session')
    @authenticated_only
    def handle_join_learning_session(data, user_id):
        """Handle joining a learning session"""
        try:
            module_id = data.get('module_id')
            
            if not module_id:
                emit('learning_session_error', {'message': 'Module ID is required'})
                return
            
            # Join learning session room
            room = f'learning_{module_id}'
            join_room(room)
            
            # Notify others in the room
            emit('user_joined_learning', {
                'user_id': user_id,
                'module_id': module_id
            }, room=room, include_self=False)
            
            emit('learning_session_joined', {
                'message': 'Joined learning session',
                'module_id': module_id,
                'room': room
            })
            
        except Exception as e:
            emit('learning_session_error', {'message': str(e)})
    
    @socketio.on('leave_learning_session')
    @authenticated_only
    def handle_leave_learning_session(data, user_id):
        """Handle leaving a learning session"""
        try:
            module_id = data.get('module_id')
            
            if not module_id:
                emit('learning_session_error', {'message': 'Module ID is required'})
                return
            
            # Leave learning session room
            room = f'learning_{module_id}'
            leave_room(room)
            
            # Notify others in the room
            emit('user_left_learning', {
                'user_id': user_id,
                'module_id': module_id
            }, room=room, include_self=False)
            
            emit('learning_session_left', {
                'message': 'Left learning session',
                'module_id': module_id
            })
            
        except Exception as e:
            emit('learning_session_error', {'message': str(e)})
    
    @socketio.on('collaborative_prompt')
    @authenticated_only
    def handle_collaborative_prompt(data, user_id):
        """Handle collaborative prompt editing"""
        try:
            session_id = data.get('session_id')
            prompt_text = data.get('prompt_text', '')
            cursor_position = data.get('cursor_position', 0)
            
            if not session_id:
                emit('collaborative_error', {'message': 'Session ID is required'})
                return
            
            # Broadcast changes to all users in the session
            room = f'collab_{session_id}'
            emit('prompt_updated', {
                'user_id': user_id,
                'prompt_text': prompt_text,
                'cursor_position': cursor_position,
                'timestamp': datetime.utcnow().isoformat()
            }, room=room, include_self=False)
            
        except Exception as e:
            emit('collaborative_error', {'message': str(e)})
    
    @socketio.on('typing_indicator')
    @authenticated_only
    def handle_typing_indicator(data, user_id):
        """Handle typing indicators for collaborative editing"""
        try:
            session_id = data.get('session_id')
            is_typing = data.get('is_typing', False)
            
            if not session_id:
                return
            
            # Broadcast typing status
            room = f'collab_{session_id}'
            emit('user_typing', {
                'user_id': user_id,
                'is_typing': is_typing
            }, room=room, include_self=False)
            
        except Exception as e:
            logging.error(f"Typing indicator error: {str(e)}")
    
    @socketio.on('get_active_users')
    @authenticated_only
    def handle_get_active_users(data, user_id):
        """Get list of active users"""
        try:
            active_users = []
            for sid, conn_info in active_connections.items():
                if conn_info['user_id'] != user_id:  # Exclude requesting user
                    user = User.query.get(conn_info['user_id'])
                    if user:
                        active_users.append({
                            'user_id': user.id,
                            'username': user.username,
                            'connected_at': conn_info['connected_at'].isoformat()
                        })
            
            emit('active_users', {
                'users': active_users,
                'total_count': len(active_users)
            })
            
        except Exception as e:
            emit('error', {'message': str(e)})

def _test_prompt_async(user_id, session_id, prompt, model, temperature, max_tokens):
    """Test prompt asynchronously"""
    try:
        # Generate response using Groq
        response = groq_service.generate_response(
            messages=[{"role": "user", "content": prompt}],
            model=model,
            temperature=temperature,
            max_tokens=max_tokens
        )
        
        # Emit successful result
        socketio.emit('prompt_test_result', {
            'success': True,
            'response': response,
            'model': model,
            'prompt': prompt,
            'timestamp': datetime.utcnow().isoformat()
        }, room=session_id)
        
    except Exception as e:
        # Emit error result
        socketio.emit('prompt_test_error', {
            'success': False,
            'error': str(e),
            'prompt': prompt
        }, room=session_id)

def _optimize_prompt_async(user_id, session_id, prompt, objective):
    """Optimize prompt asynchronously"""
    try:
        # Create optimization prompt
        optimization_prompt = f"""
        Optimize the following prompt for better results based on the objective: {objective}
        
        Original prompt: {prompt}
        
        Provide an optimized version with explanations for the improvements made.
        Format your response as JSON with 'optimized_prompt' and 'improvements' fields.
        """
        
        # Generate optimized prompt
        response = groq_service.generate_response(
            messages=[{"role": "user", "content": optimization_prompt}],
            model="llama-3.3-70b-versatile"
        )
        
        try:
            # Parse JSON response
            result = json.loads(response)
            optimized_prompt = result.get('optimized_prompt', prompt)
            improvements = result.get('improvements', [])
        except json.JSONDecodeError:
            # Fallback if response is not JSON
            optimized_prompt = response
            improvements = ["General optimization applied"]
        
        # Emit successful result
        socketio.emit('prompt_optimize_result', {
            'success': True,
            'original_prompt': prompt,
            'optimized_prompt': optimized_prompt,
            'improvements': improvements,
            'objective': objective,
            'timestamp': datetime.utcnow().isoformat()
        }, room=session_id)
        
    except Exception as e:
        # Emit error result
        socketio.emit('prompt_optimize_error', {
            'success': False,
            'error': str(e),
            'prompt': prompt
        }, room=session_id)

def _security_scan_async(user_id, session_id, prompt):
    """Perform security scan asynchronously"""
    try:
        # Import here to avoid circular imports
        from routes.security import SECURITY_PATTERNS
        
        # Perform basic pattern matching
        vulnerabilities = []
        risk_score = 0
        
        for vuln_type, patterns in SECURITY_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, prompt, re.IGNORECASE):
                    vulnerabilities.append({
                        'type': vuln_type,
                        'pattern': pattern,
                        'severity': _calculate_severity(vuln_type)
                    })
                    risk_score += _get_risk_points(vuln_type)
        
        # Calculate risk level
        risk_level = _calculate_risk_level(risk_score, len(vulnerabilities))
        
        # Emit successful result
        socketio.emit('security_scan_result', {
            'success': True,
            'prompt': prompt,
            'risk_level': risk_level,
            'risk_score': risk_score,
            'vulnerabilities': vulnerabilities,
            'vulnerability_count': len(vulnerabilities),
            'timestamp': datetime.utcnow().isoformat()
        }, room=session_id)
        
    except Exception as e:
        # Emit error result
        socketio.emit('security_scan_error', {
            'success': False,
            'error': str(e),
            'prompt': prompt
        }, room=session_id)

# Helper functions (duplicated from security.py to avoid circular imports)
def _calculate_severity(vuln_type):
    severity_map = {
        'prompt_injection': 'high',
        'data_leakage': 'high',
        'manipulation': 'medium',
        'harmful_content': 'high'
    }
    return severity_map.get(vuln_type, 'low')

def _get_risk_points(vuln_type):
    points_map = {
        'prompt_injection': 25,
        'data_leakage': 30,
        'manipulation': 15,
        'harmful_content': 35
    }
    return points_map.get(vuln_type, 5)

def _calculate_risk_level(risk_score, vuln_count):
    if risk_score >= 50 or vuln_count >= 5:
        return 'high'
    elif risk_score >= 25 or vuln_count >= 3:
        return 'medium'
    elif risk_score >= 10 or vuln_count >= 1:
        return 'low'
    else:
        return 'safe'