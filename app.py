#!/usr/bin/env python3
import os
from dotenv import load_dotenv
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from flask_socketio import SocketIO
from flask_cors import CORS
from functools import wraps
import threading
import logging
import sys

# Load environment variables
load_dotenv()

# Import custom modules
from app.backend.ai_core import AICore
from app.backend.memory_manager import MemoryManager
from app.backend.training_scheduler import TrainingScheduler
from app.backend.user_manager import UserManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Check for Google API key
google_api_key = os.getenv("GOOGLE_API_KEY", "")
if not google_api_key or google_api_key == "your_google_api_key_here":
    logger.warning("No valid Google API key found. The application will run with limited functionality.")
    logger.warning("Update your .env file with a valid Google API key for full functionality.")
else:
    logger.info("Google API key found. Attempting to use Gemini Pro API for responses.")
    logger.info("If you encounter API errors, please check that your key is valid and has access to the Gemini Pro API.")
    logger.info("The application will use fallback responses if the API is not accessible.")

# Initialize Flask app
app = Flask(__name__, 
            static_folder='app/frontend/static',
            template_folder='app/frontend/templates')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev_key')
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = 86400  # 24 hours
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Initialize core components
try:
    memory_manager = MemoryManager()
    ai_core = AICore(memory_manager)
    training_scheduler = TrainingScheduler(ai_core, memory_manager)
    user_manager = UserManager()
    
    # Start the training scheduler in a separate thread
    scheduler_thread = threading.Thread(target=training_scheduler.start_scheduler)
    scheduler_thread.daemon = True
    scheduler_thread.start()
    
    logger.info("SoulMate.AGI core components initialized successfully")
except Exception as e:
    logger.error(f"Error initializing core components: {str(e)}")
    raise

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_token' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Routes for authentication
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            error = "Please provide both username and password"
        else:
            success, result = user_manager.authenticate(username, password)
            if success:
                # Store token in session
                session['user_token'] = result
                user_info = user_manager.get_user_by_token(result)
                session['username'] = user_info['username']
                session['display_name'] = user_info['display_name']
                
                logger.info(f"User {username} logged in successfully")
                return redirect(url_for('chat'))
            else:
                error = result
    
    return render_template('login.html', error=error)

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        email = request.form.get('email')
        display_name = request.form.get('display_name')
        
        if not username or not password:
            error = "Please provide both username and password"
        elif password != confirm_password:
            error = "Passwords do not match"
        else:
            success, message = user_manager.register_user(
                username, 
                password, 
                email=email, 
                display_name=display_name
            )
            
            if success:
                flash("Registration successful! You can now log in.")
                return redirect(url_for('login'))
            else:
                error = message
    
    return render_template('register.html', error=error)

@app.route('/logout')
def logout():
    if 'user_token' in session:
        user_manager.logout(session['user_token'])
        
    # Clear session data
    session.pop('user_token', None)
    session.pop('username', None)
    session.pop('display_name', None)
    
    return redirect(url_for('login'))

@app.route('/')
def index():
    if 'user_token' in session:
        return redirect(url_for('chat'))
    return redirect(url_for('login'))

@app.route('/chat')
@login_required
def chat():
    username = session.get('username')
    user_info = {
        'username': username,
        'display_name': session.get('display_name')
    }
    return render_template('index.html', user=user_info)

@app.route('/api/health')
def health_check():
    api_status = "active" if google_api_key and google_api_key != "your_google_api_key_here" else "inactive"
    return jsonify({
        "status": "healthy", 
        "version": "1.0.0",
        "google_api": api_status,
        "platform": "soulmate_agi"
    })

@app.route('/check_device')
def check_device():
    user_agent = request.headers.get('User-Agent', '').lower()
    is_mobile = any(device in user_agent for device in [
        'android', 'iphone', 'ipad', 'mobile', 'blackberry', 
        'webos', 'windows phone', 'opera mini'
    ])
    return jsonify({
        "is_mobile": is_mobile,
        "user_agent": user_agent,
        "client_ip": request.remote_addr
    })

@app.route('/api/user/profile')
@login_required
def get_user_profile():
    username = session.get('username')
    profile = user_manager.get_user_profile(username)
    if profile:
        return jsonify(profile)
    return jsonify({"error": "User profile not found"}), 404

@app.route('/api/chat/history')
@login_required
def get_chat_history():
    """Get chat history for the current user"""
    username = session.get('username')
    if not username:
        return jsonify({"error": "User not authenticated"}), 401
    
    # Get chat history for the user
    history = memory_manager.get_chat_history(username)
    
    # Format history for the client
    formatted_history = []
    for message in history:
        formatted_message = {
            'content': message['content'],
            'timestamp': message['timestamp'],
            'is_user': message['is_user']
        }
        formatted_history.append(formatted_message)
    
    return jsonify(formatted_history)

@app.route('/api/chat/clear', methods=['POST'])
@login_required
def clear_chat_history():
    """Clear chat history for the current user"""
    username = session.get('username')
    if not username:
        return jsonify({"error": "User not authenticated"}), 401
    
    # Clear chat history
    success = memory_manager.delete_chat_history(username)
    
    if success:
        return jsonify({"status": "success"})
    else:
        return jsonify({"error": "Failed to clear chat history"}), 500

@socketio.on('message')
def handle_message(data):
    try:
        user_input = data.get('message', '')
        user_id = data.get('user_id', 'default_user')
        
        # Get username from session for chat history
        username = session.get('username')
        if not username:
            socketio.emit('error', {
                'message': 'Authentication required',
                'user_id': user_id
            })
            return
        
        logger.info(f"Received message from user {user_id}: {user_input}")
        
        # Store user message in chat history
        memory_manager.store_chat_message(username, user_input, True)
        
        # Process the message through the AI core
        response = ai_core.process_message(user_input, user_id)
        
        # Store AI response in chat history
        memory_manager.store_chat_message(username, response, False)
        
        # Log the response for debugging
        logger.info(f"Generated response for user {user_id}: {response}")
        
        # Emit the response back to the client
        # Make sure we're returning the response in a consistent format
        socketio.emit('response', {
            'message': response,
            'user_id': user_id
        })
    except Exception as e:
        logger.error(f"Error processing message: {str(e)}", exc_info=True)
        logger.error(f"Message data that caused the error: {data}")
        socketio.emit('error', {
            'message': f'An error occurred while processing your message: {str(e)}',
            'user_id': data.get('user_id', 'default_user')
        })

@socketio.on('load_history')
def handle_load_history():
    """Load chat history for the current user"""
    try:
        # Get username from session
        username = session.get('username')
        if not username:
            socketio.emit('error', {
                'message': 'Authentication required'
            })
            return
        
        # Get chat history for the user
        history = memory_manager.get_chat_history(username)
        
        # Emit history to the client
        socketio.emit('chat_history', {
            'history': history
        })
    except Exception as e:
        logger.error(f"Error loading chat history: {str(e)}", exc_info=True)
        socketio.emit('error', {
            'message': f'An error occurred while loading chat history: {str(e)}'
        })

@socketio.on('clear_history')
def handle_clear_history():
    """Clear chat history for the current user"""
    try:
        # Get username from session
        username = session.get('username')
        if not username:
            socketio.emit('error', {
                'message': 'Authentication required'
            })
            return
        
        # Clear chat history
        success = memory_manager.delete_chat_history(username)
        
        # Emit result to the client
        if success:
            socketio.emit('history_cleared')
        else:
            socketio.emit('error', {
                'message': 'Failed to clear chat history'
            })
    except Exception as e:
        logger.error(f"Error clearing chat history: {str(e)}", exc_info=True)
        socketio.emit('error', {
            'message': f'An error occurred while clearing chat history: {str(e)}'
        })

@socketio.on('audio')
def handle_audio(data):
    try:
        # Check authentication
        username = session.get('username')
        if not username:
            socketio.emit('error', {
                'message': 'Authentication required',
                'user_id': data.get('user_id', 'default_user')
            })
            return
        
        # Check if this is a voice message to be stored directly
        is_voice_message = data.get('is_voice_message', False)
        
        if is_voice_message:
            # Store the voice message directly
            user_id = data.get('user_id', 'default_user')
            audio_data = data.get('audio_data', '')
            
            # Store the audio message in chat history with special format
            memory_manager.store_voice_message(username, audio_data, True)
            
            # Create a response acknowledging the voice message
            response = {
                "response": "Voice message received",
                "type": "text",
                "metadata": {
                    "category": "voice_message_acknowledgment"
                }
            }
            
            # Store AI response in chat history
            memory_manager.store_chat_message(username, response["response"], False)
            
            # Send back confirmation
            socketio.emit('response', {
                'message': response,
                'user_id': user_id
            })
            
        else:
            # Process audio data through the AI core for speech recognition
            response = ai_core.process_audio(data)
            
            # If there's transcribed text, show it to the user
            transcribed_text = response.get('transcribed_text')
            if transcribed_text:
                # Emit the transcribed text
                socketio.emit('transcribed_text', {
                    'text': transcribed_text,
                    'user_id': data.get('user_id', 'default_user')
                })
                
                # Store the transcribed text in chat history as a user message
                memory_manager.store_chat_message(username, f"🎤 {transcribed_text}", True)
            
            # Store AI response in chat history
            response_text = "Audio processed"
            if isinstance(response.get('message'), dict) and 'response' in response.get('message', {}):
                response_text = response['message']['response']
            
            memory_manager.store_chat_message(username, response_text, False)
            
            # Emit the response back to the client
            socketio.emit('audio_response', response)
            
    except Exception as e:
        logger.error(f"Error processing audio: {str(e)}", exc_info=True)
        socketio.emit('error', {
            'message': 'An error occurred while processing your audio.',
            'user_id': data.get('user_id', 'default_user')
        })

@socketio.on('video')
def handle_video(data):
    try:
        # Check authentication
        username = session.get('username')
        if not username:
            socketio.emit('error', {
                'message': 'Authentication required',
                'user_id': data.get('user_id', 'default_user')
            })
            return
            
        # Process video data through the AI core
        response = ai_core.process_video(data)
        
        # Store AI response in chat history
        memory_manager.store_chat_message(username, response, False)
        
        # Emit the response back to the client
        socketio.emit('video_response', response)
    except Exception as e:
        logger.error(f"Error processing video: {str(e)}")
        socketio.emit('error', {
            'message': 'An error occurred while processing your video.',
            'user_id': data.get('user_id', 'default_user')
        })

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    logger.info(f"Starting SoulMate.AGI on port {port}")
    # Make sure the server is accessible from other devices, including via ngrok
    socketio.run(app, host='0.0.0.0', port=port, debug=False) 