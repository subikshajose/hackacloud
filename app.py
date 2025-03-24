import os
import time
import random
from functools import wraps
from flask import Flask, request, jsonify, render_template, redirect, url_for, send_from_directory
from pymongo import MongoClient
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from urllib.parse import quote_plus
from dotenv import load_dotenv
from bson.objectid import ObjectId
from datetime import datetime
from flask_cors import CORS
from flask_socketio import SocketIO
from flask_login import LoginManager, current_user, login_user, logout_user, login_required, UserMixin
from models.user import User
import shutil
import pathlib
import html

# Load environment variables
load_dotenv()
    
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Replace with a secure secret key

# Validate required environment variables
required_env_vars = [
    'MONGO_USERNAME', 'MONGO_PASSWORD', 'MONGO_HOST', 
    'MONGO_PORT', 'DATABASE_NAME', 'JWT_SECRET_KEY'
]

missing_vars = [var for var in required_env_vars if not os.getenv(var)]
if missing_vars:
    raise EnvironmentError(
        f"Missing required environment variables: {', '.join(missing_vars)}\n"
        "Please ensure all required variables are set in your .env file."
    )

# Configuration - use getenv with default values for non-sensitive configs
app.config.update(
    MONGO_USERNAME=os.getenv('MONGO_USERNAME'),
    MONGO_PASSWORD=os.getenv('MONGO_PASSWORD'),
    MONGO_HOST=os.getenv('MONGO_HOST'),
    MONGO_PORT=os.getenv('MONGO_PORT'),
    DATABASE_NAME=os.getenv('DATABASE_NAME'),
    JWT_SECRET_KEY=os.getenv('JWT_SECRET_KEY'),
    MONGO_OPTIONS={
        'ssl': True,
        'replicaSet': 'globaldb',
        'retryWrites': False,
        'directConnection': True
    }
)

# Secure the MongoDB connection string building
def build_mongo_uri():
    """Build MongoDB URI with proper escaping and validation"""
    try:
        username = quote_plus(app.config['MONGO_USERNAME'])
        password = quote_plus(app.config['MONGO_PASSWORD'])
        host = app.config['MONGO_HOST'].strip()
        port = app.config['MONGO_PORT']
        database = app.config['DATABASE_NAME'].strip('/')
        
        options = '&'.join(
            f"{k}={str(v).lower() if isinstance(v, bool) else v}"
            for k, v in app.config['MONGO_OPTIONS'].items()
        )
        
        return (
            f"mongodb://{username}:{password}@{host}:{port}/{database}"
            f"?{options}"
        )
    except Exception as e:
        print("Error building MongoDB URI. Check your environment variables.")
        raise

# Initialize MongoDB connection with error handling
try:
    mongo_uri = build_mongo_uri()
    mongo_client = MongoClient(
        mongo_uri,
        tlsAllowInvalidCertificates=True,
        retryWrites=False,
        retryReads=True,
        serverSelectionTimeoutMS=10000,
        maxPoolSize=50,
        waitQueueTimeoutMS=5000
    )
    db = mongo_client[app.config['DATABASE_NAME']]
    users_collection = db.users
    documents_collection = db.documents
    
    # Test connection
    mongo_client.server_info()
    print("Successfully connected to MongoDB!")
except Exception as e:
    print(f"Failed to connect to MongoDB: {str(e)}")
    raise

# Initialize Bcrypt and JWT
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Initialize SocketIO with simple-websocket
socketio = SocketIO(app, async_mode='threading', cors_allowed_origins="*", websocket=True)

# Initialize Flask-Login before other initializations
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    try:
        if not isinstance(user_id, str):
            return None
        user_data = users_collection.find_one({'_id': ObjectId(user_id)})
        if user_data:
            # Convert ObjectId to string for the id attribute
            user_data['_id'] = str(user_data['_id'])
            return User(user_data)
        return None
    except Exception as e:
        print(f"Error loading user: {str(e)}")
        return None

def retry_with_backoff(retries=5, backoff_in_seconds=1):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            x = 0
            while True:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    # Check if error is related to throughput
                    if "throughput limit" in str(e).lower():
                        if x == retries:
                            raise
                        wait = (backoff_in_seconds * 2 ** x + 
                               random.uniform(0, 1))
                        print(f"Throughput limit hit, retrying in {wait:.2f} seconds...")
                        time.sleep(wait)
                        x += 1
                    else:
                        raise
        return wrapper
    return decorator

# Define the base directory for storing user files
USER_FILES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'user_files')
# Create the directory if it doesn't exist
os.makedirs(USER_FILES_DIR, exist_ok=True)

# Helper function to create user directory
def ensure_user_directory(user_id):
    """Create user directory if it doesn't exist and return the path"""
    user_dir = os.path.join(USER_FILES_DIR, str(user_id))
    os.makedirs(user_dir, exist_ok=True)
    return user_dir

# User Registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    
    try:
        data = request.get_json()
        if not data or not data.get('email') or not data.get('password'):
            return jsonify({"error": "Email and password are required"}), 400

        # Check if user already exists
        if users_collection.find_one({"email": data['email'].lower()}):
            return jsonify({"error": "User already exists"}), 400

        # Hash the password
        hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
        
        # Prepare user document
        new_user = {
            "email": data['email'].lower(),
            "password": hashed_password,
            "first_name": data.get('first_name', ''),
            "last_name": data.get('last_name', ''),
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
            "last_login": None,
            "role": "user"
        }
        
        # Insert the new user
        result = users_collection.insert_one(new_user)
        
        # Check if insertion was successful
        if result.inserted_id:
            print(f"User registered successfully: {data['email']}")
            return jsonify({
                "message": "User registered successfully!",
                "user_id": str(result.inserted_id)
            }), 201
        else:
            return jsonify({"error": "Failed to register user"}), 500
            
    except Exception as e:
        print(f"Registration error: {str(e)}")
        return jsonify({"error": "An error occurred during registration"}), 500

# User Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    
    try:
        data = request.get_json() if request.is_json else request.form
        email = data.get('email', '').lower().strip()
        password = data.get('password', '')

        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400

        user_data = users_collection.find_one({'email': email})
        if not user_data:
            return jsonify({'error': 'Invalid email address'}), 401

        if bcrypt.check_password_hash(user_data['password'], password):
            # Convert ObjectId to string for the User model
            user_data['_id'] = str(user_data['_id'])
            user = User(user_data)
            login_user(user, remember=True)
            
            # Create JWT token
            access_token = create_access_token(identity=user_data['_id'])
            
            response = jsonify({
                'token': access_token,
                'user_id': user_data['_id'],
                'redirect': '/home'  # Changed from '/dashboard' to '/home'
            })
            
            # Set secure cookie with JWT
            response.set_cookie(
                'access_token',
                access_token,
                httponly=True,
                secure=True,
                samesite='Strict',
                max_age=3600  # 1 hour
            )
            
            return response, 200
        
        return jsonify({'error': 'Invalid password'}), 401

    except Exception as e:
        print(f"Login error: {str(e)}")
        return jsonify({'error': 'An error occurred during login'}), 500

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        # Fetch all documents created by the current user
        documents = list(documents_collection.find({
            'owner_id': str(current_user.id)
        }).sort('updated_at', -1))  # Sort by last updated

        return render_template(
            'dashboard.html',
            documents=documents,
            user={'id': current_user.id, 'email': current_user.email}
        )
    except Exception as e:
        print(f"Dashboard error: {str(e)}")
        return redirect(url_for('home'))

@app.route('/editor/<document_id>')
@jwt_required()
def editor(document_id):
    try:
        # Get JWT identity to verify authentication
        user_id = get_jwt_identity()
        if not user_id:
            return redirect(url_for('login'))
            
        document = documents_collection.find_one({'_id': ObjectId(document_id)})
        if not document:
            return jsonify({"error": "Document not found"}), 404
            
        # Add success message to template context
        return render_template('editor.html', 
                              document=document, 
                              just_created=request.args.get('new', False))
    except Exception as e:
        return jsonify({"error": "Invalid document ID"}), 400

# WebSocket events for real-time collaboration
@socketio.on('connect')
def handle_connect():
    print('Client connected')

@socketio.on('join')
def handle_join(data):
    room = data['document_id']
    socketio.join_room(room)

@socketio.on('edit')
@retry_with_backoff(retries=3)
def handle_edit(data):
    try:
        document_id = data['document_id']
        content = data['content']
        version = data.get('version', 1)
        user_id = get_jwt_identity()
        
        # Update the main document first
        result = documents_collection.update_one(
            {'_id': ObjectId(document_id)},
            {
                '$set': {
                    'content': content,
                    'version': version,
                    'updated_at': datetime.utcnow()
                }
            },
            upsert=False
        )
        
        if result.modified_count > 0:
            # Only save version history if main document update succeeds
            version_data = {
                'document_id': document_id,
                'content': content,
                'version': version,
                'user_id': user_id,
                'timestamp': datetime.utcnow()
            }
            db.document_versions.insert_one(version_data)
            
            # Broadcast the changes to all users in the room
            socketio.emit('update', data, room=document_id, skip_sid=request.sid)
    except Exception as e:
        print(f"Error in handle_edit: {str(e)}")
        socketio.emit('error', {
            'message': 'Failed to save changes. Please try again.'
        }, room=request.sid)

# Create Document
@app.route('/documents', methods=['POST'])
@jwt_required()
@retry_with_backoff(retries=7)  # Increased retries further
def create_document():
    try:
        data = request.get_json()
        if not data or not data.get('title'):
            return jsonify({"error": "Title is required"}), 400

        # Get document file type/extension (default to txt if not specified)
        file_type = data.get('file_type', 'txt').lower().strip()
        
        # Validate file type
        allowed_types = ['txt', 'md', 'html', 'css', 'js', 'py', 'java', 'c', 'cpp', 'json', 'xml', 'csv']
        if file_type not in allowed_types:
            file_type = 'txt'  # Default to txt for unrecognized types
        
        # Add file extension to title if not already present
        title = data.get('title')
        if not title.lower().endswith('.' + file_type):
            title = f"{title}.{file_type}"

        # Get the current authenticated user ID
        user_id = get_jwt_identity()
        if not user_id:
            return jsonify({"error": "Authentication required"}), 401

        new_document = {
            "title": title,
            "file_type": file_type,
            "content": data.get("content", ""),
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
            "version": 1,
            "owner_id": user_id
        }
        
        # Add document to database
        result = documents_collection.insert_one(new_document)
        document_id = str(result.inserted_id)
        
        # Save the document to the local file system in user's directory
        user_dir = ensure_user_directory(user_id)
        file_path = os.path.join(user_dir, f"{document_id}.{file_type}")
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(data.get("content", ""))
        
        # Update the document in database with local file path
        documents_collection.update_one(
            {"_id": ObjectId(document_id)},
            {"$set": {"local_path": file_path}}
        )
            
        return jsonify({
            "message": "Document created successfully!",
            "document_id": document_id,
            "file_path": file_path
        }), 201
    except Exception as e:
        error_msg = str(e)
        if "throughput limit" in error_msg.lower():
            return jsonify({
                "error": "Server is busy. Please try again in a few moments.",
                "details": "Database throughput limit reached",
                "retry": True
            }), 429
        print(f"Error creating document: {error_msg}")
        return jsonify({
            "error": "Failed to create document. Please try again later.",
            "details": error_msg if app.debug else None
        }), 500

# Get All Documents
@app.route('/documents', methods=['GET'])
@jwt_required()
def get_documents():
    documents = documents_collection.find()
    result = [{
        "id": str(doc["_id"]),
        "title": doc["title"],
        "content": doc["content"],
        "version": doc.get("version", 1),
        "updated_at": doc.get("updated_at", datetime.utcnow())
    } for doc in documents]
    return jsonify(result)

# Get Single Document
@app.route('/documents/<doc_id>', methods=['GET'])
@jwt_required()
def get_document(doc_id):
    try:
        document = documents_collection.find_one({"_id": ObjectId(doc_id)})
        if not document:
            return jsonify({"error": "Document not found"}), 404
        
        return jsonify({
            "id": str(document["_id"]),
            "title": document["title"],
            "content": document["content"],
            "version": document.get("version", 1),
            "updated_at": document.get("updated_at", datetime.utcnow())
        })
    except Exception as e:
        return jsonify({"error": "Invalid document ID"}), 400

# Update Document
@app.route('/documents/<doc_id>', methods=['PUT'])
@jwt_required()
def update_document(doc_id):
    try:
        data = request.get_json()
        if not data or not data.get('content'):
            return jsonify({"error": "Content is required"}), 400

        document = documents_collection.find_one({"_id": ObjectId(doc_id)})
        if not document:
            return jsonify({"error": "Document not found"}), 404

        # Update document in database
        updated_document = {
            "$set": {
                "content": data["content"],
                "updated_at": datetime.utcnow(),
                "version": document.get("version", 1) + 1
            }
        }
        
        documents_collection.update_one({"_id": ObjectId(doc_id)}, updated_document)
        
        # Update the file on the local file system if it exists
        user_id = get_jwt_identity()
        file_type = document.get('file_type', 'txt')
        user_dir = ensure_user_directory(user_id)
        file_path = os.path.join(user_dir, f"{doc_id}.{file_type}")
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(data["content"])
            
        return jsonify({
            "message": "Document updated successfully!",
            "file_path": file_path
        })
    except Exception as e:
        return jsonify({"error": f"Failed to update document: {str(e)}"}), 400

# Delete Document
@app.route('/documents/<doc_id>', methods=['DELETE'])
@jwt_required()
def delete_document(doc_id):
    try:
        result = documents_collection.delete_one({"_id": ObjectId(doc_id)})
        if result.deleted_count == 0:
            return jsonify({"error": "Document not found"}), 404
        return jsonify({"message": "Document deleted successfully!"})
    except Exception as e:
        return jsonify({"error": "Invalid document ID"}), 400

@app.route('/')
def index():
    return render_template('index.html', current_user=current_user)

@app.route('/home')
@login_required
def home():
    try:
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        
        # Get user's recent documents (limit to 5)
        documents = list(documents_collection.find({
            '$or': [
                {'owner_id': str(current_user.id)},
                {'shared_with': str(current_user.id)}
            ]
        }).sort('updated_at', -1).limit(5))
        
        return render_template(
            'home.html',
            documents=documents
        )
    except Exception as e:
        print(f"Home page error: {str(e)}")
        return redirect(url_for('login'))

@app.route('/myprofile')
@login_required
def myprofile():
    try:
        user_data = {
            "first_name": current_user.first_name,
            "last_name": current_user.last_name,
            "email": current_user.email,
            "role": current_user.role,
            "created_at": current_user.created_at
        }
        return render_template('myprofile.html', user=user_data)
    except Exception as e:
        print(f"Error loading profile: {str(e)}")
        return redirect(url_for('home'))

@socketio.on('save_version')
def handle_version(data):
    try:
        document_id = data.get('document_id')
        version_data = {
            'document_id': document_id,
            'version': data.get('version'),
            'content': data.get('content'),
            'timestamp': datetime.utcnow(),
            'user_id': data.get('user_id')
        }
        db.document_versions.insert_one(version_data)
        socketio.emit('update_canvas', data, broadcast=True)
    except Exception as e:
        print(f"Error in handle_version: {str(e)}")

# Route to serve a user's file
@app.route('/user_files/<user_id>/<filename>')
@login_required
def user_file(user_id, filename):
    if str(current_user.id) != user_id:
        return jsonify({"error": "Unauthorized access"}), 403
    return send_from_directory(os.path.join(USER_FILES_DIR, user_id), filename)

# Route to get all local files for a user
@app.route('/local_files')
@login_required
def get_local_files():
    try:
        user_id = current_user.id
        user_dir = ensure_user_directory(user_id)
        
        files = []
        for file in os.listdir(user_dir):
            file_path = os.path.join(user_dir, file)
            if os.path.isfile(file_path):
                # Extract document ID from filename
                doc_id = os.path.splitext(file)[0]
                # Get document info from database if available
                doc_info = documents_collection.find_one({"_id": ObjectId(doc_id)})
                
                if doc_info:
                    files.append({
                        "id": doc_id,
                        "title": doc_info.get("title", file),
                        "file_type": doc_info.get("file_type", os.path.splitext(file)[1][1:]),
                        "updated_at": doc_info.get("updated_at", datetime.fromtimestamp(os.path.getmtime(file_path))),
                        "local_path": file_path
                    })
                else:
                    # File exists but not in database
                    files.append({
                        "id": doc_id,
                        "title": file,
                        "file_type": os.path.splitext(file)[1][1:],
                        "updated_at": datetime.fromtimestamp(os.path.getmtime(file_path)),
                        "local_path": file_path
                    })
        
        return jsonify({"files": files})
    except Exception as e:
        return jsonify({"error": f"Failed to get local files: {str(e)}"}), 500

# Route for editing locally stored files
@app.route('/local_editor/<doc_id>')
@login_required
def local_editor(doc_id):
    try:
        # Get the document from the database
        document = documents_collection.find_one({"_id": ObjectId(doc_id)})
        
        if not document:
            # Try to find the file locally
            user_id = current_user.id
            user_dir = ensure_user_directory(user_id)
            
            # Look for any file starting with the document ID
            for file in os.listdir(user_dir):
                if file.startswith(doc_id):
                    file_path = os.path.join(user_dir, file)
                    file_type = os.path.splitext(file)[1][1:]
                    
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    return render_template(
                        'local_editor.html',
                        document={
                            "_id": doc_id,
                            "title": file,
                            "content": content,
                            "file_type": file_type
                        }
                    )
            
            return jsonify({"error": "Document not found"}), 404
        
        # Document exists in database, check if it exists locally
        user_id = current_user.id
        file_type = document.get('file_type', 'txt')
        user_dir = ensure_user_directory(user_id)
        file_path = os.path.join(user_dir, f"{doc_id}.{file_type}")
        
        # If the file doesn't exist locally, create it
        if not os.path.exists(file_path):
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(document.get('content', ''))
        
        # Read the local file content
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Update document with local content if different
        if content != document.get('content', ''):
            documents_collection.update_one(
                {"_id": ObjectId(doc_id)},
                {"$set": {"content": content}}
            )
        
        return render_template('local_editor.html', document=document)
    except Exception as e:
        return jsonify({"error": f"Error loading document: {str(e)}"}), 500

# Error Handler for 404
@app.errorhandler(404)
def not_found_error(error):
    return jsonify({"error": "The requested URL was not found on the server."}), 404

if __name__ == '__main__':
    # Create simple indexes without partial filter expression
    try:
        existing_indexes = users_collection.list_indexes()
        has_email_index = any(
            'email' in idx.get('key', {}) 
            for idx in existing_indexes
        )
        
        if not has_email_index:
            users_collection.create_index("email", unique=True)
            
        print("Indexes configured successfully!")
    except Exception as e:
        print(f"Warning: Could not create indexes - {str(e)}")
        print("Application will continue without indexes")

    # Run with threading mode
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True, host='0.0.0.0', port=5000)
