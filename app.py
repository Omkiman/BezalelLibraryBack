from functools import wraps
import logging
import os
from flask import Flask, current_app, request, jsonify
from models import db, User, Book, Borrows
from datetime import datetime, timedelta, timezone
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from flask_cors import CORS

app = Flask(__name__)

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///library.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'Honholulu1992'  # Change this to a random secret key for session management

db.init_app(app)
CORS(app)

# Initialize database
with app.app_context():
    db.create_all()

# Set up logging
logging.basicConfig(filename='library.log',
                    level=logging.INFO,  # Logs info, warning, error, critical
                    format='%(asctime)s - %(levelname)s - %(message)s')

logger = logging.getLogger(__name__)

app.config['SECRET_KEY'] = 'dfdf6546daf65a'

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    
    # Check if user with the same email already exists
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'message': 'Details already exists'}), 400
    
    # Check if user with the same username already exists
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'message': 'Details already exists'}), 400
    
    # Hash the password before storing it
    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    
    # Create a new user
    is_adm = data.get('is_admin', False)
    new_user = User(username=data['username'], password=hashed_password, name=data['name'], email=data['email'], is_admin=is_adm)
    db.session.add(new_user)
    db.session.commit()
    
    logger.info(f"New user registered: {new_user.name}, {new_user.email}")
    return jsonify({'message': 'User registered successfully'}), 201

# User login route
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(email=data['email']).first()
    if user and check_password_hash(user.password, data['password']):  # Check hashed password
        # Generate JWT token
        token = jwt.encode({
            'exp': datetime.now(timezone.utc) + timedelta(hours=100),
            'user_id': user.id,
            'username': user.username,
            'name': user.name,
            'is_admin': user.is_admin
        }, current_app.config['SECRET_KEY'], algorithm='HS256')

        return jsonify({'message': 'Login successful', 'token': token}), 200
    return jsonify({'message': 'Invalid credentials'}), 401

def fix_jwt_padding(token):
    padding = len(token) % 4
    if padding:
        token += '=' * (4 - padding)
    return token

# Middleware to verify JWT
def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token or not token.startswith('Bearer '):
            return jsonify({'message': 'Token is missing!'}), 401
        
        token = token.split(" ")[1]
        token = fix_jwt_padding(token)  # Fix padding if necessary
        try:
            data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = db.session.get(User, data['user_id'])
            if not current_user:
                return jsonify({'message': 'User not found!'}), 404
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid!'}), 401
        kwargs['current_user'] = current_user
        return f(*args, **kwargs)
    return decorated_function

# Middleware to verify admin access
def admin_required(f):
    @wraps(f)
    @token_required
    def decorated_function(*args, **kwargs):
        if not kwargs['current_user'].is_admin:
            return jsonify({'message': 'Admin access required!'}), 403
        return f(*args, **kwargs)
    return decorated_function



# Read all users (Admin access required)
@app.route('/users', methods=['GET'])
@admin_required
def get_users(**kwargs):
    users = User.query.all()
    logger.info('Fetched all users')
    return jsonify([{'id': user.id, 'username': user.username, 'email': user.email, 'active': user.active, 'name':user.name, 'is_admin':user.is_admin} for user in users])


# Read a single user by ID (Admin access required)
@app.route('/users/<int:user_id>', methods=['GET'])
@admin_required
def get_user(user_id, **kwargs):
    user = User.query.get_or_404(user_id)
    logger.info(f'Fetched user details: {user.username}')
    return jsonify({'id': user.id, 'username': user.username, 'email': user.email, 'active': user.active, 'name':user.name, 'is_admin':user.is_admin})


# Update a user (Admin access required)
@app.route('/users/<int:user_id>', methods=['PUT'])
@admin_required
def update_user(user_id, **kwargs):
    user = User.query.get_or_404(user_id)
    
    data = request.json
    user.username = data.get('username', user.username)
    user.email = data.get('email', user.email)
    user.name = data.get('name', user.name)
    user.password = generate_password_hash(data.get('password', user.password), method='pbkdf2:sha256')
    user.is_admin = data.get('is_admin', user.is_admin)  # Allow admin updates
    user.active = data.get('active', user.active)
    
    db.session.commit()
    logger.info(f'User updated: {user.username}')
    return jsonify({'message': 'User updated successfully'})


# Make a user inactive (Soft Delete) - Admin access required
@app.route('/users/<int:user_id>/deactivate', methods=['PUT'])
@admin_required
def deactivate_user(user_id, **kwargs):
    user = User.query.get_or_404(user_id)
    
    if not user.active:
        return jsonify({'message': 'User is already inactive'}), 400

    user.active = False  # Soft delete by making the user inactive
    db.session.commit()
    
    logger.info(f'User marked as inactive: {user.username}')
    return jsonify({'message': 'User deactivated successfully'})


# Reactivate a user (Admin access required)
@app.route('/users/<int:user_id>/reactivate', methods=['PUT'])
@admin_required
def reactivate_user(user_id, **kwargs):
    user = User.query.get_or_404(user_id)
    
    if user.active:
        return jsonify({'message': 'User is already active'}), 400

    user.active = True  # Reactivate the user
    db.session.commit()
    
    logger.info(f'User reactivated: {user.username}')
    return jsonify({'message': 'User reactivated successfully'})

# CRUD Operations for Books
@app.route('/getbooks', methods=['GET'])
def getbooks():
        books = Book.query.all()
        logger.info('Fetched all books.')
        return jsonify([{'year':book.year, 'id': book.id, 'title': book.title, 'author': book.author, 'available': book.available, 'genre': book.genre, 'photo_url': book.photo_url } for book in books])

@app.route('/getbooks/<int:book_id>', methods=['GET'])
def single_book_free(book_id):
    book = Book.query.get_or_404(book_id)
    logger.info(f"Fetched book details: {book.title}")
    return jsonify({'year':book.year, 'id': book.id, 'title': book.title, 'author': book.author, 'available': book.available, 'genre': book.genre, 'photo_url': book.photo_url })

@app.route('/books', methods=['GET', 'POST'])
@admin_required
def books(current_user):
    if request.method == 'GET':
        books = Book.query.all()
        logger.info('Fetched all books.')
        return jsonify([{'id': book.id, 'title': book.title, 'author': book.author, 'available': book.available, 'year':book.year} for book in books])
    
    if request.method == 'POST':
        data = request.json
        new_book = Book(title=data['title'], author=data['author'], genre=data['genre'], year=data['year'], available=True, photo_url =data['photo_url'])
        db.session.add(new_book)
        db.session.commit()
        logger.info(f"New book added: {new_book.title} by {new_book.author}")
        return jsonify({'message': 'Book added successfully'}), 201

@app.route('/books/<int:book_id>', methods=['GET', 'PUT', 'DELETE'])
@admin_required
def single_book(current_user, book_id):
    book = Book.query.get_or_404(book_id)

    if request.method == 'GET':
        logger.info(f"Fetched book details: {book.title}")
        return jsonify({'id': book.id, 'title': book.title, 'author': book.author, 'available': book.available, 'photo_url':book.photo_url, 'genre':book.genre, 'year':book.year})

    if request.method == 'PUT':
        data = request.json
        book.title = data.get('title', book.title)
        book.author = data.get('author', book.author)
        book.available = data.get('available', book.available)
        book.year = data.get('year', book.year)
        book.genre = data.get('genre', book.genre)
        book.photo_url = data.get('photo_url', book.photo_url)
        db.session.commit()
        logger.info(f"Book updated: {book.title}")
        return jsonify({'message': 'Book updated successfully'})

    if request.method == 'DELETE':
        if not current_user.is_admin:
            return jsonify({'message': 'Admin access required!'}), 403

        logger.warning(f"Book deleted: {book.title}")
        db.session.delete(book)
        db.session.commit()
        return jsonify({'message': 'Book deleted successfully'})

@app.route('/search', methods=['POST'])
def search_books():
    data = request.json
    search_type = data.get('type')
    search_query = data.get('query')
    if not search_type or not search_query:
        return jsonify({'message': 'Search type and query are required!'}), 400

    if search_type == 'title':
        books = Book.query.filter(Book.title.ilike(f'%{search_query}%')).all()
    elif search_type == 'author':
        books = Book.query.filter(Book.author.ilike(f'%{search_query}%')).all()
    elif search_type == 'year':
        books = Book.query.filter(Book.year == search_query).all()
    elif search_type == 'genre':
        books = Book.query.filter(Book.genre.ilike(f'%{search_query}%')).all()
    else:
        return jsonify({'message': 'Invalid search type!'}), 400

    logger.info(f'Searching books by {search_type}: {search_query}')
    return jsonify([{'id': book.id, 'title': book.title, 'author': book.author, 'genre': book.genre, 'available': book.available, 'year':book.year, 'photo_url':book.photo_url} for book in books])



# Read all Borrows 
@app.route('/borrows', methods=['GET'])
def get_borrows():
    borrows = Borrows.query.all()
    logger.info('Fetched all borrows')
    return jsonify([{'id': borrow.id, 'user_id':borrow.user_id, 'book_id':borrow.book_id, 'username': borrow.user.name, 'title': borrow.book.title, 'borrowed_at': borrow.borrowed_at, 'returned_at': borrow.returned_at} for borrow in borrows])

# Borrow and Return Books
@app.route('/borrows', methods=['POST'])
@token_required
def borrow_book(current_user):
    data = request.json
    book_id = data['id']

    book = Book.query.get_or_404(book_id)
    if not book.available:
        logger.error(f"Book not available for borrowing: {book.title}")
        return jsonify({'message': 'Book is not available for borrowing'}), 400

    new_borrow = Borrows(user_id=current_user.id, book_id=book_id)
    book.available = False
    db.session.add(new_borrow)
    db.session.commit()
    logger.info(f"Book borrowed: {book.title} by user ID {current_user.id}")
    return jsonify({'message': 'Book borrowed successfully'})

@app.route('/returns/<int:borrow_id>', methods=['PUT'])
@token_required
def return_book(current_user, borrow_id):
    borrow = Borrows.query.get_or_404(borrow_id)
    if borrow.returned_at is not None:
        logger.warning(f"Book already returned: {borrow.book.title}")
        return jsonify({'message': 'Book has already been returned'}), 400
    book = Book.query.get(borrow.book_id)
    borrow.returned_at = datetime.now(timezone.utc)
    book.available = True
    db.session.commit()
    logger.info(f"Book returned: {borrow.book.title} by user ID {borrow.user_id}")
    return jsonify({'message': 'Book returned successfully'})

if __name__ == '__main__':
    app.run(debug=True)
