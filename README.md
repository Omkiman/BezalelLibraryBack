# Flask Library Application

This is a library management system built with Flask. It provides functionality for user registration, login, borrowing and returning books, and administration of users and books. It uses JWT for authentication, and the application is designed with full CRUD operations for books, borrows, and users.

## Features

- **User Registration and Login**: 
  - Users can register with a unique email and username.
  - Passwords are securely hashed using PBKDF2.
  - Users can log in and receive a JWT token for authentication.

- **JWT Authentication**: 
  - JWT is used to secure endpoints and ensure only authenticated users can perform certain actions.
  - Admin-specific actions are protected with additional role-based access control.

- **CRUD Operations**:
  - **Users**: Admins can create, read, update, deactivate, and reactivate users.
  - **Books**: Admins can add, edit, delete, and view books.
  - **Borrows**: Users can borrow and return books, with admin access required to view all borrows.

- **Book Search**: 
  - Books can be searched by title, author, year, or genre.

- **Activity Logging**: 
  - Application activities such as user registration, book borrow/return, and admin actions are logged to a `library.log` file.

## Requirements

The following packages are required to run the application:

astroid==3.3.4  
blinker==1.8.2  
click==8.1.7  
colorama==0.4.6  
dill==0.3.9  
Flask==3.0.3  
Flask-Cors==5.0.0  
Flask-SQLAlchemy==3.1.1  
greenlet==3.1.1  
isort==5.13.2  
itsdangerous==2.2.0  
Jinja2==3.1.4  
MarkupSafe==2.1.5  
mccabe==0.7.0  
platformdirs==4.3.6  
PyJWT==2.9.0  
setuptools==75.1.0  
SQLAlchemy==2.0.35  
tomlkit==0.13.2  
typing_extensions==4.12.2  
Werkzeug==3.0.4  


## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/your-repo/library-app.git
    cd library-app
    ```

2. Set up a virtual environment and install the dependencies:
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    ```

3. Initialize the SQLite database:
    ```bash
    flask shell
    >>> from models import db
    >>> db.create_all()
    >>> exit()
    ```

4. Run the Flask application:
    ```bash
    flask run
    ```

## Endpoints

### User Endpoints
- **POST** `/register`: Register a new user.
- **POST** `/login`: Login and receive a JWT token.
- **GET** `/users`: Get all users (Admin only).
- **GET** `/users/<int:user_id>`: Get a single user by ID (Admin only).
- **PUT** `/users/<int:user_id>`: Update a user's details (Admin only).
- **PUT** `/users/<int:user_id>/deactivate`: Deactivate a user (Admin only).
- **PUT** `/users/<int:user_id>/reactivate`: Reactivate a user (Admin only).

### Book Endpoints
- **GET** `/books`: Get all books.
- **POST** `/books`: Add a new book (Admin only).
- **GET** `/books/<int:book_id>`: Get details of a single book.
- **PUT** `/books/<int:book_id>`: Update book details (Admin only).
- **DELETE** `/books/<int:book_id>`: Delete a book (Admin only).

### Borrow Endpoints
- **GET** `/borrows`: Get all borrowed books.
- **POST** `/borrows`: Borrow a book (Login required).
- **PUT** `/returns/<int:borrow_id>`: Return a borrowed book (Login required).

### Search Endpoint
- **POST** `/search`: Search for books by title, author, year, or genre.

## Environment Variables

- `SECRET_KEY`: Secret key for JWT encoding and session management.
- `SQLALCHEMY_DATABASE_URI`: Database URI, set to `sqlite:///library.db` by default.

## Logging

Logs are written to `library.log` with information, warnings, and error messages. This includes actions like user registration, book borrowing, and admin actions.

