# app.py
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
from werkzeug.utils import secure_filename
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
import os
import sqlite3
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['DATABASE'] = 'database.db'
app.config['ALLOWED_EXTENSIONS'] = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx'}

# Khởi tạo database
def init_db():
    with sqlite3.connect(app.config['DATABASE']) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                public_key TEXT,
                private_key TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                filepath TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                signature TEXT,
                upload_date DATETIME,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        conn.commit()

# Hàm tiện ích
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    # Serialize keys
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return pem_private.decode('utf-8'), pem_public.decode('utf-8')

def sign_file(private_key_pem, file_path):
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode('utf-8'),
        password=None,
        backend=default_backend()
    )
    
    with open(file_path, 'rb') as f:
        file_data = f.read()
    
    signature = private_key.sign(
        file_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    return signature.hex()

def verify_signature(public_key_pem, file_path, signature_hex):
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode('utf-8'),
        backend=default_backend()
    )
    
    with open(file_path, 'rb') as f:
        file_data = f.read()
    
    signature = bytes.fromhex(signature_hex)
    
    try:
        public_key.verify(
            signature,
            file_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Verification failed: {e}")
        return False

# Routes
@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Generate RSA keys
        private_key, public_key = generate_rsa_keys()
        
        try:
            with sqlite3.connect(app.config['DATABASE']) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    'INSERT INTO users (username, password, public_key, private_key) VALUES (?, ?, ?, ?)',
                    (username, password, public_key, private_key)
                )
                conn.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists!', 'danger')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        with sqlite3.connect(app.config['DATABASE']) as conn:
            cursor = conn.cursor()
            cursor.execute(
                'SELECT id, username FROM users WHERE username = ? AND password = ?',
                (username, password)
            )
            user = cursor.fetchone()
        
        if user:
            session['user_id'] = user[0]
            session['username'] = user[1]
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password!', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected!', 'danger')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected!', 'danger')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            file.save(filepath)
            
            with sqlite3.connect(app.config['DATABASE']) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    'SELECT private_key FROM users WHERE id = ?',
                    (session['user_id'],)
                )
                private_key = cursor.fetchone()[0]
            
            signature = sign_file(private_key, filepath)
            
            with sqlite3.connect(app.config['DATABASE']) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    'INSERT INTO files (filename, filepath, user_id, signature, upload_date) VALUES (?, ?, ?, ?, ?)',
                    (filename, filepath, session['user_id'], signature, datetime.now())
                )
                conn.commit()
            
            flash('File uploaded and signed successfully!', 'success')
            return redirect(url_for('list_files'))
    
    return render_template('upload.html', 
                         allowed_extensions=app.config['ALLOWED_EXTENSIONS'])

@app.route('/files')
def list_files():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    with sqlite3.connect(app.config['DATABASE']) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT f.id, f.filename, f.upload_date, u.username 
            FROM files f
            JOIN users u ON f.user_id = u.id
            ORDER BY f.upload_date DESC
        ''')
        files = cursor.fetchall()
    
    return render_template('files.html', files=files)

@app.route('/download/<int:file_id>')
def download_file(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    with sqlite3.connect(app.config['DATABASE']) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT f.filename, f.filepath, f.signature, u.public_key 
            FROM files f
            JOIN users u ON f.user_id = u.id
            WHERE f.id = ?
        ''', (file_id,))
        file_info = cursor.fetchone()
    
    if not file_info:
        flash('File not found!', 'danger')
        return redirect(url_for('list_files'))
    
    filename, filepath, signature, public_key = file_info
    
    # Verify signature
    is_valid = verify_signature(public_key, filepath, signature)
    
    if is_valid:
        return send_from_directory(
            directory=os.path.dirname(filepath),
            path=os.path.basename(filepath),
            as_attachment=True,
            download_name=filename
        )
    else:
        flash('File signature verification failed! File may have been tampered with.', 'danger')
        return redirect(url_for('list_files'))

if __name__ == '__main__':
    init_db()
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.run(debug=True)