# vulnerable-app/app.py
from flask import Flask, request, render_template_string, redirect, url_for, session, make_response, send_file
import sqlite3
import os
import hashlib
import subprocess
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'vulnerable_secret_key_123'  # Deliberately weak secret key

# Create uploads directory
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def init_db():
    """Initialize the vulnerable database"""
    conn = sqlite3.connect('vulnerable.db')
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            role TEXT DEFAULT 'user'
        )
    ''')
    
    # Posts table for XSS testing
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            author TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Files table for file upload testing
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            original_name TEXT NOT NULL,
            uploaded_by TEXT NOT NULL,
            upload_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Insert default users (vulnerable to SQL injection)
    try:
        cursor.execute("INSERT INTO users (username, password, email, role) VALUES ('admin', 'admin123', 'admin@vulnerable.com', 'admin')")
        cursor.execute("INSERT INTO users (username, password, email, role) VALUES ('user', 'password', 'user@vulnerable.com', 'user')")
        cursor.execute("INSERT INTO users (username, password, email, role) VALUES ('test', 'test123', 'test@vulnerable.com', 'user')")
    except sqlite3.IntegrityError:
        pass  # Users already exist
    
    # Insert sample posts
    try:
        cursor.execute("INSERT INTO posts (title, content, author) VALUES ('Welcome Post', 'This is a sample post for testing.', 'admin')")
        cursor.execute("INSERT INTO posts (title, content, author) VALUES ('Test Post', 'Another test post with some content.', 'user')")
    except:
        pass
    
    conn.commit()
    conn.close()

# Initialize database on startup
init_db()

@app.route('/')
def home():
    """Main page with links to vulnerable endpoints"""
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Vulnerable Test Application</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }
            .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            h1 { color: #d32f2f; text-align: center; }
            .warning { background: #ffebee; border: 1px solid #e57373; padding: 15px; border-radius: 4px; margin-bottom: 20px; }
            .vulnerability { margin: 15px 0; padding: 15px; background: #fff3e0; border-left: 4px solid #ff9800; }
            .vulnerability h3 { color: #e65100; margin-top: 0; }
            a { color: #1976d2; text-decoration: none; }
            a:hover { text-decoration: underline; }
            .nav { background: #424242; padding: 15px; margin: -30px -30px 30px -30px; border-radius: 8px 8px 0 0; }
            .nav a { color: white; margin-right: 20px; padding: 8px 12px; background: #616161; border-radius: 4px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="nav">
                <a href="/">Home</a>
                <a href="/login">Login</a>
                <a href="/search">Search</a>
                <a href="/profile">Profile</a>
                <a href="/upload">Upload</a>
                <a href="/posts">Posts</a>
            </div>
            
            <h1>🚨 Vulnerable Test Application</h1>
            
            <div class="warning">
                <strong>⚠️ WARNING:</strong> This application is intentionally vulnerable and should only be used in isolated testing environments. 
                Never deploy this to a production server or expose it to the internet.
            </div>
            
            <h2>Available Vulnerabilities for Testing:</h2>
            
            <div class="vulnerability">
                <h3>SQL Injection</h3>
                <p>Test SQL injection attacks on the login form and search functionality.</p>
                <ul>
                    <li><a href="/login">Login Form</a> - Try: admin' OR '1'='1' --</li>
                    <li><a href="/search">Search</a> - Try: ' UNION SELECT username,password,1 FROM users --</li>
                    <li><a href="/user?id=1">User Profile</a> - Try: /user?id=1' OR '1'='1</li>
                </ul>
            </div>
            
            <div class="vulnerability">
                <h3>Cross-Site Scripting (XSS)</h3>
                <p>Test XSS attacks through various input methods.</p>
                <ul>
                    <li><a href="/search">Search Box</a> - Try: &lt;script&gt;alert('XSS')&lt;/script&gt;</li>
                    <li><a href="/posts">Comment System</a> - Try: &lt;img src=x onerror=alert('XSS')&gt;</li>
                    <li><a href="/profile">Profile Update</a> - Try: &lt;svg onload=alert('XSS')&gt;</li>
                </ul>
            </div>
            
            <div class="vulnerability">
                <h3>Directory Traversal</h3>
                <p>Test path traversal attacks to access system files.</p>
                <ul>
                    <li><a href="/file?name=test.txt">File Access</a> - Try: /file?name=../../../etc/passwd</li>
                    <li><a href="/download?file=sample.pdf">Download</a> - Try: /download?file=../../../../etc/hosts</li>
                </ul>
            </div>
            
            <div class="vulnerability">
                <h3>File Upload</h3>
                <p>Test malicious file upload vulnerabilities.</p>
                <ul>
                    <li><a href="/upload">File Upload</a> - Try uploading: .php, .jsp, .asp files</li>
                    <li>Try: Shell scripts, executables, or files with double extensions</li>
                </ul>
            </div>
            
            <div class="vulnerability">
                <h3>Cross-Site Request Forgery (CSRF)</h3>
                <p>Test CSRF attacks on state-changing operations.</p>
                <ul>
                    <li><a href="/transfer">Money Transfer</a> - No CSRF protection</li>
                    <li><a href="/delete_user">Delete User</a> - Missing CSRF tokens</li>
                </ul>
            </div>
            
            <h2>Test Credentials:</h2>
            <ul>
                <li>Username: <strong>admin</strong>, Password: <strong>admin123</strong></li>
                <li>Username: <strong>user</strong>, Password: <strong>password</strong></li>
                <li>Username: <strong>test</strong>, Password: <strong>test123</strong></li>
            </ul>
        </div>
    </body>
    </html>
    ''')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Vulnerable login form - SQL injection"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Vulnerable SQL query - concatenation without parameterization
        conn = sqlite3.connect('vulnerable.db')
        cursor = conn.cursor()
        
        # DELIBERATELY VULNERABLE - DO NOT USE IN PRODUCTION
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        
        try:
            cursor.execute(query)
            user = cursor.fetchone()
            conn.close()
            
            if user:
                session['user_id'] = user[0]
                session['username'] = user[1]
                session['role'] = user[4]
                return redirect(url_for('profile'))
            else:
                return render_template_string('''
                <h2>Login Failed</h2>
                <p>Invalid credentials. <a href="/login">Try again</a></p>
                <p>Query executed: ''' + query + '''</p>
                ''')
        except Exception as e:
            return render_template_string(f'''
            <h2>Database Error</h2>
            <p>Error: {str(e)}</p>
            <p>Query: {query}</p>
            <a href="/login">Back to login</a>
            ''')
    
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head><title>Login - Vulnerable App</title></head>
    <body style="font-family: Arial; margin: 40px;">
        <h2>Login</h2>
        <form method="post">
            <p>Username: <input type="text" name="username" required></p>
            <p>Password: <input type="password" name="password" required></p>
            <p><input type="submit" value="Login"></p>
        </form>
        <p><a href="/">Back to Home</a></p>
        <hr>
        <h3>SQL Injection Test Payloads:</h3>
        <ul>
            <li>Username: admin' OR '1'='1' -- (bypass authentication)</li>
            <li>Username: admin'; DROP TABLE users; -- (destructive)</li>
            <li>Username: ' UNION SELECT 1,2,3,4,5 -- (union injection)</li>
        </ul>
    </body>
    </html>
    ''')

@app.route('/search')
def search():
    """Vulnerable search - SQL injection and XSS"""
    query = request.args.get('q', '')
    results = []
    
    if query:
        conn = sqlite3.connect('vulnerable.db')
        cursor = conn.cursor()
        
        # Vulnerable SQL - no parameterization
        sql = f"SELECT * FROM posts WHERE title LIKE '%{query}%' OR content LIKE '%{query}%'"
        
        try:
            cursor.execute(sql)
            results = cursor.fetchall()
        except Exception as e:
            results = [f"Error: {str(e)}"]
        finally:
            conn.close()
    
    # Vulnerable template - no escaping (XSS)
    return render_template_string(f'''
    <!DOCTYPE html>
    <html>
    <head><title>Search - Vulnerable App</title></head>
    <body style="font-family: Arial; margin: 40px;">
        <h2>Search Posts</h2>
        <form method="get">
            <input type="text" name="q" value="{query}" placeholder="Search posts...">
            <input type="submit" value="Search">
        </form>
        
        <h3>Results for: {query}</h3>
        <div>
            {'<br>'.join(str(result) for result in results) if results else 'No results found'}
        </div>
        
        <p><a href="/">Back to Home</a></p>
        
        <hr>
        <h3>Test Payloads:</h3>
        <ul>
            <li>XSS: &lt;script&gt;alert('XSS')&lt;/script&gt;</li>
            <li>SQL: ' UNION SELECT username,password,email,role,id FROM users --</li>
            <li>Combined: &lt;img src=x onerror=alert(1)&gt;' OR '1'='1</li>
        </ul>
    </body>
    </html>
    ''', query=query, results=results)

@app.route('/profile')
def profile():
    """User profile page"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    return render_template_string(f'''
    <!DOCTYPE html>
    <html>
    <head><title>Profile - Vulnerable App</title></head>
    <body style="font-family: Arial; margin: 40px;">
        <h2>User Profile</h2>
        <p>Welcome, {session.get('username', 'Unknown')}!</p>
        <p>Role: {session.get('role', 'user')}</p>
        <p>User ID: {session.get('user_id')}</p>
        
        <h3>Update Profile</h3>
        <form method="post" action="/update_profile">
            <p>Bio: <textarea name="bio" placeholder="Tell us about yourself..."></textarea></p>
            <p><input type="submit" value="Update"></p>
        </form>
        
        <p><a href="/logout">Logout</a> | <a href="/">Home</a></p>
    </body>
    </html>
    ''')

@app.route('/update_profile', methods=['POST'])
def update_profile():
    """Update profile - XSS vulnerability"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    bio = request.form.get('bio', '')
    
    # Vulnerable - directly rendering user input without escaping
    return render_template_string(f'''
    <!DOCTYPE html>
    <html>
    <head><title>Profile Updated</title></head>
    <body style="font-family: Arial; margin: 40px;">
        <h2>Profile Updated Successfully!</h2>
        <p>Your new bio: {bio}</p>
        <p><a href="/profile">Back to Profile</a></p>
    </body>
    </html>
    ''')

@app.route('/file')
def file_access():
    """Directory traversal vulnerability"""
    filename = request.args.get('name', 'default.txt')
    
    try:
        # Vulnerable - no path sanitization
        file_path = os.path.join('files', filename)
        
        # Try to read the file
        with open(file_path, 'r') as f:
            content = f.read()
        
        return render_template_string(f'''
        <h2>File Content: {filename}</h2>
        <pre>{content}</pre>
        <p><a href="/">Back to Home</a></p>
        ''')
    except Exception as e:
        return render_template_string(f'''
        <h2>Error accessing file: {filename}</h2>
        <p>Error: {str(e)}</p>
        <p>Attempted path: {file_path}</p>
        <p><a href="/">Back to Home</a></p>
        <hr>
        <h3>Try these payloads:</h3>
        <ul>
            <li><a href="/file?name=../../../etc/passwd">../../../etc/passwd</a></li>
            <li><a href="/file?name=..\\..\\..\\windows\\system32\\drivers\\etc\\hosts">..\\..\\..\\windows\\system32\\drivers\\etc\\hosts</a></li>
        </ul>
        ''')

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    """File upload vulnerability"""
    if request.method == 'POST':
        if 'file' not in request.files:
            return 'No file selected'
        
        file = request.files['file']
        if file.filename == '':
            return 'No file selected'
        
        # Vulnerable - no file type validation
        filename = file.filename  # Should use secure_filename()
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        # Store in database
        conn = sqlite3.connect('vulnerable.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO files (filename, original_name, uploaded_by) VALUES (?, ?, ?)",
                      (filename, file.filename, session.get('username', 'anonymous')))
        conn.commit()
        conn.close()
        
        return render_template_string(f'''
        <h2>File Uploaded Successfully!</h2>
        <p>Filename: {filename}</p>
        <p>Saved to: {file_path}</p>
        <p><a href="/upload">Upload another file</a> | <a href="/">Home</a></p>
        ''')
    
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head><title>File Upload - Vulnerable App</title></head>
    <body style="font-family: Arial; margin: 40px;">
        <h2>File Upload</h2>
        <form method="post" enctype="multipart/form-data">
            <p>Select file: <input type="file" name="file" required></p>
            <p><input type="submit" value="Upload"></p>
        </form>
        
        <p><a href="/">Back to Home</a></p>
        
        <hr>
        <h3>Test malicious uploads:</h3>
        <ul>
            <li>PHP shell: upload .php files</li>
            <li>Double extensions: file.jpg.php</li>
            <li>Null byte: file.php%00.jpg</li>
            <li>Executable files: .exe, .bat, .sh</li>
        </ul>
    </body>
    </html>
    ''')

@app.route('/posts')
def posts():
    """Posts with comment system - XSS vulnerability"""
    conn = sqlite3.connect('vulnerable.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM posts ORDER BY created_at DESC")
    posts = cursor.fetchall()
    conn.close()
    
    posts_html = ""
    for post in posts:
        posts_html += f'''
        <div style="border: 1px solid #ddd; padding: 15px; margin: 10px 0;">
            <h3>{post[1]}</h3>
            <p>{post[2]}</p>
            <small>By: {post[3]} on {post[4]}</small>
        </div>
        '''
    
    return render_template_string(f'''
    <!DOCTYPE html>
    <html>
    <head><title>Posts - Vulnerable App</title></head>
    <body style="font-family: Arial; margin: 40px;">
        <h2>All Posts</h2>
        {posts_html}
        
        <h3>Add Comment (Vulnerable to XSS)</h3>
        <form method="post" action="/add_comment">
            <p>Comment: <textarea name="comment" placeholder="Add your comment..."></textarea></p>
            <p><input type="submit" value="Post Comment"></p>
        </form>
        
        <p><a href="/">Back to Home</a></p>
    </body>
    </html>
    ''')

@app.route('/add_comment', methods=['POST'])
def add_comment():
    """Add comment - XSS vulnerability"""
    comment = request.form.get('comment', '')
    
    # Vulnerable - rendering user input without escaping
    return render_template_string(f'''
    <h2>Comment Added!</h2>
    <div style="border: 1px solid #ddd; padding: 10px;">
        <p>Your comment: {comment}</p>
    </div>
    <p><a href="/posts">Back to Posts</a></p>
    ''')

@app.route('/user')
def user_profile():
    """User profile by ID - SQL injection"""
    user_id = request.args.get('id', '1')
    
    conn = sqlite3.connect('vulnerable.db')
    cursor = conn.cursor()
    
    # Vulnerable SQL query
    query = f"SELECT username, email, role FROM users WHERE id = {user_id}"
    
    try:
        cursor.execute(query)
        user = cursor.fetchone()
        conn.close()
        
        if user:
            return render_template_string(f'''
            <h2>User Profile</h2>
            <p>Username: {user[0]}</p>
            <p>Email: {user[1]}</p>
            <p>Role: {user[2]}</p>
            <p>Query: {query}</p>
            <p><a href="/">Back to Home</a></p>
            ''')
        else:
            return f"No user found with ID: {user_id}"
    except Exception as e:
        return f"Database error: {str(e)}<br>Query: {query}"

@app.route('/logout')
def logout():
    """Logout user"""
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)