from flask import Flask, render_template, request, redirect, url_for, session, send_file, jsonify
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
from datetime import datetime
import mysql.connector
from io import BytesIO
from flask_mail import Mail, Message
from random import randint
import pytz
import mimetypes


# Flask setup
app = Flask(__name__)
app.secret_key = 'sudipta_gopal_encriptx'

# Flask-Mail configuration

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'encryptx.com@gmail.com'
app.config['MAIL_PASSWORD'] = 'vjul ozez jiyq ppro'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False


mail = Mail(app)


@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    return response


# Database setup
conn = mysql.connector.connect(
    host = "encryptx.cbkm0w24mmmt.eu-north-1.rds.amazonaws.com",
    user = "admin",
    password = "Encryptx2024",
    database = "Content_Protection"
)


def init_db():
    
    cursor = conn.cursor()
    try:
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                            user_id INT PRIMARY KEY AUTO_INCREMENT,
                            username varchar(256) NOT NULL,
                            email varchar(256) NOT NULL UNIQUE,
                            password varchar(256) NOT NULL
                            )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS content(
                            content_id INT PRIMARY KEY AUTO_INCREMENT,
                            filename varchar(256) NOT NULL,
                            file_type varchar(256),
                            file_size DECIMAL(10, 2),
                            encrypted_content LONGBLOB NOT NULL,
                            user_id INT NOT NULL,
                            FOREIGN KEY (user_id) REFERENCES users(user_id)
                            )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS access_logs(
                            log_id INT PRIMARY KEY AUTO_INCREMENT,
                            user_id INT NOT NULL,
                            content_id INT,
                            access_type varchar(256) NOT NULL,
                            access_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            FOREIGN KEY (content_id) REFERENCES content(content_id) ON DELETE SET NULL,
                            FOREIGN KEY (user_id) REFERENCES users(user_id)
                            
                            )''')
        conn.commit()
    except Exception as e:
        return f"An error occured : {str(e)}"
    finally :
        cursor.close()

# Initialize the database
init_db()

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/admin_login',methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':

        email = request.form['email']
        password = request.form['password']

        if not email or not password:
            return "Email & Password are required!"
            
        cursor = conn.cursor()
        try :
            
            cursor.execute("SELECT * FROM admin WHERE email=%s", (email,))
            user = cursor.fetchone()

            if user and check_password_hash(user[2], password):
                
                session['user_id'] = user[0]
                session['username'] = user[1]
                session['email'] = user[3]

                return redirect(url_for('admin'))
            else:
                return "Invalid credentials. Please try again."
        except Exception as e:
            return f"An error occured : {str(e)}"
        finally :
            cursor.close()
    return render_template('admin_login.html')
        
@app.route('/admin',methods = ['GET', 'POST'])
def admin():
    cursor = conn.cursor()
    cursor.execute("SELECT user_id, username, email FROM users")
    users = cursor.fetchall()

    cursor.execute("SELECT content_id, filename,file_size,user_id FROM content")
    content = cursor.fetchall()

    cursor.execute("SELECT log_id, user_id, content_id, access_type, access_time FROM access_logs")
    logs = cursor.fetchall()

    cursor.close()
    
    return render_template('admin.html', users=users, content=content, logs=logs)
    



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        if not email or not password:
            return "Email & Password are required!"
            
        cursor = conn.cursor()
        try :
            
            cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
            user = cursor.fetchone()

            if user and check_password_hash(user[3], password):
                
                session['user_id'] = user[0]
                session['username'] = user[1]
                session['email'] = user[2]

                # Adjusting time to local timezone (e.g., 'Asia/Kolkata')
                local_tz = pytz.timezone('Asia/Kolkata')
                current_time = datetime.now(local_tz)
                cursor.execute("INSERT INTO access_logs (user_id, access_type, access_time) VALUES (%s, %s, %s)", (user[0], 'Login', current_time))
                conn.commit()

                return redirect(url_for('dashboard_home'))
            else:
                return "Invalid credentials. Please try again."
        except Exception as e:
            return f"An error occured : {str(e)}"
        finally :
            cursor.close()
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


@app.route('/check-mail', methods=['POST'])
def check():
    data = request.get_json()
    email = data.get('email')

    cursor =conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = %s",(email,))
    temp = cursor.fetchone()

    return jsonify({"temp": temp is not None})

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = generate_password_hash(data.get('password'))

       
        cursor = conn.cursor()
        
        try:
            cursor.execute("INSERT INTO users (username, email, password) VALUES (%s, %s, %s)", (username, email, password))
            conn.commit()

            # Adjusting time to local timezone (e.g., 'Asia/Kolkata')
            local_tz = pytz.timezone('Asia/Kolkata')
            current_time = datetime.now(local_tz)
            cursor.execute("SELECT user_id FROM users WHERE email = %s",(email,))
            user = cursor.fetchone()
            cursor.execute("INSERT INTO access_logs (user_id, access_type,access_time) VALUES (%s, %s,%s)", (user[0], 'Sign Up',current_time))

            conn.commit()

            return redirect(url_for('login'))
        except Exception as e:
            return f"An error occured : {str(e)}"
        finally :
            cursor.close()
    return render_template('sign_up.html')

@app.route('/send-otp', methods=['POST'])
def send_otp():
    data = request.get_json()
    email = data.get('email')

    if not email:
        return {"error": "Email is required"}, 400

    otp = randint(1000, 9999)  # Generate a 4-digit OTP
    session['otp'] = otp  # Save OTP in the session
    session['email'] = email  # Save the email in the session

    try:
        msg = Message('Your OTP for Registration', sender=app.config['MAIL_USERNAME'], recipients=[email])
        msg.body = f"Your OTP is: {otp}"
        mail.send(msg)
        return {"message": "OTP sent successfully"}, 200
    except Exception as e:
        return {"error": str(e)}, 500


@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    email = data.get('email')
    otp = data.get('otp')

    if 'otp' not in session or 'email' not in session:
        return {"error": "Session expired. Please try again."}, 400

    if email != session['email']:
        return {"error": "Email does not match."}, 400

    if str(session['otp']) == str(otp):
        session.pop('otp', None)  # Remove OTP from session after verification
        return {"message": "OTP verified successfully"}, 200
    else:
        return {"error": "Invalid OTP"}, 400


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT * FROM content WHERE user_id=%s", (session['user_id'],))
        files = cursor.fetchall()
    except Exception as e:
        return f"An error occured : {str(e)}"
    finally :
        cursor.close()
    return render_template('dashboard.html', files=files)

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        file = request.files['file']
        # Generate an encryption key
        key = Fernet.generate_key()
        cipher_suite = Fernet(key)

        if file:
            filename = secure_filename(file.filename)
            file_content = file.read() 
            file_size = len(file_content)  # Size in bytes
            file_size = round(file_size / (1024 * 1024), 2)
            
            # Get file type (MIME type)
            
            file_type, _ = mimetypes.guess_type(filename)
            if file_type is None:
                file_type = "Unknown"
            
            # Encrypt and save the file
             # Read file content
            encrypted_content = cipher_suite.encrypt(file_content)

            # Save metadata to the database
            cursor = conn.cursor()
            cursor.execute("SELECT filename, user_id FROM content WHERE user_id = %s AND filename = %s", (session['user_id'], filename))
            x = cursor.fetchone()

            if not x:
                try:
                    cursor.execute(
                        "INSERT INTO content (filename, encrypted_content, file_size, file_type, user_id) VALUES (%s, %s, %s, %s, %s)",
                        (filename, encrypted_content, file_size, file_type, session['user_id'])
                    )
                    conn.commit()
                    cursor.execute("SELECT content_id FROM content WHERE filename = %s",(filename,))
                    con = cursor.fetchone()

                    # Adjusting time to local timezone (e.g., 'Asia/Kolkata')
                    local_tz = pytz.timezone('Asia/Kolkata')
                    current_time = datetime.now(local_tz)
                    cursor.execute("INSERT INTO access_logs (user_id, access_type, content_id, access_time) VALUES (%s, %s, %s,%s)", (session['user_id'], 'Upload', con[0],current_time))
                    conn.commit()

                    # Send email with file name and encryption key
                    user_email = session.get('email')
                    if user_email:
                        try:
                            msg = Message(
                                subject="Your File Encryption Key",
                                sender=app.config['MAIL_USERNAME'],
                                recipients=[user_email]
                            )
                            msg.body = f"Dear {session.get('username')},\n\nYour file '{filename}' has been successfully uploaded and encrypted.\n\nEncryption Key: {key.decode()}\n\nPlease keep this key secure as it is required to decrypt your file.\n\nRegards,\nEncryptX Team"
                            mail.send(msg)
                        except Exception as e:
                            return f"Failed to send email: {str(e)}"
                    else :
                        return f"failed"
                except Exception as e:
                    return f"An error occurred: {str(e)}"
                finally:
                    cursor.close()
            else:
                return render_template('upload.html', x=x)

            return render_template('upload.html', key=key.decode())

    return render_template('upload.html', key=None)

@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        file = request.files.get('file')  # Use .get() to avoid KeyError
        key = request.form.get('key')  # Get the key from the form

        if not key:
            return "Encryption key is required!"  # Handle missing key case
        
        # Convert key to bytes if it's a string
        if isinstance(key, str):
            key = key.encode()
        
        try:
            cipher_suite = Fernet(key)

            if file:
                filename = secure_filename(file.filename)
                # Read the encrypted file content
                file_content = file.read()
                
                try:
                    # Decrypt the file content
                    decrypted_content = cipher_suite.decrypt(file_content)

                    # Save the decrypted file (optional)
                    file_stream = BytesIO(decrypted_content)  # Convert decrypted content to file stream
                    file_stream.seek(0)

                    # Optionally, log the access here
                    # Uncomment and fix database code if needed
                    cursor = conn.cursor()
                    local_tz = pytz.timezone('Asia/Kolkata')
                    current_time = datetime.now(local_tz)
                    cursor.execute("INSERT INTO access_logs (user_id, access_type, access_time) VALUES (%s, %s,%s)", (session['user_id'], 'Decrypt', current_time))
                    conn.commit()

                    return send_file(
                        file_stream,
                        as_attachment=True,
                        download_name=filename,
                        mimetype='application/octet-stream'
                    )
                except Exception as decryption_error:
                    # Provide more details about the decryption error
                    return f"Decryption failed: {str(decryption_error)}. Make sure the file is encrypted with the correct key."

            else:
                return "No file uploaded."

        except Exception as e:
            return f"Invalid key or error: {str(e)}"

    return render_template('decrypt.html')


@app.route('/download/<int:file_id>', methods=['GET', 'POST'])
def download(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Get the file from the database
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT * FROM content WHERE content_id=%s AND user_id=%s", (file_id, session['user_id']))
        file = cursor.fetchone()

        if file:
            filename = file[1]
            encrypted_content = file[4]

            if request.method == 'POST':
                # Optionally, handle encryption key (but don't decrypt it
                # For downloading the encrypted file, you can skip the decryption process
                
                # Log the download attempt
                local_tz = pytz.timezone('Asia/Kolkata')
                current_time = datetime.now(local_tz)
                cursor.execute("INSERT INTO access_logs (user_id, access_type, content_id, access_time) VALUES (%s, %s, %s, %s)", (session['user_id'], 'Download', file_id, current_time))
                conn.commit()

                # Send the encrypted file as an attachment
                file_stream = BytesIO(encrypted_content)  # Use the encrypted content directly
                file_stream.seek(0)

                return send_file(
                    file_stream,
                    as_attachment=True,
                    download_name=filename,
                    mimetype='application/octet-stream'
                )

            else:
                return "Please submit the encryption key to download the file."

        else:
            return "File not found or unauthorized access."

    except Exception as e:
        return f"An error occurred: {str(e)}"
    finally:
        cursor.close()


@app.route('/delete/<int:file_id>', methods=['POST'])
def delete(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    cursor = conn.cursor()
    local_tz = pytz.timezone('Asia/Kolkata')
    current_time = datetime.now(local_tz)
    cursor.execute("INSERT INTO access_logs (user_id, access_type, content_id, access_time) VALUES (%s, %s, %s,%s)", (session['user_id'], 'Delete', file_id,current_time))
    conn.commit()

    # Get the file from the database
    
    cursor.execute("SET FOREIGN_KEY_CHECKS = 0")
    conn.commit()
    cursor.execute("DELETE FROM content WHERE content_id=%s AND user_id=%s", (file_id, session['user_id']))
    cursor.execute("SET FOREIGN_KEY_CHECKS = 1")
    conn.commit()

    
    
    cursor.close()
    return redirect(url_for('files'))


@app.route('/files')
def files():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT * FROM content WHERE user_id=%s", (session['user_id'],))
        files = cursor.fetchall()
    except Exception as e:
        return f"An error occured : {str(e)}"
    finally :
        cursor.close()
    return render_template("files.html",files=files, css_file= 'css/files.css')

@app.route('/dashboard_home')
def dashboard_home():
    
    return render_template("home.html")

@app.route('/profile')
def profile():
    
    return render_template("profile.html", css_file = 'css/profile.css')

if __name__ == '__main__':
    app.run(debug=True)
