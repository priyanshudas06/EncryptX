# EncryptX
EncryptX is a full-stack web application that secures your files through encryption and simple management. With EncryptX, users can sign up, encrypt/upload files, and receive the decryption key via email. Files can then be downloaded in encrypted form and later decrypted easily through the web interface. An admin dashboard allows monitoring of users and their data.

Features
User Authentication: Secure sign-up and login with email-based OTP verification.

File Encryption: Upload files to be encrypted using Fernet symmetric encryption.

Decryption Key Delivery: Decryption keys are emailed securely to the user.

File Management: View, download, and manage all uploaded files from a personal dashboard.

Easy Decryption: Upload an encrypted file with the decryption key to recover your original file.

Admin Dashboard: Admin can view all users and associated files/data.

Responsive UI: Front-end built for usability on both desktop and mobile devices.

Tech Stack
Backend: Python, Flask

Encryption: cryptography (Fernet module)

Frontend: HTML, CSS (Bootstrap), JavaScript

Database: MySQL usign MySQL-Connector Python

Email Delivery: SMTP (for OTP and decryption key)
