import os
import subprocess
import hashlib
import random
import secrets

# SQL Injection Vulnerabilities
user_id = request.args.get('id')
bad_query = f"SELECT * FROM users WHERE id = {user_id}"  # Should be flagged
cursor.execute(bad_query)

another_bad_query = "SELECT * FROM users WHERE name = '" + user_name + "'"  # Should be flagged
db.execute(another_bad_query)

# Command Injection
user_input = request.form['command']
os.system('ls ' + user_input)  # Should be flagged
subprocess.call('ping ' + hostname, shell=True)  # Should be flagged

# Hardcoded Secrets
API_KEY = "sk_live_abcdef1234567890abcdef1234567890"  # Should be flagged
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # Should be flagged
DATABASE_PASSWORD = "MyS3cr3tP@ssw0rd123"  # Should be flagged

# Weak Random Generation
session_token = str(random.random())  # Should be flagged
csrf_token = str(random.randint(1000, 9999))  # Should be flagged

# Weak Cryptography
weak_hash = hashlib.md5(password.encode()).hexdigest()  # Should be flagged
another_weak_hash = hashlib.sha1(data.encode()).hexdigest()  # Should be flagged

# Path Traversal
filename = request.args.get('file')
with open('/var/www/' + filename, 'r') as f:  # Should be flagged
    content = f.read()

# Safe patterns (should NOT be flagged)
safe_query = "SELECT * FROM users WHERE id = %s"
cursor.execute(safe_query, (user_id,))

secure_token = secrets.token_urlsafe(32)
secure_hash = hashlib.sha256(password.encode()).hexdigest()

# Sanitized file access
import os.path
safe_filename = os.path.basename(filename)
safe_path = os.path.join('/var/www/uploads', safe_filename) 