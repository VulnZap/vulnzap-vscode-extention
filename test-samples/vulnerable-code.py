#!/usr/bin/env python3
"""
Test file for security extension - contains intentional Python vulnerabilities
This file should trigger multiple security warnings
"""

import os
import subprocess
import pickle
import hashlib
import sqlite3

# SEC101: Code injection via eval
def process_user_input(user_code):
    return eval(user_code)  # VULNERABLE: Code injection

# SEC102: Command injection via os.system
def execute_command(user_input):
    os.system(f"ls {user_input}")  # VULNERABLE: Command injection

# SEC103: SQL Injection
def get_user_data(user_id):
    conn = sqlite3.connect('database.db')
    query = f"SELECT * FROM users WHERE id = {user_id}"  # VULNERABLE: SQL injection
    return conn.execute(query).fetchall()

# SEC104: Hardcoded credentials
API_KEY = "sk-1234567890abcdef"  # VULNERABLE: Hardcoded secret
PASSWORD = "admin123"  # VULNERABLE: Hardcoded password
SECRET_TOKEN = "abc123xyz"  # VULNERABLE: Hardcoded token

# SEC105: Insecure deserialization
def load_user_data(data):
    return pickle.loads(data)  # VULNERABLE: Insecure deserialization

# SEC106: Path traversal
def read_file(filename):
    with open(f"./uploads/{filename}", 'r') as f:  # VULNERABLE: Path traversal
        return f.read()

# SEC107: Weak cryptography
def weak_hash(password):
    return hashlib.md5(password.encode()).hexdigest()  # VULNERABLE: Weak hash

# SEC108: Shell injection
def run_command(cmd):
    subprocess.call(cmd, shell=True)  # VULNERABLE: Shell injection

# SEC109: Information disclosure in exception handling
def handle_database_error():
    try:
        conn = sqlite3.connect('nonexistent.db')
        conn.execute("SELECT * FROM users")
    except Exception as e:
        print(f"Database error: {e}")  # VULNERABLE: Information disclosure
        return str(e)

# SEC110: Insecure random number generation
import random
def generate_session_id():
    return str(random.random())  # VULNERABLE: Weak randomness

# SEC111: Debug mode in production
DEBUG = True  # VULNERABLE: Debug mode enabled

# SEC112: Insecure file permissions
def create_temp_file():
    filename = "/tmp/sensitive_data.txt"
    with open(filename, 'w') as f:
        f.write("sensitive information")
    os.chmod(filename, 0o777)  # VULNERABLE: Overly permissive permissions

# SEC113: LDAP injection
def authenticate_user(username):
    import ldap
    ldap_filter = f"(uid={username})"  # VULNERABLE: LDAP injection
    # ldap search would use this filter

# SEC114: XML External Entity (XXE)
def parse_xml(xml_data):
    import xml.etree.ElementTree as ET
    return ET.fromstring(xml_data)  # VULNERABLE: XXE if external entities enabled

# Good practices (should not trigger warnings)
def safe_processing(user_input):
    if not isinstance(user_input, str) or len(user_input) > 100:
        raise ValueError("Invalid input")
    
    conn = sqlite3.connect('database.db')
    query = "SELECT * FROM users WHERE name = ?"
    return conn.execute(query, (user_input,)).fetchall()

def secure_hash(password):
    import hashlib
    import secrets
    salt = secrets.token_bytes(32)
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)

def secure_random():
    import secrets
    return secrets.token_urlsafe(32)

if __name__ == "__main__":
    print("Testing security extension...")
    process_user_input("print('hello')")
    safe_processing("test_user") 