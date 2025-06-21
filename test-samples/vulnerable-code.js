// Test file for security extension - contains intentional vulnerabilities
// This file should trigger multiple security warnings

// SEC001: Code injection via eval
function processUserInput(userCode) {
    return eval(userCode); // VULNERABLE: Code injection
}

// SEC002: XSS via innerHTML
function displayMessage(message) {
    document.getElementById('output').innerHTML = message; // VULNERABLE: XSS
}

// SEC003: SQL Injection
function getUserData(userId) {
    const query = "SELECT * FROM users WHERE id = " + userId; // VULNERABLE: SQL injection
    return database.query(query);
}

// SEC004: Hardcoded credentials
const API_KEY = "sk-1234567890abcdef"; // VULNERABLE: Hardcoded secret
const PASSWORD = "admin123"; // VULNERABLE: Hardcoded password

// SEC005: Insecure random number generation
function generateSessionId() {
    return Math.random().toString(36); // VULNERABLE: Weak randomness
}

// SEC006: Command injection
function executeCommand(userInput) {
    const command = "ls " + userInput; // VULNERABLE: Command injection
    require('child_process').exec(command);
}

// SEC007: Path traversal
function readFile(filename) {
    const fs = require('fs');
    return fs.readFileSync('./uploads/' + filename); // VULNERABLE: Path traversal
}

// SEC008: Missing input validation
function processAge(age) {
    if (age > 0) { // Missing upper bound validation
        return "Valid age: " + age;
    }
}

// SEC009: Weak cryptography
const crypto = require('crypto');
function weakHash(password) {
    return crypto.createHash('md5').update(password).digest('hex'); // VULNERABLE: Weak hash
}

// SEC010: Information disclosure
function handleError(error) {
    console.log("Database error:", error.stack); // VULNERABLE: Information disclosure
    return { error: error.message, stack: error.stack };
}

// Good practices (should not trigger warnings)
function safeProcessing(input) {
    // Input validation
    if (typeof input !== 'string' || input.length > 100) {
        throw new Error('Invalid input');
    }
    
    // Safe HTML handling
    const safeElement = document.createElement('div');
    safeElement.textContent = input;
    
    return input;
}

module.exports = {
    processUserInput,
    displayMessage,
    getUserData,
    generateSessionId,
    executeCommand,
    readFile,
    safeProcessing
}; 