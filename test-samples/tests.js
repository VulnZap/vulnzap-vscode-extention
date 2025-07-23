const express = require('express');
const { exec, execSync } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { Pool } = require('pg'); // Assuming 'pg' library for DB examples

const app = express();
const pool = new Pool();

app.use(express.urlencoded({ extended: true }));

app.get('/user', async (req, res) => {
    // --- VULNERABILITIES ---

    // 1. SQL Injection Vulnerabilities
    const userId = req.query.id;
    const userName = req.query.name;

    const badQuery = `SELECT * FROM users WHERE id = ${userId}`; // Should be flagged
    await pool.query(badQuery);

    const anotherBadQuery = "SELECT * FROM users WHERE name = '" + userName + "'"; // Should be flagged
    await pool.query(anotherBadQuery);


    // 2. Command Injection
    const command = req.query.command;
    const hostname = req.query.host;

    exec('ls ' + command, (err, stdout, stderr) => { /* ... */ }); // Should be flagged
    execSync(`ping ${hostname}`); // Should be flagged


    // 3. Hardcoded Secrets
    const GITHUB_TOKEN = "testtoken"; // Should be flagged
    const STRIPE_SECRET = "sk_test_51Mexamplekeythatisverylongandlooksreal"; // Should be flagged
    const CUSTOM_API_KEY = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"; // Should be flagged


    // 4. Weak Random Generation
    const sessionToken = Math.random(); // Should be flagged
    const csrfToken = Math.random().toString(36).substring(2); // Should be flagged


    // 5. Weak Cryptography
    const password = 'user_password';
    const data = 'some_data';

    const weakHash = crypto.createHash('md5').update(password).digest('hex'); // Should be flagged
    const anotherWeakHash = crypto.createHash('sha1').update(data).digest('hex'); // Should be flagged


    // 6. Path Traversal
    const filename = req.query.file;
    fs.readFile('/var/www/' + filename, 'utf8', (err, data) => { // Should be flagged
        // ...
    });


    // --- SAFE PATTERNS (Should NOT be flagged) ---

    // Secure parameterized query
    const safeQuery = "SELECT * FROM users WHERE id = $1";
    await pool.query(safeQuery, [userId]);

    // Secure token generation
    const secureToken = crypto.randomBytes(32).toString('hex');

    // Secure hashing
    const secureHash = crypto.createHash('sha256').update(password).digest('hex');

    // Sanitized file access
    const safeFilename = path.basename(filename);
    const safePath = path.join('/var/www/uploads', safeFilename);
    fs.readFile(safePath, 'utf8', (err, data) => {
        // ...
    });


    res.send('Done');
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});