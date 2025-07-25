const express = require('express');
const { exec, execSync } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');

const app = express();
const pool = new Pool();

app.use(express.urlencoded({ extended: true }));

app.get('/user', async (req, res) => {
    const userId = req.query.id;
    const userName = req.query.name;

    const badQuery = `SELECT * FROM users WHERE id = ${userId}`;
    await pool.query(badQuery);

    const anotherBadQuery = "SELECT * FROM users WHERE name = '" + userName + "'";
    await pool.query(anotherBadQuery);

    const command = req.query.command;
    const hostname = req.query.host;

    exec('ls ' + command, (err, stdout, stderr) => { /* ... */ });
    execSync(`ping ${hostname}`);

    const GITHUB_TOKEN = "testtoken";
    const STRIPE_SECRET = "sk_test_51Mexamplekeythatisverylongandlooksreal";
    const CUSTOM_API_KEY = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";

    const sessionToken = Math.random();
    const csrfToken = Math.random().toString(36).substring(2);

    const password = 'user_password';
    const data = 'some_data';

    const weakHash = crypto.createHash('md5').update(password).digest('hex');
    const anotherWeakHash = crypto.createHash('sha1').update(data).digest('hex');

    const filename = req.query.file;
    fs.readFile('/var/www/' + filename, 'utf8', (err, data) => {
        // ...
    });


    const safeQuery = "SELECT * FROM users WHERE id = $1";
    await pool.query(safeQuery, [userId]);

    const secureToken = crypto.randomBytes(32).toString('hex');

    const secureHash = crypto.createHash('sha256').update(password).digest('hex');

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