const fs = require('fs');
const path = require('path');

const apiKey = "smvjnvjdfknvj";

const filePath = path.join(__dirname, 'test.js');

fs.writeFileSync(filePath, `console.log("api key: ${apiKey}")`);

console.log(`API key written to ${filePath}`);

// Test file for AST-guided security analysis and diagnostic positioning

// SEC001 - Code injection vulnerabilities
function testCodeInjection() {
    const userInput = "alert('xss')";
    eval(userInput); // Should be detected with precise AST positioning
    
    const func = new Function('return ' + userInput); // Also dangerous
    func();
    
    setTimeout("alert('delayed')", 1000); // String-based timeout
}

// SEC002 - XSS vulnerabilities via DOM manipulation
function testXSS() {
    const userContent = "<script>alert('xss')</script>";
    document.body.innerHTML = userContent; // Should be precisely underlined
    
    const element = document.getElementById('target');
    element.outerHTML = userContent; // Another XSS vector
}

// SEC003 - Document.write XSS
function testDocumentWrite() {
    const userData = "<script>alert('document.write xss')</script>";
    document.write(userData); // Deprecated and dangerous
    document.writeln(userData);
}

// SEC004 - SQL injection patterns
function testSQLInjection() {
    const userId = req.query.id; // Assume req is available
    const query = `SELECT * FROM users WHERE id = ${userId}`; // Template literal injection
    
    const query2 = "SELECT * FROM users WHERE name = '" + req.body.name + "'"; // String concatenation
    
    execute(query);
    execute(query2);
}

// SEC005 - Hardcoded secrets
function testHardcodedSecrets() {
    const apiKey = "sk_live_51234567890abcdef1234567890abcdef12345678"; // Stripe key
    const githubToken = "ghp_example_token_placeholder"; // GitHub token
    const awsKey = "AKIAEXAMPLEKEY123456"; // AWS key
    const paypalSecret = "sandbox_secret_123456"; // PayPal secret
    
    const config = {
        password: "super_secret_password_123", // Generic secret
        apiKey: "very_long_api_key_that_should_be_detected_12345",
        token: "jwt_token_abc123def456ghi789jkl012mno345pqr"
    };
    
    return { apiKey, awsKey, githubToken, config };
}

// SEC006 - Weak cryptography
function testWeakCrypto() {
    const crypto = require('crypto');
    
    // Weak random number generation
    const randomValue = Math.random(); // Should be precisely underlined
    
    // Weak hashing algorithms
    const hash1 = crypto.createHash('md5').update('data').digest('hex');
    const hash2 = crypto.createHash('sha1').update('data').digest('hex');
    
    // Weak cipher selection
    const cipher = crypto.createCipher('des', 'password');
    
    return { randomValue, hash1, hash2, cipher };
}

// SEC007 - File operation vulnerabilities
function testFileOperations() {
    const fs = require('fs');
    const path = require('path');
    
    const userPath = req.query.file; // User-controlled path
    
    // Potential path traversal
    const fullPath = path.join('/uploads', userPath);
    const content = fs.readFileSync(fullPath); // Dangerous file read
    
    fs.writeFileSync(userPath, 'data'); // Dangerous file write
    fs.unlinkSync(userPath); // Dangerous file deletion
    
    return content;
}

// Complex nested vulnerabilities
function complexVulnerabilities() {
    const userInput = req.body.code;
    
    // Multiple vulnerabilities in one function
    if (userInput) {
        eval(`
            const secret = "embedded_api_key_abc123def456";
            document.write('<div>' + userInput + '</div>');
            const randomId = Math.random().toString();
        `);
    }
    
    // Nested template literal with user input
    const template = `
        <script>
            const data = \${JSON.stringify(req.query)};
            console.log(data);
        </script>
    `;
    
    document.body.innerHTML = template;
}

// Export functions for testing
module.exports = {
    testCodeInjection,
    testXSS,
    testDocumentWrite,
    testSQLInjection,
    testHardcodedSecrets,
    testWeakCrypto,
    testFileOperations,
    complexVulnerabilities
};
