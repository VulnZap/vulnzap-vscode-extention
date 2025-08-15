# VulnZap - AI-Powered Security Reviewer for VS Code

[![Version](https://img.shields.io/vscode-marketplace/v/vulnzap.vulnzap.svg)](https://marketplace.visualstudio.com/items?itemName=vulnzap.vulnzap)
[![Downloads](https://img.shields.io/vscode-marketplace/d/vulnzap.vulnzap.svg)](https://marketplace.visualstudio.com/items?itemName=vulnzap.vulnzap)
[![Rating](https://img.shields.io/vscode-marketplace/r/vulnzap.vulnzap.svg)](https://marketplace.visualstudio.com/items?itemName=vulnzap.vulnzap)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A powerful Visual Studio Code extension that provides **real-time, AI-powered security analysis** for your code. VulnZap detects vulnerabilities like XSS, SQL injection, weak cryptography, and more with high accuracy across multiple programming languages.

![VulnZap Demo](https://raw.githubusercontent.com/VulnZap/vulnzap-vscode-extention/main/demo.gif)

## ✨ Features

### 🤖 Advanced AI-Powered Analysis

- **VulnZap Custom API**: Specialized security-focused analysis with batch scanning
- **Multi-Provider Support**: Extensible API provider system for future integrations
- **Context-Aware Detection**: Understands code patterns beyond simple regex
- **Intelligent Fallback**: Pattern-based detection when AI is unavailable

### 🔍 Comprehensive Security Coverage

- **OWASP Top 10**: Complete coverage of major security risks
- **Code Injection**: SQL injection, command injection, XSS, and LDAP injection
- **Authentication & Authorization**: Weak authentication patterns and privilege escalation
- **Cryptographic Issues**: Weak algorithms, insecure random generation, and key management
- **Data Exposure**: Sensitive data leaks, insecure storage, and logging issues
- **Configuration Issues**: Security misconfigurations and hardcoded secrets

### 🌐 Multi-Language Support

- **JavaScript & TypeScript**: Full ES6+ and Node.js support with AST-guided precision
- **Python**: Django, Flask, FastAPI, and standard library
- **Java**: Spring, servlet-based applications, and enterprise patterns

### 🔄 Smart Analysis Features

- **On-Save Scanning**: Analysis triggers when you save files for optimal performance
- **Fast Scan Mode**: Quick initial analysis for immediate feedback
- **Confidence Scoring**: Each finding includes accuracy confidence (50-100%)
- **Context-Aware Detection**: Understands code patterns and reduces false positives
- **Smart Caching**: Optimizes performance while maintaining accuracy

### 📦 Advanced Dependency Vulnerability Scanning

- **Multi-Ecosystem Support**: npm, pip, go, rust, gradle, maven, composer, rubygems, and more
- **Automatic Detection**: Scans package.json, requirements.txt, go.mod, Cargo.toml, pom.xml, etc.
- **Real-time Monitoring**: Automatically scans when dependency files are saved
- **Intelligent Caching**: 5-day cache with dependency change detection
- **Batch API Integration**: Efficient vulnerability database queries
- **Detailed Reports**: Comprehensive markdown reports with CVE information, severity levels, and fix recommendations

### 🗂️ Codebase Indexing System

- **Vector-Based Analysis**: Semantic code similarity detection using text embeddings
- **Incremental Indexing**: Smart updates when files change
- **Security Pattern Recognition**: Identifies similar vulnerable patterns across the codebase
- **Context Retrieval**: Provides security-relevant context for enhanced analysis
- **Performance Optimized**: Efficient storage and retrieval with configurable chunking

### 📊 Enhanced Security View

- **Unified Dashboard**: All security issues and dependency vulnerabilities in one view
- **Issue Categorization**: Organized by severity and file for easy navigation
- **Detailed Reports**: Comprehensive vulnerability information with fix suggestions
- **Dependency Management**: Direct links to update commands and patch versions
- **Real-time Updates**: Live synchronization with analysis results

## 🚀 Installation

### From VS Code Marketplace

1. Open VS Code
2. Press `Ctrl+Shift+X` (Windows/Linux) or `Cmd+Shift+X` (Mac)
3. Search for "VulnZap"
4. Click **Install**

### From Command Line

```bash
code --install-extension vulnzap.vulnzap
```

## ⚙️ Setup & Configuration

### 1. Configure VulnZap API

Press `Ctrl+Shift+P` (Windows/Linux) or `Cmd+Shift+P` (Mac) and run:

```
Security: Configure VulnZap API
```

### 2. Getting Your VulnZap API Key

1. Visit [VulnZap Platform](https://vulnzap.com)
2. Create an account and generate an API key
3. Enter it when prompted in VS Code

## 🎯 Usage

### Automatic Scanning

VulnZap automatically scans your code when you save files. Security issues appear as:

- 🔴 **Red squiggles**: Critical/High vulnerabilities
- 🟡 **Yellow squiggles**: Medium severity warnings
- 🔵 **Blue squiggles**: Low severity recommendations

### Manual Commands

| Command                               | Description                 |
| ------------------------------------- | --------------------------- |
| **Security: Enable Security Review**  | Enable on-save scanning     |
| **Security: Disable Security Review** | Disable all scanning        |
| **Security: Scan Current File**       | Force scan the active file  |
| **Security: Configure VulnZap API**   | Set up API credentials      |
| **Security: Toggle Security Review**  | Quick enable/disable toggle |

### Codebase Indexing Commands

| Command                                  | Description                                     |
| ---------------------------------------- | ----------------------------------------------- |
| **Security: Build Security Index**       | Index the entire codebase for enhanced analysis |
| **Security: View Index Statistics**      | Show indexing statistics and status             |
| **Security: Clear Security Index**       | Remove all indexed data                         |
| **Security: Find Similar Code Patterns** | Search for similar code patterns                |

### Dependency Scanning Commands

| Command                                             | Description                          |
| --------------------------------------------------- | ------------------------------------ |
| **Security: Scan Dependencies for Vulnerabilities** | Scan all dependencies in workspace   |
| **Security: Force Dependency Scan (Ignore Cache)**  | Fresh dependency scan ignoring cache |
| **Security: View Dependency Cache Statistics**      | Show cache status and statistics     |
| **Security: Clean Dependency Cache**                | Remove expired cache entries         |

### Status Bar Integration

The status bar shows current state:

- 🛡️ **Security: ON** - Active and scanning
- 🛡️ **Security: OFF** - Disabled
- 🛡️ **Security: ERROR** - Configuration issue

## 📋 Configuration Options

Open VS Code settings (`Ctrl+,`) and search for "VulnZap":

### Basic Settings

```json
{
  "vulnzap.enabled": true,
  "vulnzap.severity": "warning"
}
```

### AI Analysis Settings

```json
{
  // AI analysis features are always enabled
  // No configuration needed
}
```

### Indexing Settings

```json
{
  "vulnzap.enableVectorIndexing": true,
  "vulnzap.autoIndexOnSave": true,
  "vulnzap.vectorSimilarityThreshold": 0.7,
  "vulnzap.indexChunkSize": 500
}
```

### Dependency Scanning Settings

```json
{
  "vulnzap.enableDependencyScanning": true,
  "vulnzap.dependencyScanOnStartup": true
  // Timeout, cache expiry, and debounce are set to optimal defaults
}
```

### Performance Settings

```json
{
  "vulnzap.maxFileSizeBytes": 1000000,
  "vulnzap.maxFileLines": 2000,
  "vulnzap.maxIssuesPerFile": 100,
  "vulnzap.enableDebugLogging": false
}
```

## 🔍 Example Detections

### SQL Injection

```javascript
// ❌ Detected: SQL injection vulnerability (Confidence: 95%)
const query = `SELECT * FROM users WHERE id = ${userId}`;
db.query(query);

// ✅ Suggested: Use parameterized queries
const query = "SELECT * FROM users WHERE id = ?";
db.query(query, [userId]);
```

### Cross-Site Scripting (XSS)

```javascript
// ❌ Detected: XSS vulnerability via innerHTML (Confidence: 87%)
element.innerHTML = userInput;

// ✅ Suggested: Use textContent for safe content insertion
element.textContent = userInput;
```

### Weak Cryptography

```python
# ❌ Detected: Weak random number generation (Confidence: 92%)
import random
session_token = str(random.random())

# ✅ Suggested: Use cryptographically secure random
import secrets
session_token = secrets.token_urlsafe(32)
```

### Hardcoded Secrets

```javascript
// ❌ Detected: Hardcoded API key (Confidence: 98%)
const apiKey = "sk-1234567890abcdef";

// ✅ Suggested: Use environment variables
const apiKey = process.env.API_KEY;
```

### Dependency Vulnerabilities

```json
// package.json - Vulnerable package detected
{
  "dependencies": {
    "express": "4.16.0" // ❌ CVE-2024-29041: Path traversal vulnerability
  }
}

// ✅ Recommendation: Update to express@4.19.2 or later
{
  "dependencies": {
    "express": "^4.19.2"
  }
}
```

## 🛠️ Development & Contributing

### Prerequisites

- **Node.js** 16.x or higher
- **npm** 7.x or higher
- **Visual Studio Code** 1.74.0 or higher
- **TypeScript** 4.9.x or higher

### Local Development Setup

1. **Clone the repository**

   ```bash
   git clone https://github.com/VulnZap/vulnzap-vscode-extention.git
   cd vulnzap-vscode-extention
   ```

2. **Install dependencies**

   ```bash
   npm install
   ```

3. **Compile TypeScript**

   ```bash
   npm run compile
   ```

4. **Launch Development Environment**
   - Open the project in VS Code
   - Press `F5` to launch a new Extension Development Host window
   - The extension will be loaded automatically for testing

### Development Commands

```bash
# Watch mode for continuous compilation
npm run watch

# Compile once
npm run compile

# Package extension for distribution
npm run vscode:prepublish
```

### Project Structure

```
vulnzap-vscode-extension/
├── src/
│   ├── core/                 # Main extension entry point and core functionality
│   │   ├── extension.ts      # Main extension activation/deactivation
│   │   └── index.ts          # Core exports
│   ├── indexing/             # Codebase indexing and vector storage
│   │   ├── codebaseIndexer.ts    # Main indexing orchestrator
│   │   ├── textChunker.ts        # Code chunking for indexing
│   │   ├── vectorStorage.ts      # Vector storage and retrieval
│   │   ├── codeRetriever.ts      # Security context retrieval
│   │   └── incrementalIndexer.ts # Incremental index updates
│   ├── security/             # Security analysis components
│   │   └── codebaseSecurityAnalyzer.ts # AI-powered security analysis
│   ├── dependencies/         # Dependency vulnerability scanning
│   │   ├── dependencyScanner.ts  # Main scanning orchestrator
│   │   ├── dependencyParser.ts   # Multi-ecosystem dependency parsing
│   │   └── dependencyCache.ts    # Intelligent result caching
│   ├── providers/            # VS Code integration providers
│   │   ├── apiProviders.ts       # API provider management
│   │   ├── diagnosticProvider.ts # VS Code diagnostics integration
│   │   ├── securityViewProvider.ts # Security tree view
│   │   └── dependencyDiagnosticProvider.ts # Dependency diagnostics
│   └── utils/                # Utility functions
│       └── logger.ts         # Centralized logging
├── package.json              # Extension manifest and dependencies
├── tsconfig.json            # TypeScript configuration
├── webpack.config.js        # Build configuration
└── README.md               # This file
```

### Testing Your Changes

1. **Manual Testing**

   - Open test files in different languages
   - Verify security issues are detected correctly
   - Test dependency scanning with various package managers

2. **Test Indexing System**

   - Build index and verify statistics
   - Test similar code pattern detection
   - Verify incremental updates work correctly

3. **Performance Testing**
   - Test with large files and codebases
   - Verify caching behavior
   - Test network failure scenarios

### Debugging

1. **Enable Debug Logging**

   - Set `vulnzap.enableDebugLogging: true` in settings
   - View → Output → Select "VulnZap"

2. **Extension Logs**

   - Check Console for error messages in Extension Development Host
   - Monitor API call success/failure

3. **VS Code Debugging**
   - Set breakpoints in TypeScript files
   - Use F5 to debug the extension

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for detailed information on:

- Code of Conduct
- Development workflow
- Testing procedures
- Pull request process
- Issue reporting guidelines

### Quick Start for Contributors

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes and test thoroughly
4. Commit with descriptive messages: `git commit -m 'Add amazing feature'`
5. Push to your branch: `git push origin feature/amazing-feature`
6. Create a Pull Request

## 📊 Performance & Limits

- **File Size Limit**: 1MB per file for analysis
- **File Line Limit**: 2000 lines per file
- **Max Issues per File**: 100 issues to prevent overwhelming output
- **Caching Duration**: Configurable dependency cache (default: 5 days)
- **Memory Usage**: Optimized for large codebases with chunked indexing
- **Network Failures**: Graceful fallback to pattern matching

## 🔒 Security & Privacy

- **API Keys**: Stored securely in VS Code's encrypted storage
- **Code Privacy**: Code sent to VulnZap API for analysis only
- **No Data Storage**: Your code is never permanently stored on external servers
- **Local Fallback**: Works with pattern-based detection when API is unavailable
- **Configurable Scanning**: All features can be enabled/disabled per preference

## 🧪 Supported Vulnerability Types

### OWASP Top 10 Coverage

- **A01: Broken Access Control** - Authorization bypass, privilege escalation
- **A02: Cryptographic Failures** - Weak encryption, insecure storage
- **A03: Injection** - SQL, NoSQL, command, LDAP injection
- **A04: Insecure Design** - Design flaws and threat modeling gaps
- **A05: Security Misconfiguration** - Default configs, verbose errors
- **A06: Vulnerable Components** - Outdated dependencies (fully supported)
- **A07: Authentication Failures** - Weak authentication, session management
- **A08: Software Integrity** - Insecure CI/CD, auto-update without verification
- **A09: Logging Failures** - Insufficient logging, log injection
- **A10: Server-Side Request Forgery** - SSRF vulnerabilities

### Additional Security Patterns

- **Cross-Site Scripting (XSS)** - Reflected, stored, DOM-based
- **Cross-Site Request Forgery (CSRF)** - Missing tokens, weak validation
- **Information Disclosure** - Debug info, stack traces, sensitive data
- **Business Logic Flaws** - Race conditions, workflow bypasses
- **API Security** - Authentication, rate limiting, input validation

### Pattern-Based Detection

- **SQL Injection**: Template literals, string concatenation in queries
- **XSS**: innerHTML assignments, eval usage, unsafe DOM manipulation
- **Hardcoded Secrets**: API keys, tokens, Base64 strings, cryptographic keys
- **Weak Crypto**: MD5, SHA1, DES, RC4 usage
- **Unsafe Functions**: Command execution, system calls, shell operations

## 🆘 Troubleshooting

### Common Issues

**"Extension not working"**

1. Check VulnZap API key configuration: `Security: Configure VulnZap API`
2. Verify internet connection for API calls
3. Check VS Code output panel for errors
4. Ensure supported file type is being analyzed

**"Analysis taking too long"**

1. Check file size (limit: 1MB, 2000 lines)
2. Verify API key validity and quota
3. Check if fallback mode is active
4. Adjust confidence threshold in settings

**"Files not being scanned"**

1. Check if file type is supported (JS/TS/Python/Java/PHP/C#)
2. Verify file isn't in excluded list (package.json, config files, etc.)
3. Use `Security: Show File Exclusion Information` to see exclusion rules
4. Add custom patterns to `vulnzap.excludeFilePatterns` if needed

**"No security issues detected"**

1. Verify file language is supported (JS/TS/Python/Java)
2. Check if real-time scanning is enabled
3. Try manual scan: `Security: Scan Current File`
4. Review confidence threshold settings (default: 80%)

**"Dependency scanning not working"**

1. Ensure dependency files exist (package.json, requirements.txt, etc.)
2. Check VulnZap API configuration
3. Verify `vulnzap.enableDependencyScanning` is true
4. Try `Security: Force Dependency Scan (Ignore Cache)`

**"Indexing issues"**

1. Check if indexing is enabled: `vulnzap.enableVectorIndexing`
2. Try rebuilding index: `Security: Build Security Index`
3. View statistics: `Security: View Index Statistics`
4. Clear and rebuild if corrupted: `Security: Clear Security Index`

### Getting Support

- 📝 **GitHub Issues**: [Report bugs and request features](https://github.com/VulnZap/vulnzap-vscode-extention/issues)
- 📖 **Documentation**: Check VS Code settings for configuration options
- 🔧 **API Status**: Verify VulnZap API service status
- 💬 **Community**: Join discussions in our GitHub repository

## 🔧 Configuration & File Exclusions

### VS Code Settings

VulnZap can be customized through VS Code settings (`Preferences: Open Settings (UI)` → Search "VulnZap"):

- **vulnzap.enabled**: Enable/disable security scanning
- **vulnzap.vulnzapApiKey**: Your VulnZap API key for enhanced analysis
- **vulnzap.maxFileSizeBytes**: Maximum file size to scan (default: 1MB)
- **vulnzap.maxFileLines**: Maximum lines per file to scan (default: 2000)
- **vulnzap.excludeFilePatterns**: Additional file patterns to exclude from scanning

### File Exclusions

VulnZap automatically excludes common non-code files from security scanning:

**📁 Excluded Directories:** `node_modules/`, `dist/`, `build/`, `target/`, `.git/`, `vendor/`, `__pycache__/`, etc.

**📄 Excluded Files:**

- Configuration: `package.json`, `tsconfig.json`, `webpack.config.js`, `.env`, etc.
- Documentation: `README.md`, `CHANGELOG.md`, `LICENSE`, etc.
- Media: `*.png`, `*.jpg`, `*.mp4`, `*.svg`, etc.
- Generated: `*.min.js`, `*.bundle.js`, `*.map`, etc.
- Tests: `*.test.js`, `*.spec.ts`, `*.stories.jsx`, etc.

**🎯 Custom Exclusions:**

```json
{
  "vulnzap.excludeFilePatterns": ["*.config.js", "test/**/*.js", "docs/**/*"]
}
```

**📊 View Exclusions:** Use `Security: Show File Exclusion Information` command to see complete statistics.

## 📈 Roadmap

### Upcoming Features

- **Additional Language Support**: Go, Rust, C++, PHP support
- **Enhanced AI Models**: Support for additional AI providers
- **Custom Rules**: User-defined security patterns and rules
- **Team Collaboration**: Shared configurations and rule sets
- **CI/CD Integration**: GitHub Actions, GitLab CI support
- **Advanced Reporting**: Security dashboards and metrics
- **IDE Integration**: Support for JetBrains IDEs, Vim, Emacs

### Current Version: 0.2.1

- ✅ VulnZap API integration
- ✅ Advanced dependency scanning with caching
- ✅ Codebase indexing and vector analysis
- ✅ AST-guided precision for JavaScript/TypeScript
- ✅ Unified security view with dependency management
- ✅ Pattern-based fallback detection
- ✅ Performance optimizations and file size limits

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Made with ❤️ by the VulnZap Team**

_Secure your code, one vulnerability at a time._
