# VulnZap - AI-Powered Security Reviewer for VS Code

[![Version](https://img.shields.io/vscode-marketplace/v/vulnzap.vulnzap.svg)](https://marketplace.visualstudio.com/items?itemName=vulnzap.vulnzap)
[![Downloads](https://img.shields.io/vscode-marketplace/d/vulnzap.vulnzap.svg)](https://marketplace.visualstudio.com/items?itemName=vulnzap.vulnzap)
[![Rating](https://img.shields.io/vscode-marketplace/r/vulnzap.vulnzap.svg)](https://marketplace.visualstudio.com/items?itemName=vulnzap.vulnzap)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A powerful Visual Studio Code extension that provides **real-time, AI-powered security analysis** for your code. VulnZap detects vulnerabilities like XSS, SQL injection, weak cryptography, and more with high accuracy across multiple programming languages.

With an intuitive webview-based interface, login system, and comprehensive dependency scanning, VulnZap provides enterprise-grade security analysis directly in your development environment.

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

### 1. Sign In to VulnZap

After installing the extension:

1. Look for the VulnZap shield icon in the Activity Bar (left sidebar)
2. Click **"Sign In"** in the VulnZap panel
3. This will open your browser to authenticate with VulnZap
4. Once authenticated, return to VS Code - you're ready to scan!

### 2. Alternative: Manual API Configuration

If you prefer to configure manually:

Press `Ctrl+Shift+P` (Windows/Linux) or `Cmd+Shift+P` (Mac) and run:

```
Security: Configure VulnZap API
```

### 3. Getting Your VulnZap Account

1. Visit [VulnZap Platform](https://vulnzap.com)
2. Create an account (free tier available)
3. Your API credentials will be managed automatically after login

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

### Authentication Commands

| Command                               | Description                          |
| ------------------------------------- | ------------------------------------ |
| **Security: Log In to VulnZap**      | Sign in to your VulnZap account     |
| **Security: Sign Out of VulnZap**    | Sign out from VulnZap               |

### Dependency Scanning Commands

| Command                                             | Description                          |
| --------------------------------------------------- | ------------------------------------ |
| **Security: Scan Dependencies for Vulnerabilities** | Scan all dependencies in workspace   |
| **Security: Force Dependency Scan (Ignore Cache)**  | Fresh dependency scan ignoring cache |
| **Security: View Dependency Cache Statistics**      | Show cache status and statistics     |
| **Security: Clean Dependency Cache**                | Remove expired cache entries         |
| **Security: Fix All Dependencies**                  | Update all vulnerable dependencies   |
| **Security: Show Update Command**                   | Display terminal commands for updates|
| **Security: Show VulnZap Output Logs**              | View detailed extension logs         |
| **Security: Show File Exclusion Information**       | View file exclusion statistics       |
| **Security: Optimize Layout for VulnZap**           | Optimize VS Code layout for security work |

### VulnZap Activity Bar Panel

The VulnZap panel in the Activity Bar shows:

- **Login View**: When not authenticated, shows sign-in options
- **Usage Bar**: Real-time API usage tracking and quota monitoring
- **Security Analysis**: Comprehensive view of all detected issues and vulnerabilities
- **Dependency Management**: Interactive tools for fixing vulnerable dependencies

## 📋 Configuration Options

Open VS Code settings (`Ctrl+,`) and search for "VulnZap":

### Basic Settings

```json
{
  "vulnzap.enabled": true,
  "vulnzap.severity": "warning"
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

### Additional Settings

```json
{
  "vulnzap.vulnzapApiKey": "",
  "vulnzap.enableDebugLogging": false,
  "vulnzap.excludeFilePatterns": []
}
```

**Note**: File size limits (1MB), line limits (2000 lines), and performance settings are automatically managed by the extension for optimal performance.

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
│   ├── security/             # Security analysis components
│   │   ├── codebaseSecurityAnalyzer.ts # AI-powered security analysis
│   │   └── index.ts          # Security exports
│   ├── dependencies/         # Dependency vulnerability scanning
│   │   ├── dependencyScanner.ts  # Main scanning orchestrator
│   │   ├── dependencyParser.ts   # Multi-ecosystem dependency parsing
│   │   ├── dependencyCache.ts    # Intelligent result caching
│   │   └── index.ts          # Dependency exports
│   ├── providers/            # VS Code integration providers
│   │   ├── apiProviders.ts       # API provider management
│   │   ├── diagnosticProvider.ts # VS Code diagnostics integration
│   │   ├── dependencyDiagnosticProvider.ts # Dependency diagnostics
│   │   ├── codeActionProvider.ts # Code action provider for fixes
│   │   ├── securityViewProvider.ts # Security webview provider
│   │   └── index.ts          # Provider exports
│   ├── webview/              # Webview components for modern UI
│   │   ├── LoginWebviewProvider.ts    # Login interface
│   │   ├── SecurityWebviewProvider.ts # Security dashboard
│   │   ├── UsageBarWebviewProvider.ts # Usage tracking display
│   │   └── index.ts          # Webview exports
│   ├── utils/                # Utility functions
│   │   ├── config.ts         # Extension configuration
│   │   ├── logger.ts         # Centralized logging
│   │   ├── fileExclusions.ts # File exclusion management
│   │   ├── usageService.ts   # Usage tracking service
│   │   └── index.ts          # Utility exports
│   └── index.ts              # Main exports
├── media/                    # Static assets for webviews
│   ├── login.css             # Login interface styles
│   ├── login.js              # Login interface scripts
│   ├── security.css          # Security dashboard styles
│   ├── security.js           # Security dashboard scripts
│   ├── usageBar.css          # Usage bar styles
│   ├── usageBar.js           # Usage bar scripts
│   └── icons.js              # Icon definitions
├── package.json              # Extension manifest and dependencies
├── tsconfig.json            # TypeScript configuration
├── webpack.config.js        # Build configuration
└── README.md               # This file
```

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

- **File Size Limit**: 1MB per file for analysis (automatically enforced)
- **File Line Limit**: 2000 lines per file (automatically enforced)
- **Max Issues per File**: 100 issues to prevent overwhelming output
- **Dependency Caching**: Intelligent caching system with change detection
- **Memory Usage**: Optimized for large codebases with efficient scanning
- **Network Failures**: Graceful error handling and user feedback
- **File Exclusions**: Comprehensive exclusion system for non-code files

## 🔒 Security & Privacy

- **Secure Authentication**: OAuth-based login with secure token storage
- **API Keys**: Stored securely in VS Code's encrypted storage
- **Code Privacy**: Code sent to VulnZap API for analysis only
- **No Data Storage**: Your code is never permanently stored on external servers
- **Configurable Scanning**: All features can be enabled/disabled per preference
- **Usage Tracking**: Transparent usage monitoring

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

1. Check if file type is supported (JS/TS/React/Python/Java/PHP/C#)
2. Verify file isn't in excluded list (package.json, config files, etc.)
3. Use `Security: Show File Exclusion Information` to see exclusion rules
4. Add custom patterns to `vulnzap.excludeFilePatterns` if needed

**"No security issues detected"**

1. Verify file language is supported (JS/TS/React/Python/Java/PHP/C#)
2. Check if you're logged in to VulnZap
3. Try manual scan: `Security: Scan Current File`
4. Check network connectivity for API calls

**"Dependency scanning not working"**

1. Ensure dependency files exist (package.json, requirements.txt, etc.)
2. Check VulnZap API configuration
3. Verify `vulnzap.enableDependencyScanning` is true
4. Try `Security: Force Dependency Scan (Ignore Cache)`

### Getting Support

- 📝 **GitHub Issues**: [Report bugs and request features](https://github.com/VulnZap/vulnzap-vscode-extention/issues)
- 📖 **Documentation**: Check VS Code settings for configuration options
- 🔧 **API Status**: Verify VulnZap API service status
- 💬 **Community**: Join discussions in our GitHub repository

## 🔧 File Exclusions & Performance

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

- **Additional Language Support**: Go, Rust, C++, Ruby, Kotlin support
- **Enhanced Webview Features**: Advanced filtering, sorting, and export options
- **Custom Rules**: User-defined security patterns and rules
- **Team Collaboration**: Shared configurations and rule sets
- **CI/CD Integration**: GitHub Actions, GitLab CI support
- **Advanced Reporting**: Detailed security metrics and trends

## 🆕 What's New in v0.2.9

### Major UI Overhaul
- **Modern Webview Interface**: Complete redesign with integrated login system
- **Real-time Usage Tracking**: Monitor your API usage and quotas directly in VS Code
- **Interactive Security Dashboard**: Comprehensive view of all security issues with one-click fixes

### Enhanced Dependency Management
- **11+ Package Managers**: Support for npm, pip, go, cargo, maven, gradle, composer, rubygems, nuget, cocoapods, and yarn
- **Smart Caching System**: Intelligent dependency change detection
- **One-click Fixes**: Direct dependency updates with terminal command generation
- **Batch Vulnerability Scanning**: Efficient API-based vulnerability detection

### Improved Developer Experience
- **Seamless Authentication**: OAuth-based login with secure session management
- **Comprehensive File Exclusions**: Smart exclusion of 100+ file types and patterns
- **Enhanced Logging**: Detailed debug information for troubleshooting
- **Performance Optimizations**: Better handling of large codebases

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Made with ❤️ by the Plawlabs Team**

_Secure your code, one vulnerability at a time._
