# VulnZap - AI-Powered Security Reviewer for VS Code

[![Version](https://img.shields.io/vscode-marketplace/v/vulnzap.vulnzap.svg)](https://marketplace.visualstudio.com/items?itemName=vulnzap.vulnzap)
[![Downloads](https://img.shields.io/vscode-marketplace/d/vulnzap.vulnzap.svg)](https://marketplace.visualstudio.com/items?itemName=vulnzap.vulnzap)
[![Rating](https://img.shields.io/vscode-marketplace/r/vulnzap.vulnzap.svg)](https://marketplace.visualstudio.com/items?itemName=vulnzap.vulnzap)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A powerful Visual Studio Code extension that provides **real-time, AI-powered security analysis** for your code. VulnZap detects vulnerabilities like XSS, SQL injection, weak cryptography, and more with high accuracy across multiple programming languages.

![VulnZap Demo](https://raw.githubusercontent.com/VulnZap/vulnzap-vscode-extention/main/demo.gif)

## ✨ Features

### 🤖 Multi-Provider AI Analysis
- **OpenAI GPT Models**: GPT-3.5, GPT-4, and GPT-4 Turbo
- **Google Gemini**: Advanced Gemini Pro models
- **OpenRouter**: Access to Claude, Llama, Mixtral, and more
- **VulnZap Custom API**: Specialized security-focused analysis
- **Intelligent Fallback**: Pattern-based detection when AI is unavailable

### 🔍 Comprehensive Security Coverage
- **OWASP Top 10**: Complete coverage of major security risks
- **Code Injection**: SQL injection, command injection, XSS, and LDAP injection
- **Authentication & Authorization**: Weak authentication patterns and privilege escalation
- **Cryptographic Issues**: Weak algorithms, insecure random generation, and key management
- **Data Exposure**: Sensitive data leaks, insecure storage, and logging issues
- **Configuration Issues**: Security misconfigurations and hardcoded secrets

### 🌐 Multi-Language Support
- **JavaScript & TypeScript**: Full ES6+ and Node.js support
- **Python**: Django, Flask, FastAPI, and standard library
- **Java**: Spring, servlet-based applications, and enterprise patterns
- **And more**: Expanding language support based on community needs

### 🔄 Smart Analysis Features
- **Real-time Scanning**: Analysis as you type with configurable delays
- **Confidence Scoring**: Each finding includes accuracy confidence (0-100%)
- **Context-Aware Detection**: Understands code patterns beyond simple regex
- **CVE Integration**: Links findings to known vulnerabilities when applicable
- **Smart Caching**: Reduces API calls while maintaining accuracy
- **Performance Optimization**: Handles large files efficiently

### 📊 Enhanced Vulnerability Research
- **Google Search Integration**: Automatic CVE and vulnerability research
- **Security Intelligence**: Real-time updates from security databases
- **Research Summaries**: Contextual information for better understanding
- **Remediation Guidance**: Specific, actionable fix recommendations

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

### 1. Choose Your AI Provider
Press `Ctrl+Shift+P` (Windows/Linux) or `Cmd+Shift+P` (Mac) and run:
```
Security: Select AI Provider
```

Available providers:
- **OpenAI**: Requires OpenAI API key
- **Google Gemini**: Requires Google AI API key (free tier available)
- **OpenRouter**: Access to multiple models with one API key
- **VulnZap**: Specialized security analysis (beta)

### 2. Configure API Keys
Run the command:
```
Security: Configure API Keys
```

#### Getting API Keys

**Google Gemini (Recommended for beginners)**
1. Visit [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Create a new API key
3. Enter it when prompted in VS Code

**OpenAI**
1. Visit [OpenAI API Platform](https://platform.openai.com/api-keys)
2. Create a new secret key
3. Enter it when prompted in VS Code

**OpenRouter**
1. Visit [OpenRouter](https://openrouter.ai/keys)
2. Create an API key
3. Choose from multiple AI models

### 3. Optional: Enhanced Research
For vulnerability research and CVE detection:
1. Get a [Google Custom Search API key](https://developers.google.com/custom-search/v1/introduction)
2. Create a [Custom Search Engine](https://cse.google.com/cse/)
3. Configure both in the extension settings

## 🎯 Usage

### Automatic Scanning
VulnZap automatically scans your code as you type. Security issues appear as:
- 🔴 **Red squiggles**: Critical vulnerabilities (high confidence)
- 🟡 **Yellow squiggles**: Security warnings (medium confidence)  
- 🔵 **Blue squiggles**: Security recommendations (informational)

### Manual Commands
| Command | Shortcut | Description |
|---------|----------|-------------|
| Security: Scan Current File | `Ctrl+Shift+S` | Force scan the active file |
| Security: Enable Security Review | - | Enable real-time scanning |
| Security: Disable Security Review | - | Disable all scanning |
| Security: Select AI Provider | - | Choose your AI provider |
| Security: Configure API Keys | - | Set up API credentials |

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
  "vulnzap.scanDelay": 1000,
  "vulnzap.severity": "warning",
  "vulnzap.confidenceThreshold": 80
}
```

### AI Provider Settings
```json
{
  "vulnzap.apiProvider": "gemini",
  "vulnzap.enableAIAnalysis": true,
  "vulnzap.enableSearchEnhancement": true
}
```

### Performance Settings
```json
{
  "vulnzap.scanDelay": 1000,
  "vulnzap.confidenceThreshold": 80
}
```

## 🔍 Example Detections

### SQL Injection
```javascript
// ❌ Detected: SQL injection vulnerability (Confidence: 95%)
const query = `SELECT * FROM users WHERE id = ${userId}`;
db.query(query);

// ✅ Suggested: Use parameterized queries
const query = 'SELECT * FROM users WHERE id = ?';
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

## 🛠️ Development & Contributing

### Prerequisites
- **Node.js** 16.x or higher
- **npm** 7.x or higher
- **Visual Studio Code** 1.101.0 or higher
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
vulnzap-vscode-extention/
├── src/
│   ├── extension.ts          # Main extension entry point
│   ├── securityAnalyzer.ts   # Core security analysis logic
│   ├── diagnosticProvider.ts # VS Code diagnostics integration
│   └── apiProviders.ts       # AI provider implementations
├── test-samples/             # Sample vulnerable code for testing
├── package.json             # Extension manifest and dependencies
├── tsconfig.json           # TypeScript configuration
└── README.md               # This file
```

### Testing Your Changes

1. **Manual Testing**
   - Open test files from `test-samples/`
   - Verify security issues are detected
   - Test different AI providers

2. **Test with Different Languages**
   - Create test files in JavaScript, Python, Java
   - Ensure proper syntax highlighting and detection

3. **Performance Testing**
   - Test with large files (>10,000 characters)
   - Verify caching behavior
   - Test network failure scenarios

### Debugging

1. **Enable Developer Tools**
   - In the Extension Development Host, press `Ctrl+Shift+I`
   - Check Console for error messages

2. **Extension Logs**
   - View → Output → Select "VulnZap"
   - Check for API errors or parsing issues

3. **VS Code Debugging**
   - Set breakpoints in TypeScript files
   - Use F5 to debug the extension

### Building for Production

```bash
# Install vsce globally
npm install -g @vscode/vsce

# Package extension
vsce package

# This creates a .vsix file for distribution
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

- **File Size Limit**: 10,000 characters per file for AI analysis
- **Caching Duration**: 5 minutes to reduce API costs
- **Rate Limiting**: Automatic backoff for API limits
- **Memory Usage**: Optimized for large codebases
- **Network Failures**: Graceful fallback to pattern matching

## 🔒 Security & Privacy

- **API Keys**: Stored securely in VS Code's encrypted storage
- **Code Privacy**: Code sent to AI providers for analysis only
- **No Data Storage**: Your code is never stored on external servers
- **Optional Features**: All external integrations can be disabled
- **Local Fallback**: Works offline with pattern-based detection

## 🧪 Supported Vulnerability Types

### OWASP Top 10 Coverage
- **A01: Broken Access Control** - Authorization bypass, privilege escalation
- **A02: Cryptographic Failures** - Weak encryption, insecure storage
- **A03: Injection** - SQL, NoSQL, command, LDAP injection
- **A04: Insecure Design** - Design flaws and threat modeling gaps
- **A05: Security Misconfiguration** - Default configs, verbose errors
- **A06: Vulnerable Components** - Outdated dependencies (when configured)
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

## 🆘 Troubleshooting

### Common Issues

**"Extension not working"**
1. Check API key configuration: `Security: Configure API Keys`
2. Verify internet connection
3. Check VS Code output panel for errors
4. Try switching AI providers

**"Analysis taking too long"**
1. Check file size (limit: 10,000 characters)
2. Verify API key validity and quota
3. Check if fallback mode is active
4. Adjust confidence threshold in settings

**"No security issues detected"**
1. Verify file language is supported
2. Check if real-time scanning is enabled
3. Try manual scan: `Security: Scan Current File`
4. Review confidence threshold settings

**"API errors or rate limiting"**
1. Check API key validity and billing
2. Try switching to a different provider
3. Increase scan delay in settings
4. Enable fallback mode for offline use

### Getting Support

- 📝 **GitHub Issues**: [Report bugs and request features](https://github.com/VulnZap/vulnzap-vscode-extention/issues)
- 📖 **Documentation**: Check VS Code settings for configuration options
- 🔧 **API Status**: Verify provider service status
- 💬 **Community**: Join discussions in our GitHub repository

## 📈 Roadmap

### Upcoming Features
- **IDE Integration**: Support for JetBrains IDEs, Vim, Emacs
- **Custom Rules**: User-defined security patterns
- **Team Collaboration**: Shared configurations and rule sets
- **CI/CD Integration**: GitHub Actions, GitLab CI support
- **Advanced Reporting**: Security dashboards and metrics
- **More Languages**: Go, Rust, C++, PHP support

### Community Requests
Vote for features and view progress on our [GitHub Discussions](https://github.com/VulnZap/vulnzap-vscode-extention/discussions) page.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **OWASP**: For security guidelines and vulnerability classifications
- **VS Code Team**: For the excellent extension API and documentation
- **AI Providers**: OpenAI, Google, Anthropic for powering our analysis
- **Security Community**: For continuous feedback and vulnerability research
- **Contributors**: All developers who help improve VulnZap

---

**🛡️ Secure your code with AI-powered intelligence**

Built with ❤️ by the VulnZap team | [Website](https://vulnzap.com) | [GitHub](https://github.com/VulnZap) | [Support](mailto:support@vulnzap.com) 