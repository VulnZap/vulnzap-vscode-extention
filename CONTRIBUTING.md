# Contributing to VulnZap VS Code Extension

First off, thank you for considering contributing to VulnZap! 🎉 

VulnZap is a community-driven project, and we welcome contributions from developers of all skill levels. Whether you're fixing bugs, adding features, improving documentation, or helping with testing, your contribution is valuable.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Environment Setup](#development-environment-setup)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Pull Request Process](#pull-request-process)
- [Issue Guidelines](#issue-guidelines)
- [Security Contributions](#security-contributions)
- [Documentation](#documentation)
- [Community](#community)

## 📜 Code of Conduct

This project and everyone participating in it is governed by our Code of Conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior to [anirudh@plawlabs.com](mailto:anirudh@plawlabs.com).

### Our Pledge
- Be welcoming to newcomers
- Be respectful of differing viewpoints and experiences
- Focus on what is best for the community
- Show empathy towards other community members

## 🤝 How Can I Contribute?

### 🐛 Reporting Bugs
Before creating bug reports, please check the existing issues to avoid duplicates. When creating a bug report, include:

- **Clear title and description**
- **Steps to reproduce** the issue
- **Expected vs actual behavior**
- **Screenshots or GIFs** if applicable
- **Environment details**:
  - VS Code version
  - Extension version
  - Operating system
  - Node.js version
  - AI provider being used

### 💡 Suggesting Enhancements
Enhancement suggestions are welcome! Please include:

- **Clear description** of the enhancement
- **Use case** or problem it solves
- **Proposed solution** or implementation ideas
- **Alternative solutions** considered
- **Impact assessment** (performance, security, usability)

### 🔧 Code Contributions
- **Bug fixes**: Always welcome!
- **New features**: Please discuss in an issue first
- **Performance improvements**: Include benchmarks
- **Security enhancements**: Follow our security guidelines
- **Documentation**: Help make our docs better

### 🧪 Testing
- **Manual testing**: Try the extension with different languages and scenarios
- **Regression testing**: Ensure new changes don't break existing functionality
- **Performance testing**: Test with large files and various AI providers
- **Security testing**: Validate vulnerability detection accuracy

## 🛠️ Development Environment Setup

### Prerequisites
```bash
# Required versions
Node.js >= 16.x
npm >= 7.x
VS Code >= 1.101.0
TypeScript >= 4.9.x
```

### Step-by-Step Setup

1. **Fork and Clone**
   ```bash
   # Fork the repository on GitHub first
   git clone https://github.com/YOUR_USERNAME/vscode-extension.git
   cd vscode-extension
   ```

2. **Install Dependencies**
   ```bash
   npm install
   ```

3. **Build the Extension**
   ```bash
   npm run compile
   ```

4. **Open in VS Code**
   ```bash
   code .
   ```

5. **Launch Development Environment**
   - Press `F5` or go to `Run > Start Debugging`
   - This opens a new VS Code window with your extension loaded
   - The Extension Development Host window shows debug output

### Useful Commands

```bash
# Watch mode for continuous compilation
npm run watch

# Compile once
npm run compile

# Package extension
npm run vscode:prepublish

# Format code (when available)
npm run format

# Lint code (when available)
npm run lint
```

### VS Code Configuration

Add these to your `.vscode/settings.json` for optimal development:

```json
{
  "typescript.preferences.useAliasesForRenames": false,
  "typescript.suggest.autoImports": true,
  "editor.formatOnSave": true,
  "editor.codeActionsOnSave": {
    "source.organizeImports": true
  },
  "files.associations": {
    "*.ts": "typescript"
  }
}
```

## 🔄 Development Workflow

### Branching Strategy

We use **GitHub Flow** for simplicity:

```bash
# Create a feature branch from main
git checkout -b feature/add-new-detection

# Make your changes
git add .
git commit -m "Add detection for XYZ vulnerability"

# Push to your fork
git push origin feature/add-new-detection

# Create a Pull Request on GitHub
```

### Branch Naming Convention

- `feature/description` - New features
- `fix/description` - Bug fixes
- `docs/description` - Documentation updates
- `perf/description` - Performance improvements
- `security/description` - Security-related changes

### Commit Message Guidelines

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```bash
# Format
type(scope): description

# Examples
feat(analyzer): add support for Python async/await patterns
fix(diagnostics): resolve memory leak in caching
docs(readme): update installation instructions
test(security): add test cases for SQL injection detection
perf(api): optimize API request batching
```

Types:
- `feat`: New features
- `fix`: Bug fixes
- `docs`: Documentation
- `test`: Tests
- `perf`: Performance
- `refactor`: Code refactoring
- `style`: Formatting
- `chore`: Maintenance

## 📝 Coding Standards

### TypeScript Guidelines

1. **Use TypeScript strictly**
   ```typescript
   // ✅ Good - explicit types
   function analyzeCode(code: string, language: string): SecurityIssue[] {
     return [];
   }

   // ❌ Avoid - implicit any
   function analyzeCode(code, language) {
     return [];
   }
   ```

2. **Follow consistent naming**
   ```typescript
   // Classes: PascalCase
   class SecurityAnalyzer {}

   // Functions/variables: camelCase
   const analyzeCodeSecurity = () => {};

   // Constants: UPPER_SNAKE_CASE
   const MAX_FILE_SIZE = 10000;

   // Interfaces: PascalCase
   interface SecurityIssue {}
   ```

3. **Use async/await over promises**
   ```typescript
   // ✅ Good
   async function analyzeWithAI(code: string): Promise<SecurityIssue[]> {
     try {
       const result = await apiProvider.analyze(code);
       return result.issues;
     } catch (error) {
       console.error('Analysis failed:', error);
       return [];
     }
   }
   ```

4. **Error handling**
   ```typescript
   // ✅ Good - specific error handling
   try {
     const analysis = await performAnalysis(code);
     return analysis;
   } catch (error) {
     if (error instanceof APIRateLimitError) {
       await this.backoffAndRetry();
     } else if (error instanceof NetworkError) {
       return this.fallbackAnalysis(code);
     } else {
       console.error('Unexpected analysis error:', error);
       throw error;
     }
   }
   ```

### Code Organization

1. **File structure**
   ```
   src/
   ├── extension.ts           # Main entry point
   ├── securityAnalyzer.ts    # Core analysis logic
   ├── diagnosticProvider.ts  # VS Code diagnostics
   ├── apiProviders.ts        # AI provider implementations
   └── utils/                 # Utility functions
   ```

2. **Import organization**
   ```typescript
   // 1. Node.js modules
   import * as fs from 'fs';
   import * as path from 'path';

   // 2. VS Code API
   import * as vscode from 'vscode';

   // 3. Third-party modules
   import axios from 'axios';

   // 4. Local modules (relative imports)
   import { SecurityAnalyzer } from './securityAnalyzer';
   ```

## 🧪 Testing Guidelines

### Manual Testing Checklist

Before submitting a PR, test these scenarios:

#### Basic Functionality
- [ ] Extension activates on supported file types (JS, TS, Python, Java)
- [ ] Security issues are highlighted with appropriate colors
- [ ] Hover tooltips show detailed information
- [ ] Commands work from Command Palette
- [ ] Status bar shows correct state

#### AI Provider Testing
- [ ] Test with different AI providers (OpenAI, Gemini, OpenRouter)
- [ ] Verify API key configuration works
- [ ] Test provider switching
- [ ] Verify error handling for invalid keys
- [ ] Test rate limiting and backoff

#### Security Detection Testing
- [ ] Test detection accuracy on sample vulnerable code
- [ ] Verify no false positives on secure code patterns
- [ ] Test different programming languages
- [ ] Check confidence scores are reasonable
- [ ] Verify CVE information when available

#### Performance Testing
- [ ] Test with large files (>10,000 characters)
- [ ] Verify reasonable response times (<3 seconds)
- [ ] Check memory usage doesn't grow excessively
- [ ] Test caching behavior

### Test Files

Create test files in the `test-samples/` directory:

```javascript
// test-samples/sql-injection-test.js
const userId = req.params.id;

// This should be detected as SQL injection
const query = `SELECT * FROM users WHERE id = ${userId}`;
db.query(query);

// This should be safe
const safeQuery = 'SELECT * FROM users WHERE id = ?';
db.query(safeQuery, [userId]);
```

## 🔄 Pull Request Process

### Before Submitting

1. **Update your branch**
   ```bash
   git checkout main
   git pull upstream main
   git checkout your-feature-branch
   git rebase main
   ```

2. **Test thoroughly**
   - Run manual tests from the checklist
   - Test with different AI providers
   - Verify no regressions

3. **Update documentation**
   - Update README if needed
   - Add comments for new APIs
   - Update CHANGELOG.md if it exists

### PR Description Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update

## How Has This Been Tested?
Describe the tests you ran and how to reproduce them.

## Screenshots (if applicable)
Add screenshots to help explain your changes.

## Checklist
- [ ] My code follows the style guidelines of this project
- [ ] I have performed a self-review of my own code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I have made corresponding changes to the documentation
- [ ] My changes generate no new warnings
- [ ] I have tested with multiple AI providers
- [ ] I have tested with different programming languages
```

## 🔒 Security Contributions

### Reporting Security Vulnerabilities

**DO NOT** create public issues for security vulnerabilities. Instead:

1. Email [anirudh@plawlabs.com](mailto:anirudh@plawlabs.com)
2. Include detailed description and reproduction steps
3. Wait for confirmation before public disclosure
4. Follow responsible disclosure guidelines

### Adding Security Detections

When adding new vulnerability detection:

1. **Research thoroughly**
   - Check OWASP guidelines
   - Review CVE databases
   - Study real-world examples

2. **Implement carefully**
   - Minimize false positives
   - Provide accurate confidence scores
   - Include remediation guidance

3. **Test extensively**
   - Test with various code patterns
   - Verify no false positives on legitimate code
   - Test across different languages

## 📚 Documentation

### Types of Documentation

1. **Code documentation** - Inline comments
2. **User documentation** - README, usage guides
3. **Developer documentation** - This contributing guide
4. **API documentation** - For extension APIs

### Documentation Standards

1. **Clear and concise** writing
2. **Code examples** for all features
3. **Screenshots** for UI features
4. **Keep it updated** with code changes

## 💬 Community

### Getting Help

- **GitHub Issues** - For bugs and feature requests
- **GitHub Discussions** - For questions and ideas
- **Email** - [anirudh@plawlabs.com](mailto:anirudh@plawlabs.com) for general inquiries

### Community Guidelines

1. **Be respectful** and inclusive
2. **Help newcomers** get started
3. **Share knowledge** and best practices
4. **Provide constructive feedback**
5. **Follow the Code of Conduct**

---

## 🙏 Thank You

Thank you for taking the time to contribute to VulnZap! Every contribution, no matter how small, helps make the development community more secure.

### Questions?

If you have any questions about contributing, please:

1. Check this guide first
2. Search existing GitHub discussions
3. Create a new discussion or issue
4. Email us at [support@plawlabs.com](mailto:support@plawlabs.com)

---

**Happy contributing!** 🚀

*Last updated: July 2025* 