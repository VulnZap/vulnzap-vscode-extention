# VulnZap Code Scan API - Server Implementation Guide



## API Endpoints

### 1. Code Analysis Endpoint

#### Request Body Structure

```json
{
  "code": "const user = req.query.id;\nconst query = `SELECT * FROM users WHERE id = ${user}`;",
  "language": "javascript", 
  "prompt": "AST-guided security analysis for javascript code. Use AST guidance for PRECISE vulnerability detection.\n\nAST ANALYSIS FOUND:\n- 3 security-relevant nodes out of 25 total AST nodes\n- Template literal with variable interpolation at line 2\n- Variable assignment from user input at line 1\n- Potential SQL injection pattern detected\n\nFOCUS ON THESE SPECIFIC AST NODES:\n1. Line 1: VariableDeclarator - user input assignment\n2. Line 2: TemplateLiteral - SQL query construction with ${user}\n3. Line 2: CallExpression - potential database query\n\nPRECISION REQUIREMENTS:\n- Point to EXACT character positions where vulnerabilities exist\n- Use AST node information for pinpoint accuracy\n- Focus on the template literal interpolation: ${user}\n\nRESPONSE FORMAT:\nReturn a JSON response with this exact structure:\n\n{\n  \"issues\": [\n    {\n      \"line\": 2,\n      \"column\": 47,\n      \"endLine\": 2,\n      \"endColumn\": 53,\n      \"message\": \"SQL injection vulnerability in template literal\",\n      \"severity\": \"error\",\n      \"code\": \"SQL_INJECTION\",\n      \"suggestion\": \"Use parameterized queries\",\n      \"confidence\": 95,\n      \"cve\": [\"CWE-89\"],\n      \"searchQuery\": \"SQL injection prevention\"\n    }\n  ],\n  \"summary\": \"Found 1 critical vulnerability using AST guidance\",\n  \"overallRisk\": \"high\"\n}\n\nCode to analyze:\n```javascript\n1: const user = req.query.id;\n2: const query = `SELECT * FROM users WHERE id = ${user}`;\n```",
  "astGuidance": {
    "securityNodes": 3,
    "totalNodes": 25,
    "precisionMode": true
  },
  "options": {
    "fastScan": false,
    "includeLineNumbers": true,
    "maxLines": 200,
    "astGuided": true
  }
}
```

#### Request Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `code` | string | Yes | Source code to analyze (max 50,000 chars) |
| `language` | string | Yes | Programming language (javascript, typescript, python, java, etc.) |
| `prompt` | string | Yes | Complete analysis prompt (built by extension) |
| `astGuidance` | object | No | AST analysis metadata (only for AST-guided requests) |
| `astGuidance.securityNodes` | number | No | Number of security-relevant AST nodes found |
| `astGuidance.totalNodes` | number | No | Total AST nodes analyzed |
| `astGuidance.precisionMode` | boolean | No | Whether precision mode is enabled |
| `options.fastScan` | boolean | No | Fast scan mode for critical vulns only (default: false) |
| `options.includeLineNumbers` | boolean | No | Include line numbers in analysis (default: true) |
| `options.maxLines` | number | No | Maximum lines to analyze (default: 200) |
| `options.astGuided` | boolean | No | Whether this is AST-guided analysis (default: false) |

#### Response Format

The API should return the **exact same format** 
```json
{
  "success": true,
  "data": {
    "issues": [
      {
        "line": 2,
        "column": 15,
        "endLine": 2,
        "endColumn": 65,
        "message": "SQL injection vulnerability detected in dynamic query construction",
        "severity": "error",
        "code": "SQL_INJECTION",
        "suggestion": "Use parameterized queries or prepared statements to prevent SQL injection",
        "confidence": 95,
        "cve": ["CWE-89"],
        "searchQuery": "SQL injection prevention",
        "precise": true,
        "astNodeId": 15
      }
    ],
    "summary": "Found 1 critical security vulnerability using AST guidance",
    "overallRisk": "high",
    "analysisTime": 1250,
    "isPartial": false,
    "precision": "ast-guided"
  },
  "metadata": {
    "requestId": "req_123456789",
    "timestamp": 1703123456789,
    "model": "gemini-1.5-pro",
    "tokensUsed": 1024
  }
}
```

#### Additional Response Fields for AST-Guided Analysis

| Field | Type | Description |
|-------|------|-------------|
| `issues[].precise` | boolean | Whether this issue was precisely located using AST |
| `issues[].astNodeId` | number | ID of the AST node where vulnerability was found |
| `data.precision` | string | Analysis method: "ast-guided" or "traditional" |

#### Error Response
```json
{
  "success": false,
  "error": {
    "code": "ANALYSIS_FAILED",
    "message": "Failed to analyze code",
    "details": "Gemini API rate limit exceeded",
    "requestId": "req_123456789"
  }
}
```

## Server Implementation Guide

### Key Processing Requirements

Your server should process requests as follows:

1. **Receive the request** at `/api/v1/vulnzap/code-scan`
2. **Extract the pre-built prompt** from `request.prompt` (don't rebuild it)
3. **Send the prompt directly to Gemini** (or your AI provider)
4. **Parse the JSON response** from Gemini 
5. **Return the formatted response** to the extension

### Important Notes

- ✅ **USE the provided prompt as-is** - The extension builds AST-enhanced prompts
- ✅ **Don't rebuild prompts** - The `prompt` field contains the complete analysis instructions
- ✅ **Handle both analysis types** - Traditional and AST-guided use the same endpoint
- ✅ **Parse JSON from AI response** - Extract JSON from markdown code blocks
- ✅ **Validate line numbers** - Ensure they're within valid ranges

### 1. Basic Express Server Setup

```javascript
// server.js
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const { GoogleGenerativeAI } = require('@google/generative-ai');

const app = express();

// Security middleware
app.use(helmet());
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
  credentials: true
}));
app.use(express.json({ limit: '1mb' }));

// Initialize Gemini
const genAI = new GoogleGenerativeAI(process.env.GOOGLE_GEMINI_API_KEY);
const model = genAI.getGenerativeModel({ model: "gemini-1.5-pro" });

app.listen(process.env.PORT || 3000, () => {
  console.log(`VulnZap API server running on port ${process.env.PORT || 3000}`);
});
```

### 2. Code Analysis Route Handler

```javascript
// routes/code-scan.js
const express = require('express');
const router = express.Router();

router.post('/vulnzap/code-scan', async (req, res) => {
  const requestId = req.headers['x-request-id'] || generateRequestId();
  
  try {
    // Validate request
    const validation = validateCodeScanRequest(req.body);
    if (!validation.valid) {
      return res.status(400).json({
        success: false,
        error: {
          code: 'INVALID_REQUEST',
          message: validation.error,
          requestId
        }
      });
    }

    const { code, language, prompt, astGuidance, options = {} } = req.body;
    
    // Log analysis type for debugging
    const analysisType = options.astGuided ? 'AST-guided' : 'traditional';
    console.log(`Processing ${analysisType} analysis for ${language} (${code.length} chars)`);
    
    // Use the pre-built prompt directly (DON'T rebuild it)
    // The extension already created the perfect prompt with AST context
    
    // Call Gemini API with the provided prompt
    const startTime = Date.now();
    const result = await model.generateContent(prompt);
    const analysisTime = Date.now() - startTime;
    
    // Parse the AI response and extract JSON
    const analysis = parseAIResponse(result.response.text(), {
      language,
      astGuided: options.astGuided,
      totalLines: code.split('\n').length
    });
    
    // Prepare final response
    const responseData = {
      issues: analysis.issues,
      summary: analysis.summary,
      overallRisk: analysis.overallRisk,
      analysisTime,
      isPartial: false,
      precision: options.astGuided ? "ast-guided" : "traditional"
    };

    // Add AST metadata if available
    if (astGuidance) {
      responseData.astStats = {
        securityNodes: astGuidance.securityNodes,
        totalNodes: astGuidance.totalNodes,
        precisionMode: astGuidance.precisionMode
      };
    }

    res.json({
      success: true,
      data: responseData,
      metadata: {
        requestId,
        timestamp: Date.now(),
        model: "gemini-1.5-pro",
        tokensUsed: result.response.usageMetadata?.totalTokenCount || 0,
        analysisType
      }
    });

  } catch (error) {
    console.error(`Analysis failed for request ${requestId}:`, error);
    
    let errorCode = 'ANALYSIS_FAILED';
    let errorMessage = 'Failed to analyze code';
    
    if (error.message?.includes('rate limit')) {
      errorCode = 'RATE_LIMIT_EXCEEDED';
      errorMessage = 'API rate limit exceeded';
    } else if (error.message?.includes('quota')) {
      errorCode = 'QUOTA_EXCEEDED';
      errorMessage = 'API quota exceeded';
    }

    res.status(500).json({
      success: false,
      error: {
        code: errorCode,
        message: errorMessage,
        details: error.message,
        requestId
      }
    });
  }
});

module.exports = router;
```

### 3. Request Validation

```javascript
// utils/validation.js
function validateCodeScanRequest(body) {
  const { code, language, prompt } = body;
  
  if (!code || typeof code !== 'string') {
    return { valid: false, error: 'Code is required and must be a string' };
  }
  
  if (code.length > (parseInt(process.env.MAX_CODE_LENGTH) || 50000)) {
    return { valid: false, error: 'Code exceeds maximum length' };
  }
  
  if (!language || typeof language !== 'string') {
    return { valid: false, error: 'Language is required and must be a string' };
  }
  
  if (!prompt || typeof prompt !== 'string') {
    return { valid: false, error: 'Prompt is required and must be a string' };
  }
  
  const supportedLanguages = [
    'javascript', 'typescript', 'python', 'java', 'csharp', 'cpp', 'c',
    'php', 'ruby', 'go', 'rust', 'swift', 'kotlin', 'scala', 'dart'
  ];
  
  if (!supportedLanguages.includes(language.toLowerCase())) {
    return { valid: false, error: `Unsupported language: ${language}` };
  }
  
  return { valid: true };
}

module.exports = { validateCodeScanRequest };
```

### 4. AI Response Parser

```javascript
// utils/responseParser.js
function parseAIResponse(responseText, options = {}) {
  const { language, astGuided, totalLines } = options;
  
  try {
    // Extract JSON from AI response (handles markdown code blocks)
    const jsonMatch = responseText.match(/```json\s*([\s\S]*?)\s*```/) || 
                     responseText.match(/\{[\s\S]*\}/);
    
    if (!jsonMatch) {
      throw new Error('No JSON found in AI response');
    }
    
    const parsed = JSON.parse(jsonMatch[1] || jsonMatch[0]);
    
    if (!parsed.issues || !Array.isArray(parsed.issues)) {
      console.warn('Invalid response structure, creating empty issues array');
      parsed.issues = [];
    }
    
    // Normalize and validate issues
    const normalizedIssues = parsed.issues.map((issue, index) => {
      let line = parseInt(issue.line);
      let endLine = parseInt(issue.endLine) || line;
      let column = parseInt(issue.column) || 0;
      let endColumn = parseInt(issue.endColumn) || column;
      
      // Validate line numbers
      if (isNaN(line) || line < 1) {
        console.warn(`Invalid line number ${issue.line} in issue ${index}, defaulting to 1`);
        line = 1;
      }
      
      if (totalLines && line > totalLines) {
        console.warn(`Line number ${line} exceeds file length ${totalLines}, adjusting`);
        line = totalLines;
      }
      
      if (endLine < line) {
        endLine = line;
      }
      
      // Ensure columns are non-negative
      column = Math.max(0, column);
      endColumn = Math.max(column, endColumn);
      
      return {
        line,                    // Keep 1-based for API response
        column,
        endLine,                 // Keep 1-based for API response
        endColumn,
        message: issue.message || 'Security issue detected',
        severity: normalizeSeverity(issue.severity),
        code: issue.code || 'SECURITY_ISSUE',
        suggestion: issue.suggestion || '',
        confidence: Math.max(0, Math.min(100, parseInt(issue.confidence) || 80)),
        cve: Array.isArray(issue.cve) ? issue.cve : [],
        searchQuery: issue.searchQuery || '',
        precise: astGuided || false,
        astNodeId: issue.astNodeId || null
      };
    });
    
    return {
      issues: normalizedIssues,
      summary: parsed.summary || `Security analysis completed using ${astGuided ? 'AST-guided' : 'traditional'} method`,
      overallRisk: normalizeRisk(parsed.overallRisk)
    };
    
  } catch (error) {
    console.error('Failed to parse AI response:', error);
    return {
      issues: [],
      summary: 'Failed to parse security analysis response',
      overallRisk: 'low'
    };
  }
}

function normalizeSeverity(severity) {
  const severityMap = {
    'critical': 'error',
    'high': 'error', 
    'medium': 'warning',
    'low': 'info',
    'error': 'error',
    'warning': 'warning',
    'info': 'info'
  };
  return severityMap[severity?.toLowerCase()] || 'warning';
}

function normalizeRisk(risk) {
  const validRisks = ['low', 'medium', 'high', 'critical'];
  return validRisks.includes(risk?.toLowerCase()) ? risk.toLowerCase() : 'low';
}

module.exports = { parseAIResponse };
```

### 5. Utility Functions

```javascript
// utils/helpers.js
const crypto = require('crypto');

function generateRequestId() {
  return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

function generateCacheKey(code, language, options) {
  const content = JSON.stringify({ code, language, options });
  return crypto.createHash('md5').update(content).digest('hex');
}

// Clean expired cache entries
function cleanupCache() {
  const now = Date.now();
  const cacheExpiry = parseInt(process.env.CACHE_DURATION_MS) || 600000;
  
  for (const [key, value] of responseCache.entries()) {
    if (now - value.timestamp > cacheExpiry) {
      responseCache.delete(key);
    }
  }
}

// Run cleanup every 5 minutes
setInterval(cleanupCache, 5 * 60 * 1000);

module.exports = { generateRequestId, generateCacheKey, cleanupCache };
```

## API Testing

### Test Traditional Analysis with cURL
```bash
curl -X POST http://localhost:3000/api/v1/vulnzap/code-scan \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your_api_token" \
  -H "User-Agent: VulnZap-VSCode-Extension" \
  -H "X-Request-ID: test_traditional_123" \
  -d '{
    "code": "const user = req.query.id;\nconst query = `SELECT * FROM users WHERE id = ${user}`;",
    "language": "javascript",
    "prompt": "Comprehensive security analysis for javascript code. Find ACTUAL security vulnerabilities.\n\nCRITICAL GUIDELINES:\n- Only flag ACTUAL vulnerabilities you can see in the code\n- Do NOT flag possibilities, suggestions, or general security advice\n- Focus on dangerous functions, patterns, and actual security flaws\n- Only report if confidence is 85% or higher\n\nLINE NUMBER INSTRUCTIONS:\n- Use EXACT line numbers from the numbered code below\n- Line numbers are 1-based (first line is line 1)\n- Point to the EXACT line where the vulnerability occurs\n\nRESPONSE FORMAT:\nReturn a JSON response with this exact structure:\n\n{\n  \"issues\": [\n    {\n      \"line\": 1,\n      \"column\": 0,\n      \"endLine\": 1,\n      \"endColumn\": 10,\n      \"message\": \"Specific description of vulnerability\",\n      \"severity\": \"error|warning|info\",\n      \"code\": \"VULN_CODE\",\n      \"suggestion\": \"How to fix this issue\",\n      \"confidence\": 90,\n      \"cve\": [\"CWE-89\"],\n      \"searchQuery\": \"vulnerability type\"\n    }\n  ],\n  \"summary\": \"Brief summary of issues found\",\n  \"overallRisk\": \"low|medium|high|critical\"\n}\n\nCode to analyze:\n```javascript\n1: const user = req.query.id;\n2: const query = `SELECT * FROM users WHERE id = ${user}`;\n```",
    "options": {
      "fastScan": false,
      "includeLineNumbers": true,
      "maxLines": 200,
      "astGuided": false
    }
  }'
```

### Test AST-Guided Analysis with cURL
```bash
curl -X POST http://localhost:3000/api/v1/vulnzap/code-scan \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your_api_token" \
  -H "User-Agent: VulnZap-VSCode-Extension-AST" \
  -H "X-Request-ID: test_ast_guided_456" \
  -d '{
    "code": "const user = req.query.id;\nconst query = `SELECT * FROM users WHERE id = ${user}`;",
    "language": "javascript",
    "prompt": "AST-guided security analysis for javascript code. Use AST guidance for PRECISE vulnerability detection.\n\nAST ANALYSIS FOUND:\n- 3 security-relevant nodes out of 25 total AST nodes\n- Template literal with variable interpolation at line 2\n- Variable assignment from user input at line 1\n- Potential SQL injection pattern detected\n\nFOCUS ON THESE SPECIFIC AST NODES:\n1. Line 1: VariableDeclarator - user input assignment\n2. Line 2: TemplateLiteral - SQL query construction with ${user}\n3. Line 2: CallExpression - potential database query\n\nPRECISION REQUIREMENTS:\n- Point to EXACT character positions where vulnerabilities exist\n- Use AST node information for pinpoint accuracy\n- Focus on the template literal interpolation: ${user}\n\nRESPONSE FORMAT:\nReturn a JSON response with this exact structure:\n\n{\n  \"issues\": [\n    {\n      \"line\": 2,\n      \"column\": 47,\n      \"endLine\": 2,\n      \"endColumn\": 53,\n      \"message\": \"SQL injection vulnerability in template literal\",\n      \"severity\": \"error\",\n      \"code\": \"SQL_INJECTION\",\n      \"suggestion\": \"Use parameterized queries\",\n      \"confidence\": 95,\n      \"cve\": [\"CWE-89\"],\n      \"searchQuery\": \"SQL injection prevention\"\n    }\n  ],\n  \"summary\": \"Found 1 critical vulnerability using AST guidance\",\n  \"overallRisk\": \"high\"\n}\n\nCode to analyze:\n```javascript\n1: const user = req.query.id;\n2: const query = `SELECT * FROM users WHERE id = ${user}`;\n```",
    "astGuidance": {
      "securityNodes": 3,
      "totalNodes": 25,
      "precisionMode": true
    },
    "options": {
      "fastScan": false,
      "includeLineNumbers": true,
      "maxLines": 200,
      "astGuided": true
    }
  }'
```

### Expected Traditional Response
```json
{
  "success": true,
  "data": {
    "issues": [
      {
        "line": 2,
        "column": 15,
        "endLine": 2,
        "endColumn": 65,
        "message": "SQL injection vulnerability detected",
        "severity": "error",
        "code": "SQL_INJECTION",
        "suggestion": "Use parameterized queries",
        "confidence": 90,
        "cve": ["CWE-89"],
        "searchQuery": "SQL injection prevention",
        "precise": false,
        "astNodeId": null
      }
    ],
    "summary": "Found 1 critical security vulnerability using traditional method",
    "overallRisk": "high",
    "analysisTime": 1250,
    "isPartial": false,
    "precision": "traditional"
  },
  "metadata": {
    "requestId": "test_traditional_123",
    "timestamp": 1703123456789,
    "model": "gemini-1.5-pro",
    "tokensUsed": 1024,
    "analysisType": "traditional"
  }
}
```

### Expected AST-Guided Response
```json
{
  "success": true,
  "data": {
    "issues": [
      {
        "line": 2,
        "column": 47,
        "endLine": 2,
        "endColumn": 53,
        "message": "SQL injection vulnerability in template literal interpolation",
        "severity": "error", 
        "code": "SQL_INJECTION",
        "suggestion": "Use parameterized queries instead of template literals",
        "confidence": 95,
        "cve": ["CWE-89"],
        "searchQuery": "SQL injection prevention",
        "precise": true,
        "astNodeId": 15
      }
    ],
    "summary": "Found 1 critical vulnerability using AST guidance with pinpoint accuracy",
    "overallRisk": "high",
    "analysisTime": 980,
    "isPartial": false,
    "precision": "ast-guided",
    "astStats": {
      "securityNodes": 3,
      "totalNodes": 25,
      "precisionMode": true
    }
  },
  "metadata": {
    "requestId": "test_ast_guided_456",
    "timestamp": 1703123456789,
    "model": "gemini-1.5-pro",
    "tokensUsed": 1156,
    "analysisType": "AST-guided"
  }
}
```

## Security Considerations

1. **API Key Protection**: Store Gemini API keys securely using environment variables
2. **Rate Limiting**: Implement proper rate limiting to prevent abuse
3. **Input Validation**: Validate all inputs to prevent injection attacks
4. **CORS Configuration**: Configure CORS properly for your domain
5. **Request Size Limits**: Limit request body size to prevent DoS attacks
6. **Logging**: Log security events but avoid logging sensitive code content
7. **HTTPS**: Always use HTTPS in production

## Performance Optimization

1. **Caching**: Implement response caching to reduce API calls
2. **Request Batching**: For multiple files, consider batching requests
3. **Async Processing**: Use async/await for non-blocking operations
4. **Connection Pooling**: Use HTTP connection pooling for better performance
5. **Compression**: Enable gzip compression for responses

## Error Handling

The API handles various error scenarios:

- **Rate Limiting**: Returns 429 with retry-after header
- **Invalid Input**: Returns 400 with validation errors
- **API Failures**: Returns 500 with error details
- **Timeout**: Returns 408 for request timeouts
- **Quota Exceeded**: Returns 429 for API quota issues

## Monitoring and Logging

Implement comprehensive logging for:
- Request/response times
- Error rates
- API usage statistics
- Cache hit rates
- Security violations

## Deployment Considerations

1. **Environment Variables**: Use proper environment configuration
2. **Health Checks**: Implement health check endpoints
3. **Graceful Shutdown**: Handle shutdown signals properly
4. **Horizontal Scaling**: Design for multiple instances
5. **Load Balancing**: Use proper load balancing strategies

## Processing Summary for Server Implementers

### What Your Server Receives

The VulnZap extension will send you **two types of requests** to `/api/v1/vulnzap/code-scan`:

#### 1. Traditional Analysis (Python, Java, etc.)
```json
{
  "code": "actual source code",
  "language": "python", 
  "prompt": "Complete analysis prompt with instructions and numbered code",
  "options": { "astGuided": false }
}
```

#### 2. AST-Guided Analysis (JavaScript, TypeScript)
```json
{
  "code": "actual source code",
  "language": "javascript",
  "prompt": "Enhanced prompt with AST context and specific node guidance", 
  "astGuidance": { "securityNodes": 3, "totalNodes": 25 },
  "options": { "astGuided": true }
}
```

### What You Should Do

1. **Use the `prompt` field directly** - Don't rebuild prompts, the extension creates optimized ones
2. **Send the prompt to your AI provider** (Gemini, Claude, etc.)
3. **Parse the JSON response** from the AI
4. **Return the standardized format** with line numbers (1-based)

### Key Processing Rules

- ✅ **DO**: Use the provided prompt as-is
- ✅ **DO**: Extract JSON from AI response markdown blocks
- ✅ **DO**: Validate line numbers are within file bounds
- ✅ **DO**: Return the same response format for both analysis types
- ❌ **DON'T**: Rebuild or modify the prompts
- ❌ **DON'T**: Change the analysis logic based on `astGuided` flag
- ❌ **DON'T**: Convert line numbers (keep them 1-based in response)

### Simple Implementation Flow

```javascript
app.post('/api/v1/vulnzap/code-scan', async (req, res) => {
  const { prompt, options, astGuidance } = req.body;
  
  // Send prompt directly to AI
  const aiResponse = await aiProvider.generate(prompt);
  
  // Extract and parse JSON
  const analysis = parseJSONFromResponse(aiResponse);
  
  // Return standardized format
  res.json({
    success: true,
    data: {
      ...analysis,
      precision: options.astGuided ? "ast-guided" : "traditional"
    }
  });
});
```

**The extension handles all the complexity - your server just needs to process the prompts and return clean JSON responses!**

This comprehensive line number handling ensures accurate vulnerability reporting from server to VS Code, handling all edge cases and providing precise code highlighting.