import * as vscode from "vscode";
import axios from "axios";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { ASTAnalyzerFactory } from "../security/astAnalyzerFactory";
import { ASTGuidedAnalysisResponse } from "../security/astAnalyzer";

/**
 * Standard response format for AI security analysis results
 */
export interface AISecurityResponse {
  issues: Array<{
    line: number;
    column: number;
    endLine: number;
    endColumn: number;
    message: string;
    severity: "error" | "warning" | "info";
    code: string;
    suggestion?: string;
    confidence: number;
    cve?: string[];
    searchQuery?: string;
  }>;
  summary: string;
  overallRisk: "low" | "medium" | "high" | "critical";
  isPartial?: boolean;
  analysisTime?: number;
}

/**
 * Interface that all AI providers must implement for security analysis
 */
export interface APIProvider {
  name: string;
  displayName: string;
  analyzeCode(code: string, language: string): Promise<AISecurityResponse>;
  isConfigured(): boolean;
  getConfigurationErrors(): string[];
}

/**
 * Utility class for logging LLM interactions for debugging and analysis
 */
class LLMLogger {
  private static logDir: string = path.join(os.homedir(), '.vulnzap');

  /**
   * Creates the log directory if it doesn't exist
   */
  static async ensureLogDirectory(): Promise<void> {
    try {
      if (!fs.existsSync(this.logDir)) {
        fs.mkdirSync(this.logDir, { recursive: true });
      }
    } catch (error) {
      console.error('Failed to create log directory:', error);
    }
  }

  /**
   * Logs an LLM interaction with input, output, and metadata
   */
  static async logLLMInteraction(
    provider: string,
    input: string,
    output: string,
    metadata: any = {}
  ): Promise<void> {
    try {
      await this.ensureLogDirectory();
      
      const timestamp = new Date().toISOString();
      const logEntry = {
        timestamp,
        provider,
        metadata,
        input: {
          content: input,
          length: input.length
        },
        output: {
          content: output,
          length: output.length
        }
      };

      const logFileName = `llm-${provider}-${new Date().toISOString().split('T')[0]}.log`;
      const logFilePath = path.join(this.logDir, logFileName);
      
      const logLine = JSON.stringify(logEntry) + '\n';
      fs.appendFileSync(logFilePath, logLine);
    } catch (error) {
      console.error('Failed to log LLM interaction:', error);
    }
  }
}

/**
 * Shared utilities for building consistent security analysis prompts across providers
 */
class SharedPromptBuilder {
  /**
   * Builds a comprehensive security analysis prompt with configurable options
   */
  static buildSecurityAnalysisPrompt(
    code: string, 
    language: string, 
    options: {
      maxLines?: number;
      includeLineNumbers?: boolean;
      fastScan?: boolean;
    } = {}
  ): string {
    const { maxLines = 100, includeLineNumbers = true, fastScan = false } = options;
    
    // Limit code length for analysis to manage token usage
    const lines = code.split('\n').slice(0, maxLines);
    let processedCode: string;
    
    if (includeLineNumbers) {
      processedCode = lines
        .map((line, index) => `${index + 1}: ${line}`)
        .join('\n');
    } else {
      processedCode = lines.join('\n');
    }

    const scanType = fastScan ? 'Fast security scan' : 'Comprehensive security analysis';
    const focusLevel = fastScan ? 'CRITICAL vulnerabilities only' : 'ACTUAL security vulnerabilities';
    
    return `${scanType} for ${language} code. Find ${focusLevel}.

CRITICAL GUIDELINES:
- Only flag ACTUAL vulnerabilities you can see in the code
- Do NOT flag possibilities, suggestions, or general security advice
- Do NOT flag normal logging, debugging, or test code as suspicious
- Do NOT assume file paths, variable names, or strings indicate vulnerabilities
- Only report if confidence is 85% or higher
- Focus on dangerous functions, patterns, and actual security flaws
- Ignore benign console.log statements UNLESS they contain sensitive data (API keys, passwords, tokens, secrets)
- ALWAYS flag hardcoded credentials, API keys, passwords, or tokens even if in console.log or comments
- Ignore test files unless they contain actual vulnerabilities

${includeLineNumbers ? `LINE NUMBER INSTRUCTIONS:
- Use EXACT line numbers from the numbered code below
- Line numbers are 1-based (first line is line 1)
- Point to the EXACT line where the vulnerability occurs
- For multi-line vulnerabilities, use the line where it starts

` : ''}SECURITY FOCUS AREAS (HIGH PRIORITY):
- Hardcoded API keys, passwords, tokens, or secrets (in ANY location including console.log, comments, strings)
- SQL injection vulnerabilities
- Cross-site scripting (XSS) vulnerabilities
- Unsafe code evaluation (eval, exec, etc.)
- Insecure file operations
- Authentication bypasses
- Unsafe deserialization
- Command injection
- Path traversal vulnerabilities
- Weak cryptographic implementations

HARDCODED SECRETS PATTERNS TO DETECT:
- API keys in strings, variables, or logs
- Passwords or tokens in code
- Database connection strings with credentials
- JWT tokens or session keys
- OAuth client secrets
- Cryptographic keys or certificates

RESPONSE FORMAT:
Return a JSON response with this exact structure:

{
  "issues": [
    {
      "line": 1,
      "column": 0,
      "endLine": 1,
      "endColumn": 10,
      "message": "Specific description of the actual vulnerability found",
      "severity": "error|warning|info",
      "code": "VULN_CODE",
      "suggestion": "How to fix this specific issue",
      "confidence": 90,
      "cve": ["CVE-2023-1234"],
      "searchQuery": "specific vulnerability type"
    }
  ],
  "summary": "Brief summary of actual security issues found (or 'No security vulnerabilities detected')",
  "overallRisk": "low|medium|high|critical"
}

Code to analyze${maxLines < code.split('\n').length ? ` (first ${maxLines} lines)` : ''}:
\`\`\`${language}
${processedCode}
\`\`\``;
  }

  /**
   * Parses AI responses and extracts JSON from various formats
   */
  static parseAIResponse(aiText: string): AISecurityResponse {
    try {
      // Handle responses wrapped in markdown code blocks
      const jsonMatch = aiText.match(/```(?:json)?\s*(\{[\s\S]*\})\s*```/);
      const jsonText = jsonMatch ? jsonMatch[1] : aiText;

      const parsed = JSON.parse(jsonText);

      // Validate that required fields are present
      if (!parsed.issues || !Array.isArray(parsed.issues)) {
        throw new Error("Invalid response format: missing issues array");
      }

      return {
        issues: parsed.issues || [],
        summary: parsed.summary || "Security analysis completed",
        overallRisk: parsed.overallRisk || "low",
      };
    } catch (error) {
      console.error("Failed to parse AI response:", error);
      console.error("Raw response:", aiText);
      return {
        issues: [],
        summary: "Failed to parse security analysis response",
        overallRisk: "low",
      };
    }
  }

  /**
   * Filters out security issues below the specified confidence threshold
   */
  static filterLowConfidenceIssues(
    response: AISecurityResponse,
    minConfidence: number = 80
  ): AISecurityResponse {
    const filteredIssues = response.issues.filter(
      (issue) => (issue.confidence || 0) >= minConfidence
    );

    return {
      ...response,
      issues: filteredIssues,
    };
  }
}

/**
 * VulnZap API provider implementation for specialized security analysis
 * Connects to the VulnZap backend service for enhanced vulnerability detection
 */
export class VulnZapProvider implements APIProvider {
  name = "vulnzap";
  displayName = "VulnZap API";
  private context: vscode.ExtensionContext | undefined;

  constructor(context?: vscode.ExtensionContext) {
    this.context = context;
  }

  /**
   * Sets the VS Code extension context for accessing configuration
   */
  setContext(context: vscode.ExtensionContext) {
    this.context = context;
  }

  /**
   * Checks if the provider has all required configuration (API key and URL)
   */
  isConfigured(): boolean {
    const config = vscode.workspace.getConfiguration("vulnzap");
    const apiKey = config.get("vulnzapApiKey", "").trim();
    const apiUrl = config.get("vulnzapApiUrl", "").trim();
    
    return apiKey.length > 0 && apiUrl.length > 0;
  }

  /**
   * Returns a list of configuration issues that prevent the provider from working
   */
  getConfigurationErrors(): string[] {
    const errors: string[] = [];
    const config = vscode.workspace.getConfiguration("vulnzap");
    
    const apiKey = config.get("vulnzapApiKey", "").trim();
    const apiUrl = config.get("vulnzapApiUrl", "").trim();
    
    if (!apiKey) {
      errors.push("VulnZap API key is required");
    }
    
    if (!apiUrl) {
      errors.push("VulnZap API URL is required");
    } else {
      try {
        new URL(apiUrl);
      } catch {
        errors.push("VulnZap API URL must be a valid URL");
      }
    }
    
    return errors;
  }

  /**
   * Analyzes code using the VulnZap API service with AST-guided precision
   * Handles errors gracefully and provides detailed error messages
   */
  async analyzeCode(code: string, language: string): Promise<AISecurityResponse> {
    const config = vscode.workspace.getConfiguration("vulnzap");
    const apiKey = config.get("vulnzapApiKey", "").trim();
    const apiUrl = config.get("vulnzapApiUrl", "").trim();
    const enableASTPrecision = config.get("enableASTPrecision", true);
    
    if (!apiKey || !apiUrl) {
      throw new Error("VulnZap API key and URL are required");
    }

    const startTime = Date.now();
    const fastScan = config.get("enableFastScan", true);

    try {
      let analysisResult: AISecurityResponse;

      // Use AST-guided analysis if supported and enabled
      if (enableASTPrecision && ASTAnalyzerFactory.isSupported(language)) {
        console.log(`Using AST-guided analysis for ${language}`);
        analysisResult = await this.performASTGuidedAnalysis(code, language, apiKey, apiUrl, fastScan);
      } else {
        console.log(`Using traditional analysis for ${language}`);
        analysisResult = await this.performTraditionalAnalysis(code, language, apiKey, apiUrl, fastScan);
      }

      const analysisTime = Date.now() - startTime;
      analysisResult.analysisTime = analysisTime;
      
      return analysisResult;
    } catch (error: any) {
      console.error("VulnZap API error:", error);
      
      // Provide specific error messages based on the type of failure
      if (error.response) {
        const status = error.response.status;
        const message = error.response.data?.message || error.response.statusText;
        
        if (status === 401) {
          throw new Error("Invalid VulnZap API key");
        } else if (status === 429) {
          throw new Error("VulnZap API rate limit exceeded");
        } else if (status >= 500) {
          throw new Error("VulnZap API server error");
        } else {
          throw new Error(`VulnZap API error: ${message}`);
        }
      } else if (error.code === 'ECONNABORTED') {
        throw new Error("VulnZap API request timeout");
      } else if (error.code === 'ENOTFOUND' || error.code === 'ECONNREFUSED') {
        throw new Error("Cannot connect to VulnZap API - check URL");
      } else {
        throw new Error(`VulnZap API error: ${error.message}`);
      }
    }
  }

  /**
   * Perform AST-guided analysis for precise vulnerability detection
   */
  private async performASTGuidedAnalysis(
    code: string, 
    language: string, 
    apiKey: string, 
    apiUrl: string, 
    fastScan: boolean
  ): Promise<AISecurityResponse> {
    // Create AST analyzer for the language
    const astAnalyzer = ASTAnalyzerFactory.createAnalyzer(language);
    
    // Parse AST and extract security-relevant nodes
    const astResult = await astAnalyzer.analyzeCode(code);
    
    // Build enhanced prompt with AST guidance
    const prompt = this.buildASTGuidedPrompt(code, language, astResult, fastScan);

    const response = await axios.post(
      `${apiUrl}/api/v1/vulnzap/code-scan`,
      {
        code,
        language,
        prompt,
        astGuidance: {
          securityNodes: astResult.astStats.securityRelevantNodes,
          totalNodes: astResult.astStats.totalNodes,
          precisionMode: true
        },
        options: {
          fastScan,
          includeLineNumbers: true,
          maxLines: 200,
          astGuided: true
        }
      },
      {
        headers: {
          "Authorization": `Bearer ${apiKey}`,
          "Content-Type": "application/json",
          "User-Agent": "VulnZap-VSCode-Extension-AST"
        },
        timeout: 45000 // Longer timeout for AST analysis
      }
    );

    // Log the AST-guided interaction
    await LLMLogger.logLLMInteraction(
      `${this.name}-ast`,
      prompt,
      JSON.stringify(response.data),
      { 
        language, 
        codeLength: code.length, 
        astStats: astResult.astStats,
        fastScan,
        precision: 'ast-guided'
      }
    );

    // Convert AST response to standard format
    return this.convertASTResponseToStandard(response.data, astResult);
  }

  /**
   * Perform traditional regex-based analysis (fallback)
   */
  private async performTraditionalAnalysis(
    code: string, 
    language: string, 
    apiKey: string, 
    apiUrl: string, 
    fastScan: boolean
  ): Promise<AISecurityResponse> {
    // Build the analysis prompt using shared utilities
    const prompt = SharedPromptBuilder.buildSecurityAnalysisPrompt(code, language, {
      maxLines: 200,
      includeLineNumbers: true,
      fastScan
    });

    const response = await axios.post(
      `${apiUrl}/api/v1/vulnzap/code-scan`,
      {
        code,
        language,
        prompt,
        options: {
          fastScan,
          includeLineNumbers: true,
          maxLines: 200,
          astGuided: false
        }
      },
      {
        headers: {
          "Authorization": `Bearer ${apiKey}`,
          "Content-Type": "application/json",
          "User-Agent": "VulnZap-VSCode-Extension"
        },
        timeout: 30000
      }
    );

    // Log the interaction for debugging and analytics
    await LLMLogger.logLLMInteraction(
      this.name,
      prompt,
      JSON.stringify(response.data),
      { 
        language, 
        codeLength: code.length, 
        fastScan,
        precision: 'traditional'
      }
    );

    return this.validateAndNormalizeResponse(response.data);
  }

  /**
   * Build AST-guided prompt for enhanced precision
   */
  private buildASTGuidedPrompt(
    code: string, 
    language: string, 
    astResult: ASTGuidedAnalysisResponse,
    fastScan: boolean
  ): string {
    const scanType = fastScan ? 'Fast AST-guided security scan' : 'Comprehensive AST-guided security analysis';
    const focusLevel = fastScan ? 'CRITICAL vulnerabilities only' : 'ACTUAL security vulnerabilities';

    return `${scanType} for ${language} code. Use AST guidance for PRECISE vulnerability detection.

PRECISION REQUIREMENTS:
- Use AST node information to target EXACT vulnerable code segments
- Provide character-level precision for underlines
- Only flag ACTUAL vulnerabilities with 85%+ confidence
- Focus on the specific vulnerable substring within each AST node

AST ANALYSIS SUMMARY:
- Total AST nodes analyzed: ${astResult.astStats.totalNodes}
- Security-relevant nodes: ${astResult.astStats.securityRelevantNodes}
- Previous precise detections: ${astResult.astStats.preciselyLocated}

VULNERABILITY FOCUS AREAS:
- Hardcoded secrets (API keys, passwords, tokens)
- SQL injection vulnerabilities  
- Cross-site scripting (XSS)
- Code injection (eval, exec)
- File operation vulnerabilities
- Weak cryptography usage

RESPONSE FORMAT (CRITICAL - Follow exactly):
{
  "issues": [
    {
      "line": 12,
      "column": 23,
      "endLine": 12, 
      "endColumn": 35,
      "message": "Specific vulnerability description",
      "severity": "error|warning|info",
      "code": "VULN_CODE",
      "suggestion": "Precise fix suggestion",
      "confidence": 95,
      "precise": true,
      "astNodeId": 15
    }
  ],
  "summary": "Found X precise vulnerabilities using AST guidance",
  "overallRisk": "low|medium|high|critical",
  "precision": "ast-guided"
}

Code to analyze:
\`\`\`${language}
${code}
\`\`\``;
  }

  /**
   * Convert AST-guided response to standard format
   */
  private convertASTResponseToStandard(
    data: any, 
    astResult: ASTGuidedAnalysisResponse
  ): AISecurityResponse {
    try {
      if (typeof data === 'string') {
        data = JSON.parse(data);
      }

      const issues = Array.isArray(data.issues) ? data.issues.map((issue: any) => ({
        ...issue,
        precise: true,
        astGuided: true,
        confidence: issue.confidence || 90
      })) : [];

      return {
        issues,
        summary: data.summary || `AST-guided analysis found ${issues.length} precise vulnerabilities`,
        overallRisk: data.overallRisk || "low",
        isPartial: data.isPartial || false,
        analysisTime: data.analysisTime
      };
    } catch (error) {
      console.error("Failed to parse AST-guided response:", error);
      return {
        issues: [],
        summary: "Failed to process AST-guided analysis response",
        overallRisk: "low"
      };
    }
  }

  /**
   * Validates and normalizes API responses to ensure consistent format
   */
  private validateAndNormalizeResponse(data: any): AISecurityResponse {
    try {
      // If the response is a string, try to parse it
      if (typeof data === 'string') {
        return SharedPromptBuilder.parseAIResponse(data);
      }
      
      // If it's already an object, validate and normalize
      if (data && typeof data === 'object') {
        return {
          issues: Array.isArray(data.issues) ? data.issues : [],
          summary: data.summary || "Security analysis completed",
          overallRisk: data.overallRisk || "low",
          isPartial: data.isPartial || false,
          analysisTime: data.analysisTime
        };
      }
      
      throw new Error("Invalid response format");
    } catch (error) {
      console.error("Failed to validate VulnZap response:", error);
      return {
        issues: [],
        summary: "Failed to process security analysis response",
        overallRisk: "low"
      };
    }
  }
}

/**
 * Manages API providers for security analysis
 * Currently supports VulnZap API but designed to be extensible for future providers
 */
export class APIProviderManager {
  private provider: VulnZapProvider;
  private context: vscode.ExtensionContext | undefined;

  constructor(context?: vscode.ExtensionContext) {
    this.context = context;
    this.provider = new VulnZapProvider(context);
  }

  /**
   * Updates the extension context for all managed providers
   */
  setContext(context: vscode.ExtensionContext) {
    this.context = context;
    this.provider.setContext(context);
  }

  /**
   * Updates the current provider based on configuration
   * Currently a no-op since we only have one provider
   */
  updateCurrentProvider() {
    // No-op since we only have one provider
  }

  /**
   * Returns the currently active API provider
   */
  getCurrentProvider(): APIProvider {
    return this.provider;
  }

  /**
   * Gets a specific provider by name
   */
  getProvider(name: string): APIProvider | undefined {
    return name === "vulnzap" ? this.provider : undefined;
  }

  /**
   * Returns all available providers
   */
  getAllProviders(): APIProvider[] {
    return [this.provider];
  }

  /**
   * Returns only providers that are properly configured
   */
  getAvailableProviders(): APIProvider[] {
    return this.provider.isConfigured() ? [this.provider] : [];
  }

  /**
   * Analyzes code using the current provider
   * Throws an error if no provider is configured
   */
  async analyzeCode(code: string, language: string): Promise<AISecurityResponse> {
    if (!this.provider.isConfigured()) {
      throw new Error("VulnZap API is not configured");
    }
    
    return this.provider.analyzeCode(code, language);
  }
} 