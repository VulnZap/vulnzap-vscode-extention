import * as vscode from "vscode";
import axios from "axios";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
// AST analysis removed - using text-based approach now
import { Logger } from "../utils/logger";

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
      Logger.error('Failed to create log directory:', error as Error);
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
      Logger.error('Failed to log LLM interaction:', error as Error);
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
   * Parses AI response text and converts to standardized format
   */
  static parseAIResponse(aiText: string): AISecurityResponse {
    try {
      // Try to parse as JSON first
      if (aiText.trim().startsWith('{')) {
        return JSON.parse(aiText);
      }

      // Look for JSON content within markdown code blocks
      const jsonMatch = aiText.match(/```(?:json)?\s*(\{[\s\S]*\})\s*```/);
      if (jsonMatch) {
        return JSON.parse(jsonMatch[1]);
      }

      // Try to extract JSON from anywhere in the response
      const braceStart = aiText.indexOf('{');
      const braceEnd = aiText.lastIndexOf('}');
      if (braceStart !== -1 && braceEnd !== -1 && braceEnd > braceStart) {
        const jsonStr = aiText.substring(braceStart, braceEnd + 1);
        return JSON.parse(jsonStr);
      }

      // If no JSON found, return empty response
      return {
        issues: [],
        summary: "Could not parse AI response",
        overallRisk: "low"
      };
    } catch (error) {
      Logger.error('Failed to parse AI response:', error as Error);
      return {
        issues: [],
        summary: "Failed to parse AI response",
        overallRisk: "low"
      };
    }
  }

  /**
   * Filters out low confidence issues from the response
   */
  static filterLowConfidenceIssues(
    response: AISecurityResponse,
    minConfidence: number = 80
  ): AISecurityResponse {
    const filteredIssues = response.issues.filter(issue => 
      (issue.confidence || 0) >= minConfidence
    );

    return {
      ...response,
      issues: filteredIssues,
      summary: filteredIssues.length > 0 
        ? `Found ${filteredIssues.length} high-confidence security issues`
        : "No high-confidence security issues found"
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
   * Analyzes code for security vulnerabilities using text-based approach
   */
  async analyzeCode(code: string, language: string): Promise<AISecurityResponse> {
    const config = vscode.workspace.getConfiguration("vulnzap");
    const apiKey = config.get("vulnzapApiKey", "").trim();
    const apiUrl = config.get("vulnzapApiUrl", "").trim();
    
    if (!apiKey || !apiUrl) {
      throw new Error("VulnZap API key and URL are required");
    }

    const startTime = Date.now();
    const fastScan = config.get("enableFastScan", true);

    try {
      // Use text-based analysis (AST removed for simplicity and speed)
      Logger.debug(`Using text-based analysis for ${language}`);
      const analysisResult = await this.performTextBasedAnalysis(code, language, apiKey, apiUrl, fastScan);

      const analysisTime = Date.now() - startTime;
      analysisResult.analysisTime = analysisTime;
      
      return analysisResult;
    } catch (error: any) {
      Logger.error("VulnZap API error:", error as Error);
      
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
   * Perform text-based analysis (fast and simple)
   */
  private async performTextBasedAnalysis(
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
          textBased: true
        }
      },
      {
        headers: {
          "x-api-key": `${apiKey}`,
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
        approach: 'text-based'
      }
    );

    return this.validateAndNormalizeResponse(response.data);
  }

  /**
   * Validates and normalizes the API response
   */
  private validateAndNormalizeResponse(data: any): AISecurityResponse {
    try {
      // Handle different response formats from the API
      let parsedData = data;
      
      if (typeof data === 'string') {
        parsedData = SharedPromptBuilder.parseAIResponse(data);
      }

      // Handle nested response structure - actual data is in response.data
      if (parsedData.data) {
        parsedData = parsedData.data;
      }
      
      // Ensure the response has the required structure
      const normalizedResponse: AISecurityResponse = {
        issues: Array.isArray(parsedData.issues) ? parsedData.issues.map((issue: any) => ({
          line: Math.max(0, Number(issue.line) || 0),
          column: Math.max(0, Number(issue.column) || 0),
          endLine: Math.max(0, Number(issue.endLine) || Number(issue.line) || 0),
          endColumn: Math.max(0, Number(issue.endColumn) || Number(issue.column) || 0),
          message: String(issue.message || 'Security issue detected'),
          severity: ['error', 'warning', 'info'].includes(issue.severity) ? issue.severity : 'warning',
          code: String(issue.code || 'SECURITY_ISSUE'),
          suggestion: issue.suggestion ? String(issue.suggestion) : undefined,
          confidence: Math.min(100, Math.max(0, Number(issue.confidence) || 50)),
          cve: Array.isArray(issue.cve) ? issue.cve : [],
          searchQuery: issue.searchQuery ? String(issue.searchQuery) : undefined
        })) : [],
        summary: String(parsedData.summary || 'Security analysis completed'),
        overallRisk: ['low', 'medium', 'high', 'critical'].includes(parsedData.overallRisk) 
          ? parsedData.overallRisk : 'low',
        isPartial: Boolean(parsedData.isPartial),
        analysisTime: parsedData.analysisTime
      };

      Logger.debug('Normalized response:', JSON.stringify(normalizedResponse, null, 2));

      // Filter out low confidence issues (reduce threshold from 75 to 70 to keep high confidence issues)
      return SharedPromptBuilder.filterLowConfidenceIssues(normalizedResponse, 70);
    } catch (error) {
      Logger.error('Error validating API response:', error as Error);
      return {
        issues: [],
        summary: 'Failed to process security analysis response',
        overallRisk: 'low'
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