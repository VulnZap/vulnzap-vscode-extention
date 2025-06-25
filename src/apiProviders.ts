import * as vscode from 'vscode';
import { GoogleGenAI } from '@google/genai';
import axios from 'axios';

export interface AISecurityResponse {
    issues: Array<{
        line: number;
        column: number;
        endLine: number;
        endColumn: number;
        message: string;
        severity: 'error' | 'warning' | 'info';
        code: string;
        suggestion?: string;
        confidence: number;
        cve?: string[];
        searchQuery?: string;
    }>;
    summary: string;
    overallRisk: 'low' | 'medium' | 'high' | 'critical';
    isPartial?: boolean; // For streaming/progressive results
    analysisTime?: number; // Track performance
}

export interface APIProvider {
    name: string;
    displayName: string;
    analyzeCode(code: string, language: string): Promise<AISecurityResponse>;
    isConfigured(): boolean;
    getConfigurationErrors(): string[];
}

export class OpenAIProvider implements APIProvider {
    name = 'openai';
    displayName = 'OpenAI GPT';
    private readonly fastModels = ['gpt-3.5-turbo', 'gpt-3.5-turbo-16k'];

    isConfigured(): boolean {
        const apiKey = vscode.workspace.getConfiguration('vulnzap').get<string>('openaiApiKey');
        return !!apiKey && apiKey.trim().length > 0;
    }

    getConfigurationErrors(): string[] {
        const errors: string[] = [];
        if (!this.isConfigured()) {
            errors.push('OpenAI API key is required');
        }
        return errors;
    }

    async analyzeCode(code: string, language: string): Promise<AISecurityResponse> {
        const startTime = Date.now();
        const config = vscode.workspace.getConfiguration('vulnzap');
        const apiKey = config.get<string>('openaiApiKey');
        let model = config.get<string>('openaiModel', 'gpt-4');

        // Use faster model for initial quick scan
        const enableFastScan = config.get<boolean>('enableFastScan', true);
        if (enableFastScan && code.length > 1000) {
            model = 'gpt-3.5-turbo'; // Much faster than GPT-4
        }

        if (!apiKey) {
            throw new Error('OpenAI API key not configured');
        }

        const prompt = this.buildOptimizedAnalysisPrompt(code, language);

        try {
            const response = await axios.post(
                'https://api.openai.com/v1/chat/completions',
                {
                    model: model,
                    messages: [
                        {
                            role: 'system',
                            content: 'You are a fast security scanner. Focus on critical vulnerabilities only. Respond with concise JSON.'
                        },
                        {
                            role: 'user',
                            content: prompt
                        }
                    ],
                    temperature: 0.1,
                    max_tokens: 2000, // Reduced for faster response
                    stream: false // Keep false for now, but prepare for streaming
                },
                {
                    headers: {
                        'Authorization': `Bearer ${apiKey}`,
                        'Content-Type': 'application/json'
                    },
                    timeout: 8000 // Reduced from 30000 to 8 seconds
                }
            );

            const aiText = response.data.choices[0]?.message?.content;
            if (!aiText) {
                throw new Error('No response from OpenAI API');
            }

            const parsed = this.parseAIResponse(aiText);
            const result = this.filterLowConfidenceIssues(parsed);
            result.analysisTime = Date.now() - startTime;
            return result;
        } catch (error: any) {
            if (error.response?.status === 401) {
                throw new Error('Invalid OpenAI API key');
            } else if (error.response?.status === 429) {
                throw new Error('OpenAI API rate limit exceeded');
            } else if (error.code === 'ECONNABORTED') {
                throw new Error('Analysis timeout - try enabling fast scan mode');
            }
            throw new Error(`OpenAI API error: ${error.message}`);
        }
    }

    private buildOptimizedAnalysisPrompt(code: string, language: string): string {
        // Optimize prompt for speed - less verbose, focus on critical issues
        const maxLines = 100; // Limit analysis to first 100 lines for speed
        const lines = code.split('\n').slice(0, maxLines);
        const limitedCode = lines.join('\n');
        
        return `Quick security scan for ${language} code. Find CRITICAL vulnerabilities only:

FOCUS ON: SQL injection, XSS, hardcoded secrets, eval(), unsafe file ops
IGNORE: Warnings, suggestions, minor issues
RESPONSE: Concise JSON only

{
  "issues": [{"line": 1, "column": 0, "endLine": 1, "endColumn": 10, "message": "Critical issue", "severity": "error", "code": "CRIT_VULN", "confidence": 95}],
  "summary": "Found X critical issues",
  "overallRisk": "high"
}

Code (first ${maxLines} lines):
\`\`\`${language}
${limitedCode}
\`\`\``;
    }

    private parseAIResponse(aiText: string): AISecurityResponse {
        try {
            // Extract JSON from markdown code blocks if present
            const jsonMatch = aiText.match(/```(?:json)?\s*(\{[\s\S]*\})\s*```/);
            const jsonText = jsonMatch ? jsonMatch[1] : aiText;
            
            const parsed = JSON.parse(jsonText);
            
            // Validate required fields
            if (!parsed.issues || !Array.isArray(parsed.issues)) {
                throw new Error('Invalid response format: missing issues array');
            }
            
            return {
                issues: parsed.issues || [],
                summary: parsed.summary || 'Security analysis completed',
                overallRisk: parsed.overallRisk || 'low'
            };
        } catch (error) {
            console.error('Failed to parse AI response:', error);
            console.error('Raw response:', aiText);
            throw new Error(`Failed to parse AI response: ${error}`);
        }
    }

    private filterLowConfidenceIssues(response: AISecurityResponse): AISecurityResponse {
        const minConfidence = 80;
        const filteredIssues = response.issues.filter(issue => {
            return issue.confidence >= minConfidence;
        });

        return {
            ...response,
            issues: filteredIssues,
            summary: filteredIssues.length === 0 ? 'No high-confidence security vulnerabilities detected' : response.summary
        };
    }
}

export class GeminiProvider implements APIProvider {
    name = 'gemini';
    displayName = 'Google Gemini';
    private genAI: GoogleGenAI | null = null;

    constructor() {
        this.initializeAI();
    }

    private async initializeAI() {
        const apiKey = vscode.workspace.getConfiguration('vulnzap').get<string>('geminiApiKey');
        if (apiKey) {
            this.genAI = new GoogleGenAI({
                apiKey: apiKey,
            });
        }
    }

    isConfigured(): boolean {
        const apiKey = vscode.workspace.getConfiguration('vulnzap').get<string>('geminiApiKey');
        return !!apiKey && apiKey.trim().length > 0;
    }

    getConfigurationErrors(): string[] {
        const errors: string[] = [];
        if (!this.isConfigured()) {
            errors.push('Gemini API key is required');
        }
        return errors;
    }

    async analyzeCode(code: string, language: string): Promise<AISecurityResponse> {
        const startTime = Date.now();
        if (!this.genAI) {
            await this.initializeAI();
            if (!this.genAI) {
                throw new Error('Gemini API not configured');
            }
        }

        const prompt = this.buildOptimizedAnalysisPrompt(code, language);

        try {
            // Use fastest Gemini model
            const result = await this.genAI.models.generateContent({
                model: 'gemini-1.5-flash', // Much faster than gemini-pro
                contents: [{
                    role: 'user',
                    parts: [{ text: prompt }]
                }],
                config: {
                    temperature: 0.1,
                    maxOutputTokens: 1500, // Reduced for speed
                    // Remove search tools for faster response
                }
            });

            const aiText = result.text;

            if (!aiText) {
                throw new Error('No response from Gemini API');
            }

            const parsed = this.parseAIResponse(aiText);
            const result_final = this.filterLowConfidenceIssues(parsed);
            result_final.analysisTime = Date.now() - startTime;
            return result_final;
        } catch (error: any) {
            if (error.message?.includes('API_KEY_INVALID') || error.message?.includes('invalid api key')) {
                throw new Error('Invalid Gemini API key');
            }
            throw new Error(`Gemini API error: ${error.message}`);
        }
    }

    private buildOptimizedAnalysisPrompt(code: string, language: string): string {
        // Same optimization as OpenAI
        const maxLines = 100;
        const lines = code.split('\n').slice(0, maxLines);
        const limitedCode = lines.join('\n');
        
        return `Fast security scan - ${language} code. Critical vulnerabilities only:

Find: SQL injection, XSS, secrets, eval(), unsafe file ops
Skip: Minor issues, suggestions
Format: Minimal JSON

{
  "issues": [{"line": 1, "column": 0, "endLine": 1, "endColumn": 10, "message": "Issue", "severity": "error", "code": "VULN", "confidence": 90}],
  "summary": "X issues found",
  "overallRisk": "medium"
}

Code:
\`\`\`${language}
${limitedCode}
\`\`\``;
    }

    private parseAIResponse(aiText: string): AISecurityResponse {
        try {
            // Extract JSON from markdown code blocks if present
            const jsonMatch = aiText.match(/```(?:json)?\s*(\{[\s\S]*\})\s*```/);
            const jsonText = jsonMatch ? jsonMatch[1] : aiText;
            
            const parsed = JSON.parse(jsonText);
            
            // Validate required fields
            if (!parsed.issues || !Array.isArray(parsed.issues)) {
                throw new Error('Invalid response format: missing issues array');
            }
            
            return {
                issues: parsed.issues || [],
                summary: parsed.summary || 'Security analysis completed',
                overallRisk: parsed.overallRisk || 'low'
            };
        } catch (error) {
            console.error('Failed to parse AI response:', error);
            console.error('Raw response:', aiText);
            throw new Error(`Failed to parse AI response: ${error}`);
        }
    }

    private filterLowConfidenceIssues(response: AISecurityResponse): AISecurityResponse {
        const minConfidence = 80;
        const filteredIssues = response.issues.filter(issue => {
            return issue.confidence >= minConfidence;
        });

        return {
            ...response,
            issues: filteredIssues,
            summary: filteredIssues.length === 0 ? 'No high-confidence security vulnerabilities detected' : response.summary
        };
    }
}

export class OpenRouterProvider implements APIProvider {
    name = 'openrouter';
    displayName = 'OpenRouter';

    isConfigured(): boolean {
        const apiKey = vscode.workspace.getConfiguration('vulnzap').get<string>('openrouterApiKey');
        return !!apiKey && apiKey.trim().length > 0;
    }

    getConfigurationErrors(): string[] {
        const errors: string[] = [];
        if (!this.isConfigured()) {
            errors.push('OpenRouter API key is required');
        }
        return errors;
    }

    async analyzeCode(code: string, language: string): Promise<AISecurityResponse> {
        const config = vscode.workspace.getConfiguration('vulnzap');
        const apiKey = config.get<string>('openrouterApiKey');
        const model = config.get<string>('openrouterModel', 'anthropic/claude-3-haiku');

        if (!apiKey) {
            throw new Error('OpenRouter API key not configured');
        }

        const prompt = this.buildAnalysisPrompt(code, language);

        try {
            const response = await axios.post(
                'https://openrouter.ai/api/v1/chat/completions',
                {
                    model: model,
                    messages: [
                        {
                            role: 'system',
                            content: 'You are a security expert analyzing code for vulnerabilities. Respond only with valid JSON in the specified format.'
                        },
                        {
                            role: 'user',
                            content: prompt
                        }
                    ],
                    temperature: 0.3,
                    max_tokens: 4000
                },
                {
                    headers: {
                        'Authorization': `Bearer ${apiKey}`,
                        'Content-Type': 'application/json',
                        'HTTP-Referer': 'https://github.com/vulnzap/vscode-extension',
                        'X-Title': 'VulnZap VS Code Extension'
                    },
                    timeout: 10000 // Reduced from 30000 to 10 seconds
                }
            );

            const aiText = response.data.choices[0]?.message?.content;
            if (!aiText) {
                throw new Error('No response from OpenRouter API');
            }

            return this.parseAIResponse(aiText);
        } catch (error: any) {
            if (error.response?.status === 401) {
                throw new Error('Invalid OpenRouter API key');
            } else if (error.response?.status === 429) {
                throw new Error('OpenRouter API rate limit exceeded');
            }
            throw new Error(`OpenRouter API error: ${error.message}`);
        }
    }

    private buildAnalysisPrompt(code: string, language: string): string {
        // Add line numbers to the code for accurate reference
        const numberedLines = code.split('\n').map((line, index) => `${index + 1}: ${line}`);
        const numberedCode = numberedLines.join('\n');
        
        return `Analyze this ${language} code for ACTUAL security vulnerabilities. Only report issues where you can identify concrete evidence of a security problem in the code itself.

CRITICAL GUIDELINES:
- Only flag ACTUAL vulnerabilities you can see in the code
- Do NOT flag possibilities, suggestions, or general security advice
- Do NOT flag normal logging, debugging, or test code as suspicious
- Do NOT assume file paths, variable names, or strings indicate vulnerabilities
- Only report if confidence is 85% or higher
- Focus on dangerous functions, patterns, and actual security flaws
- Ignore benign console.log, file paths, or debugging statements
- Ignore test files unless they contain actual vulnerabilities

LINE NUMBER INSTRUCTIONS:
- Use EXACT line numbers from the numbered code below
- Line numbers are 1-based (first line is line 1)
- Point to the EXACT line where the vulnerability occurs
- For multi-line vulnerabilities, use the line where it starts

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

Code to analyze (with line numbers):
\`\`\`${language}
${numberedCode}
\`\`\`

Look for ACTUAL instances of: SQL injection, XSS vulnerabilities, hardcoded API keys/passwords, unsafe eval(), insecure file operations, authentication bypasses, unsafe deserialization, and other concrete security flaws.`;
    }

    private parseAIResponse(aiText: string): AISecurityResponse {
        try {
            // Extract JSON from markdown code blocks if present
            const jsonMatch = aiText.match(/```(?:json)?\s*(\{[\s\S]*\})\s*```/);
            const jsonText = jsonMatch ? jsonMatch[1] : aiText;
            
            const parsed = JSON.parse(jsonText);
            
            // Validate required fields
            if (!parsed.issues || !Array.isArray(parsed.issues)) {
                throw new Error('Invalid response format: missing issues array');
            }
            
            return {
                issues: parsed.issues || [],
                summary: parsed.summary || 'Security analysis completed',
                overallRisk: parsed.overallRisk || 'low'
            };
        } catch (error) {
            console.error('Failed to parse AI response:', error);
            console.error('Raw response:', aiText);
            throw new Error(`Failed to parse AI response: ${error}`);
        }
    }
}

export class VulnZapProvider implements APIProvider {
    name = 'vulnzap';
    displayName = 'VulnZap Custom API';

    isConfigured(): boolean {
        const config = vscode.workspace.getConfiguration('vulnzap');
        const apiKey = config.get<string>('vulnzapApiKey');
        const baseUrl = config.get<string>('vulnzapApiUrl');
        return !!apiKey && apiKey.trim().length > 0 && !!baseUrl && baseUrl.trim().length > 0;
    }

    getConfigurationErrors(): string[] {
        const errors: string[] = [];
        const config = vscode.workspace.getConfiguration('vulnzap');
        const apiKey = config.get<string>('vulnzapApiKey');
        const baseUrl = config.get<string>('vulnzapApiUrl');
        
        if (!apiKey || apiKey.trim().length === 0) {
            errors.push('VulnZap API key is required');
        }
        if (!baseUrl || baseUrl.trim().length === 0) {
            errors.push('VulnZap API URL is required');
        }
        return errors;
    }

    async analyzeCode(code: string, language: string): Promise<AISecurityResponse> {
        const config = vscode.workspace.getConfiguration('vulnzap');
        const apiKey = config.get<string>('vulnzapApiKey');
        const baseUrl = config.get<string>('vulnzapApiUrl', 'https://api.vulnzap.com');

        if (!apiKey || !baseUrl) {
            throw new Error('VulnZap API key and URL not configured');
        }

        // Ensure baseUrl doesn't end with slash for consistent URL building
        const cleanBaseUrl = baseUrl.replace(/\/$/, '');
        const endpoint = `${cleanBaseUrl}/api/v1/extension`;

        try {
            const response = await axios.post(
                endpoint,
                {
                    code: code,
                    language: language,
                    options: {
                        includeSearchResults: true,
                        includeCVEs: true,
                        confidence_threshold: 70
                    }
                },
                {
                    headers: {
                        'Authorization': `Bearer ${apiKey}`,
                        'Content-Type': 'application/json',
                        'User-Agent': 'VulnZap-VSCode-Extension/1.0.0'
                    },
                    timeout: 12000
                }
            );

            if (response.data.success === false) {
                throw new Error(response.data.error || 'VulnZap API returned an error');
            }

            // VulnZap API should return data in the expected format
            return this.validateAndNormalizeResponse(response.data);
        } catch (error: any) {
            if (error.response?.status === 401) {
                throw new Error('Invalid VulnZap API key');
            } else if (error.response?.status === 403) {
                throw new Error('VulnZap API access denied - check your subscription');
            } else if (error.response?.status === 429) {
                throw new Error('VulnZap API rate limit exceeded');
            } else if (error.code === 'ECONNREFUSED' || error.code === 'ENOTFOUND') {
                throw new Error('Cannot connect to VulnZap API - check the URL');
            }
            throw new Error(`VulnZap API error: ${error.message}`);
        }
    }

    private validateAndNormalizeResponse(data: any): AISecurityResponse {
        // Handle both direct response format and wrapped response format
        const responseData = data.data || data;
        
        if (!responseData.issues || !Array.isArray(responseData.issues)) {
            throw new Error('Invalid VulnZap API response format: missing issues array');
        }

        return {
            issues: responseData.issues.map((issue: any) => ({
                line: issue.line || 1,
                column: issue.column || 0,
                endLine: issue.endLine || issue.line || 1,
                endColumn: issue.endColumn || issue.column || 0,
                message: issue.message || 'Security issue detected',
                severity: issue.severity || 'warning',
                code: issue.code || 'SECURITY_ISSUE',
                suggestion: issue.suggestion,
                confidence: issue.confidence || 80,
                cve: issue.cve || [],
                searchQuery: issue.searchQuery
            })),
            summary: responseData.summary || 'Security analysis completed',
            overallRisk: responseData.overallRisk || 'low'
        };
    }
}

export class APIProviderManager {
    private providers: Map<string, APIProvider> = new Map();
    private currentProvider: APIProvider | null = null;

    constructor() {
        this.initializeProviders();
    }

    private initializeProviders() {
        const providers = [
            new OpenAIProvider(),
            new GeminiProvider(),
            new OpenRouterProvider(),
            new VulnZapProvider()
        ];

        providers.forEach(provider => {
            this.providers.set(provider.name, provider);
        });

        // Set the current provider based on configuration
        this.updateCurrentProvider();
    }

    updateCurrentProvider() {
        const config = vscode.workspace.getConfiguration('vulnzap');
        const selectedProvider = config.get<string>('apiProvider', 'gemini');
        
        this.currentProvider = this.providers.get(selectedProvider) || null;
    }

    getCurrentProvider(): APIProvider | null {
        return this.currentProvider;
    }

    getProvider(name: string): APIProvider | undefined {
        return this.providers.get(name);
    }

    getAllProviders(): APIProvider[] {
        return Array.from(this.providers.values());
    }

    getAvailableProviders(): APIProvider[] {
        return this.getAllProviders().filter(provider => provider.isConfigured());
    }

    async analyzeCode(code: string, language: string): Promise<AISecurityResponse> {
        if (!this.currentProvider) {
            throw new Error('No API provider selected. Please configure an API provider in settings.');
        }

        if (!this.currentProvider.isConfigured()) {
            const errors = this.currentProvider.getConfigurationErrors();
            throw new Error(`${this.currentProvider.displayName} is not properly configured: ${errors.join(', ')}`);
        }

        return await this.currentProvider.analyzeCode(code, language);
    }
}
