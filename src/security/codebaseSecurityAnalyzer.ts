import * as vscode from 'vscode';
import { CodebaseIndexer, TextChunk } from '../indexing';
import { APIProviderManager } from '../providers/apiProviders';
import { Logger } from '../utils/logger';

/**
 * Security issue found by the analyzer
 */
export interface SecurityIssue {
    id: string;
    type: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    message: string;
    description: string;
    filePath: string;
    startLine: number;
    endLine: number;
    startColumn: number;
    endColumn: number;
    confidence: number;
    suggestion?: string;
    context?: {
        similarVulnerabilities: TextChunk[];
        relatedPatterns: TextChunk[];
    };
}

/**
 * Analysis response from the AI
 */
export interface SecurityAnalysisResponse {
    issues: SecurityIssue[];
    summary: string;
    overallRisk: 'low' | 'medium' | 'high' | 'critical';
    recommendations: string[];
    analysisStats: {
        chunksAnalyzed: number;
        securityPatternsFound: number;
        contextualMatches: number;
    };
}

/**
 * Codebase security analyzer using text-based indexing
 * Replaces the complex AST-based approach with simple, fast text analysis
 */
export class CodebaseSecurityAnalyzer {
    private codebaseIndexer: CodebaseIndexer;
    private apiProvider: APIProviderManager;

    // Security patterns for quick detection
    private readonly SECURITY_PATTERNS = {
        sql_injection: [
            /\$\{.*\}/g,                    // Template literal with variables
            /['"`]\s*\+\s*\w+/g,           // String concatenation
            /query\s*\(\s*['"`].*\$\{/g,   // Query with template literal
            /execute\s*\(\s*['"`].*\+/g,   // Execute with concatenation
        ],
        xss: [
            /innerHTML\s*=\s*[^'"]/g,      // innerHTML assignment
            /document\.write\s*\(/g,       // document.write
            /eval\s*\(/g,                  // eval function
            /setTimeout\s*\(\s*['"`]/g,    // setTimeout with string
        ],
        hardcoded_secrets: [
            /['"`][A-Za-z0-9+/]{40,}['"`]/g,           // Base64-like strings
            /['"`]sk_[a-zA-Z0-9]{24,}['"`]/g,          // Stripe secret keys
            /['"`]AKIA[0-9A-Z]{16}['"`]/g,             // AWS access keys
            /['"`][a-f0-9]{32,64}['"`]/g,              // Hex tokens
            /['"`]ghp_[a-zA-Z0-9]{36,}['"`]/g,          // GitHub personal access tokens
            /['"`]sandbox_secret_[a-zA-Z0-9]{32,}['"`]/g, // PayPal sandbox secrets
        ],
        weak_crypto: [
            /md5\s*\(/gi,                  // MD5 usage
            /sha1\s*\(/gi,                 // SHA1 usage
            /des\s*\(/gi,                  // DES encryption
            /rc4\s*\(/gi,                  // RC4 encryption
        ],
        unsafe_functions: [
            /exec\s*\(/g,                  // Command execution
            /system\s*\(/g,                // System calls
            /shell_exec\s*\(/g,            // Shell execution
            /passthru\s*\(/g,              // PHP passthru
        ]
    };

    constructor(codebaseIndexer: CodebaseIndexer) {
        this.codebaseIndexer = codebaseIndexer;
        this.apiProvider = new APIProviderManager();
    }

    /**
     * Analyze a VS Code document for security vulnerabilities
     * This method provides compatibility with the old SecurityAnalyzer interface
     */
    async analyzeDocument(document: vscode.TextDocument): Promise<any[]> {
        const response = await this.analyzeCode(
            document.getText(),
            document.uri.fsPath,
            document.languageId.toString(),
            0
        );

        // Convert SecurityIssue[] to the format expected by the diagnostic provider
        return response.issues.map(issue => ({
            line: issue.startLine - 1, // Convert to 0-based
            column: issue.startColumn,
            endLine: issue.endLine - 1, // Convert to 0-based
            endColumn: issue.endColumn,
            message: issue.message,
            severity: this.convertToVSCodeSeverity(issue.severity),
            code: issue.type,
            suggestion: issue.suggestion,
            confidence: issue.confidence,
            cve: [],
            searchResults: [],
            relatedCode: [],
            similarVulnerabilities: issue.context?.similarVulnerabilities || []
        }));
    }

    /**
     * Convert our severity enum to VS Code DiagnosticSeverity
     */
    public convertToVSCodeSeverity(severity: 'low' | 'medium' | 'high' | 'critical'): vscode.DiagnosticSeverity {
        switch (severity) {
            case 'critical':
            case 'high':
                return vscode.DiagnosticSeverity.Error;
            case 'medium':
                return vscode.DiagnosticSeverity.Warning;
            case 'low':
            default:
                return vscode.DiagnosticSeverity.Information;
        }
    }

    /**
     * Analyze code for security vulnerabilities using text-based approach
     */
    async analyzeCode(
        code: string,
        filePath: string,
        language: string,
        line?: number
    ): Promise<SecurityAnalysisResponse> {
        Logger.debug(`Analyzing code security for: ${filePath}`);

        try {
            // Step 1: Quick pattern-based detection
            const quickIssues = await this.performQuickScan(code, filePath);
            
            // Step 2: Get contextual analysis from indexed codebase
            const contextualAnalysis = line 
                ? await this.getContextualAnalysis(code, filePath, line)
                : { similarVulnerabilities: [], relatedPatterns: [] };

            // Step 3: AI-enhanced analysis with context
            const enhancedIssues = await this.performAIAnalysis(
                code,
                filePath,
                quickIssues,
                contextualAnalysis,
                language
            );

            // Step 4: Combine and deduplicate results
            const allIssues = this.combineAndDeduplicateIssues(quickIssues, enhancedIssues);

            return {
                issues: allIssues,
                summary: this.generateSummary(allIssues),
                overallRisk: this.calculateOverallRisk(allIssues),
                recommendations: this.generateRecommendations(allIssues),
                analysisStats: {
                    chunksAnalyzed: contextualAnalysis.similarVulnerabilities.length + 
                                  contextualAnalysis.relatedPatterns.length,
                    securityPatternsFound: quickIssues.length,
                    contextualMatches: contextualAnalysis.similarVulnerabilities.length
                }
            };

        } catch (error) {
            Logger.error('Security analysis failed:', error as Error);
            return this.createFallbackResponse(filePath);
        }
    }

    /**
     * Perform quick pattern-based security scan
     */
    private async performQuickScan(code: string, filePath: string): Promise<SecurityIssue[]> {
        const issues: SecurityIssue[] = [];
        const lines = code.split('\n');

        for (const [patternType, patterns] of Object.entries(this.SECURITY_PATTERNS)) {
            for (const pattern of patterns) {
                let match;
                while ((match = pattern.exec(code)) !== null) {
                    const lineNumber = this.getLineFromIndex(code, match.index);
                    const lineContent = lines[lineNumber - 1] || '';
                    
                    const issue: SecurityIssue = {
                        id: `quick_${patternType}_${Date.now()}_${Math.random()}`,
                        type: patternType,
                        severity: this.getSeverityForPattern(patternType),
                        message: this.getMessageForPattern(patternType, match[0]),
                        description: this.getDescriptionForPattern(patternType),
                        filePath,
                        startLine: lineNumber,
                        endLine: lineNumber,
                        startColumn: this.getColumnFromIndex(code, match.index),
                        endColumn: this.getColumnFromIndex(code, match.index + match[0].length),
                        confidence: 75, // Quick scan has medium confidence
                        suggestion: this.getSuggestionForPattern(patternType)
                    };

                    issues.push(issue);
                }
                
                // Reset regex global flag
                pattern.lastIndex = 0;
            }
        }

        Logger.debug(`Quick scan found ${issues.length} potential issues`);
        return issues;
    }

    /**
     * Get contextual analysis from the indexed codebase
     */
    private async getContextualAnalysis(
        code: string,
        filePath: string,
        line: number
    ): Promise<{
        similarVulnerabilities: TextChunk[];
        relatedPatterns: TextChunk[];
    }> {
        try {
            const context = await this.codebaseIndexer.getSecurityAnalysisContext(
                code,
                filePath,
                line
            );

            return {
                similarVulnerabilities: context.similarVulnerabilities,
                relatedPatterns: [
                    ...context.relatedSecurityPatterns,
                    ...context.dataFlowRelated,
                    ...context.frameworkSpecific
                ]
            };
        } catch (error) {
            Logger.warn('Failed to get contextual analysis:', error as Error);
            return { similarVulnerabilities: [], relatedPatterns: [] };
        }
    }

    /**
     * Perform AI-enhanced analysis with contextual information
     */
    private async performAIAnalysis(
        code: string,
        filePath: string,
        quickIssues: SecurityIssue[],
        context: { similarVulnerabilities: TextChunk[]; relatedPatterns: TextChunk[] },
        language: string
    ): Promise<SecurityIssue[]> {
        try {
            const prompt = this.buildAIAnalysisPrompt(code, filePath, quickIssues, context, language);
            Logger.debug('AI Analysis prompt built, calling API...');
            const aiResponse = await this.getAIAnalysis(prompt, language);
            
            const parsedIssues = this.parseAIResponse(aiResponse, filePath, context);
            return parsedIssues;
        } catch (error) {
            Logger.warn('AI analysis failed, using quick scan results:', error as Error);
            return [];
        }
    }

    /**
     * Build AI analysis prompt with context
     */
    private buildAIAnalysisPrompt(
        code: string,
        filePath: string,
        quickIssues: SecurityIssue[],
        context: { similarVulnerabilities: TextChunk[]; relatedPatterns: TextChunk[] },
        language: string
    ): string {
        let prompt = `Analyze this code for security vulnerabilities:

FILE: ${filePath}

CODE:
\`\`\`
${code.substring(0, 2000)} // Truncated for analysis
\`\`\`

INITIAL FINDINGS:
${quickIssues.map(issue => `- ${issue.type}: ${issue.message}`).join('\n')}

`;

        if (context.similarVulnerabilities.length > 0) {
            prompt += `SIMILAR VULNERABILITIES FOUND IN CODEBASE:
${context.similarVulnerabilities.slice(0, 3).map(chunk => 
    `- File: ${chunk.filePath}\n  Code: ${chunk.content.substring(0, 200)}...`
).join('\n')}

`;
        }

        if (context.relatedPatterns.length > 0) {
            prompt += `RELATED SECURITY PATTERNS:
${context.relatedPatterns.slice(0, 3).map(chunk => 
    `- File: ${chunk.filePath}\n  Pattern: ${chunk.content.substring(0, 150)}...`
).join('\n')}

`;
        }

        prompt += `Please provide:
1. Validate and refine the initial findings
2. Identify any additional security issues
3. Assess severity levels (low/medium/high/critical)
4. Provide specific line numbers and recommendations
5. Consider the context from similar patterns in the codebase

Respond in JSON format:
{
  "issues": [
    {
      "type": "vulnerability_type",
      "severity": "high",
      "message": "Brief description",
      "line": 5,
      "column": 10,
      "confidence": 90,
      "explanation": "Detailed explanation",
      "suggestion": "How to fix"
    }
  ]
}`;

        return prompt;
    }

    /**
     * Get AI analysis response
     */
    private async getAIAnalysis(prompt: string, language: string): Promise<any> {
        const provider = this.apiProvider.getCurrentProvider();
        if (!provider) {
            throw new Error('No AI provider configured');
        }

        const response = await provider.analyzeCode(prompt, language);
        
        // The response is already an AISecurityResponse object, not a string
        if (response && response.issues) {
            return response;
        }

        // Fallback to empty response
        return { issues: [] };
    }

    /**
     * Parse AI response into security issues
     */
    private parseAIResponse(
        aiResponse: any,
        filePath: string,
        context: { similarVulnerabilities: TextChunk[]; relatedPatterns: TextChunk[] }
    ): SecurityIssue[] {
        const issues: SecurityIssue[] = [];

        // Handle nested response structure (response.data.issues or response.issues)
        let issuesArray = aiResponse.issues;
        if (aiResponse.data && aiResponse.data.issues) {
            issuesArray = aiResponse.data.issues;
        }

        Logger.debug(`Parsing AI response, found ${issuesArray?.length || 0} issues`);

        if (issuesArray && Array.isArray(issuesArray)) {
            for (const issue of issuesArray) {
                const securityIssue: SecurityIssue = {
                    id: `ai_${issue.code || issue.type || 'unknown'}_${Date.now()}_${Math.random()}`,
                    type: issue.code || issue.type || 'unknown',
                    severity: issue.severity || 'medium',
                    message: issue.message || 'Security issue detected',
                    description: issue.explanation || issue.message || '',
                    filePath,
                    startLine: issue.line || 1,
                    endLine: issue.endLine || issue.line || 1,
                    startColumn: issue.column || 0,
                    endColumn: issue.endColumn || (issue.column || 0) + 10,
                    confidence: issue.confidence || 80,
                    suggestion: issue.suggestion,
                    context: {
                        similarVulnerabilities: context.similarVulnerabilities,
                        relatedPatterns: context.relatedPatterns
                    }
                };

                issues.push(securityIssue);
            }
        }

        Logger.debug(`Parsed ${issues.length} AI issues`);
        return issues;
    }

    /**
     * Combine and deduplicate issues from different analysis stages
     */
    private combineAndDeduplicateIssues(
        quickIssues: SecurityIssue[],
        aiIssues: SecurityIssue[]
    ): SecurityIssue[] {
        // Flag either quickIssues or aiIssues as the primary source
        const deduplicatedIssues: SecurityIssue[] = [];
        let allIssues: SecurityIssue[] = [];
        if (aiIssues.length > 0) {
            allIssues = [...aiIssues];
        } else {
            allIssues = [...quickIssues];
        }
        for (const issue of allIssues) {
            // Check if we already have an identical issue (same type, same position)
            const existing = deduplicatedIssues.find(existing => 
                existing.type === issue.type &&
                existing.startLine === issue.startLine &&
                existing.startColumn === issue.startColumn &&
                existing.filePath === issue.filePath
            );

            if (existing) {
                // Keep the one with higher confidence
                if (issue.confidence > existing.confidence) {
                    const index = deduplicatedIssues.indexOf(existing);
                    deduplicatedIssues[index] = issue;
                }
            } else {
                deduplicatedIssues.push(issue);
            }
        }

        return deduplicatedIssues;
    }

    // Helper methods for pattern analysis

    private getLineFromIndex(text: string, index: number): number {
        return text.substring(0, index).split('\n').length;
    }

    private getColumnFromIndex(text: string, index: number): number {
        const beforeIndex = text.substring(0, index);
        const lastNewline = beforeIndex.lastIndexOf('\n');
        return lastNewline === -1 ? index : index - lastNewline - 1;
    }

    private getSeverityForPattern(patternType: string): 'low' | 'medium' | 'high' | 'critical' {
        const severityMap: { [key: string]: 'low' | 'medium' | 'high' | 'critical' } = {
            sql_injection: 'high',
            xss: 'high',
            hardcoded_secrets: 'critical',
            weak_crypto: 'medium',
            unsafe_functions: 'high'
        };
        return severityMap[patternType] || 'medium';
    }

    private getMessageForPattern(patternType: string, match: string): string {
        const messageMap: { [key: string]: string } = {
            sql_injection: `Potential SQL injection vulnerability: ${match}`,
            xss: `Potential XSS vulnerability: ${match}`,
            hardcoded_secrets: `Hardcoded secret detected: ${match.substring(0, 20)}...`,
            weak_crypto: `Weak cryptographic function: ${match}`,
            unsafe_functions: `Unsafe function call: ${match}`
        };
        return messageMap[patternType] || `Security issue detected: ${match}`;
    }

    private getDescriptionForPattern(patternType: string): string {
        const descriptionMap: { [key: string]: string } = {
            sql_injection: 'SQL injection occurs when untrusted input is concatenated into SQL queries without proper sanitization.',
            xss: 'Cross-site scripting (XSS) allows attackers to inject malicious scripts into web pages.',
            hardcoded_secrets: 'Hardcoded secrets in source code can be easily discovered and exploited.',
            weak_crypto: 'Weak cryptographic algorithms are vulnerable to attacks and should not be used.',
            unsafe_functions: 'These functions can execute arbitrary commands and should be used with extreme caution.'
        };
        return descriptionMap[patternType] || 'Security vulnerability detected';
    }

    private getSuggestionForPattern(patternType: string): string {
        const suggestionMap: { [key: string]: string } = {
            sql_injection: 'Use parameterized queries or prepared statements instead of string concatenation.',
            xss: 'Sanitize and validate all user input before displaying it. Use textContent instead of innerHTML.',
            hardcoded_secrets: 'Store secrets in environment variables or secure configuration files.',
            weak_crypto: 'Use strong cryptographic algorithms like AES-256 or SHA-256.',
            unsafe_functions: 'Validate and sanitize all input before passing to these functions.'
        };
        return suggestionMap[patternType] || 'Review this code for security implications.';
    }

    private generateSummary(issues: SecurityIssue[]): string {
        if (issues.length === 0) {
            return 'No security issues detected in the analyzed code.';
        }

        const severityCounts = issues.reduce((acc, issue) => {
            acc[issue.severity] = (acc[issue.severity] || 0) + 1;
            return acc;
        }, {} as { [key: string]: number });

        const severityList = Object.entries(severityCounts)
            .map(([severity, count]) => `${count} ${severity}`)
            .join(', ');

        return `Found ${issues.length} security issue(s): ${severityList}`;
    }

    private calculateOverallRisk(issues: SecurityIssue[]): 'low' | 'medium' | 'high' | 'critical' {
        if (issues.length === 0) return 'low';

        const criticalCount = issues.filter(i => i.severity === 'critical').length;
        const highCount = issues.filter(i => i.severity === 'high').length;
        const mediumCount = issues.filter(i => i.severity === 'medium').length;

        if (criticalCount > 0) return 'critical';
        if (highCount >= 3) return 'critical';
        if (highCount >= 1) return 'high';
        if (mediumCount >= 3) return 'high';
        if (mediumCount >= 1) return 'medium';

        return 'low';
    }

    private generateRecommendations(issues: SecurityIssue[]): string[] {
        const recommendations: string[] = [];

        const issueTypes = new Set(issues.map(i => i.type));

        if (issueTypes.has('sql_injection')) {
            recommendations.push('Implement parameterized queries to prevent SQL injection');
        }

        if (issueTypes.has('xss')) {
            recommendations.push('Implement proper input validation and output encoding');
        }

        if (issueTypes.has('hardcoded_secrets')) {
            recommendations.push('Move secrets to environment variables or secure vaults');
        }

        if (issueTypes.has('weak_crypto')) {
            recommendations.push('Upgrade to stronger cryptographic algorithms');
        }

        if (issueTypes.has('unsafe_functions')) {
            recommendations.push('Review and secure all command execution functions');
        }

        if (recommendations.length === 0) {
            recommendations.push('Continue following secure coding practices');
        }

        return recommendations;
    }

    private createFallbackResponse(filePath: string): SecurityAnalysisResponse {
        return {
            issues: [],
            summary: 'Security analysis failed, manual review recommended',
            overallRisk: 'low',
            recommendations: ['Manually review this code for security issues'],
            analysisStats: {
                chunksAnalyzed: 0,
                securityPatternsFound: 0,
                contextualMatches: 0
            }
        };
    }
} 