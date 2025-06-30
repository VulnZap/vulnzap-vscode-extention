import * as vscode from 'vscode';
import axios from 'axios';
import { APIProviderManager, AISecurityResponse } from '../providers/apiProviders';
import { ContextAnalyzer, CodeContext, SecurityContext } from '../utils/contextAnalyzer';
import { VectorIndexer, CodeChunk, SearchResult } from './vectorIndexer';
import { ASTAnalyzerFactory } from './astAnalyzerFactory';
import { ASTSecurityAnalyzer } from './astAnalyzer';

/**
 * Represents a security vulnerability found in code
 * Contains location information, severity, and remediation suggestions
 */
export interface SecurityIssue {
    line: number;
    column: number;
    endLine: number;
    endColumn: number;
    message: string;
    severity: vscode.DiagnosticSeverity;
    code: string;
    suggestion?: string;
    confidence?: number;
    cve?: string[];
    searchResults?: string[];
    relatedCode?: CodeChunk[];
    similarVulnerabilities?: CodeChunk[];
}

/**
 * Core security analysis engine that combines AI-powered detection with traditional pattern matching
 * Provides context-aware vulnerability detection with vector-based code similarity analysis
 */
export class SecurityAnalyzer {
    private apiProviderManager: APIProviderManager;
    private contextAnalyzer: ContextAnalyzer;
    private vectorIndexer: VectorIndexer | null = null;
    private cache = new Map<string, { result: AISecurityResponse; timestamp: number }>();
    
    // Configuration constants for analysis optimization
    private readonly CACHE_DURATION = 10 * 60 * 1000; // 10 minutes to reduce API costs
    private readonly MAX_CHUNK_SIZE = 4000; // Maximum size for AI analysis chunks
    private readonly MAX_FILE_SIZE = 50000; // Files larger than this use basic analysis only

    constructor(vectorIndexer?: VectorIndexer) {
        this.apiProviderManager = new APIProviderManager();
        this.contextAnalyzer = new ContextAnalyzer();
        this.vectorIndexer = vectorIndexer || null;
    }

    /**
     * Sets the vector indexer for enhanced semantic analysis
     */
    setVectorIndexer(vectorIndexer: VectorIndexer): void {
        this.vectorIndexer = vectorIndexer;
    }

    /**
     * Main entry point for document analysis
     * Combines AST-guided precision with AI analysis, context awareness and vector similarity matching
     */
    async analyzeDocument(document: vscode.TextDocument): Promise<SecurityIssue[]> {
        const config = vscode.workspace.getConfiguration('vulnzap');
        const aiEnabled = config.get('enableAIAnalysis', true);
        const astPrecisionEnabled = config.get('enableASTPrecision', true);
        
        // Analyze document context to understand its purpose and reduce false positives
        const codeContext = await this.contextAnalyzer.analyzeDocumentContext(document);
        console.log(`Context analysis: fileType=${codeContext.fileType}, framework=${codeContext.framework}, isTest=${codeContext.isTestFile}`);
        
        if (!aiEnabled) {
            console.log('AI analysis disabled, using basic analysis');
            const basicIssues = this.fallbackToBasicAnalysis(document);
            return this.filterIssuesWithContext(basicIssues, document, codeContext);
        }

        const currentProvider = this.apiProviderManager.getCurrentProvider();
        if (!currentProvider) {
            console.log('No API provider configured, falling back to basic analysis');
            const basicIssues = this.fallbackToBasicAnalysis(document);
            return this.filterIssuesWithContext(basicIssues, document, codeContext);
        }

        if (!currentProvider.isConfigured()) {
            console.log(`${currentProvider.displayName} not configured, falling back to basic analysis`);
            const basicIssues = this.fallbackToBasicAnalysis(document);
            return this.filterIssuesWithContext(basicIssues, document, codeContext);
        }

        try {
            const text = document.getText();
            const languageId = document.languageId;
            
            // Determine analysis method based on language support and user preference
            const useASTAnalysis = astPrecisionEnabled && ASTAnalyzerFactory.isSupported(languageId);
            const analysisMethod = useASTAnalysis ? 'AST-guided precision' : 'traditional';
            
            console.log(`Analyzing ${languageId} file with ${text.length} characters using ${currentProvider.displayName} (${analysisMethod})`);
            
            // Skip AI analysis for very large files to avoid performance issues
            if (text.length > this.MAX_FILE_SIZE) {
                vscode.window.showWarningMessage(
                    `File too large (${text.length} chars). Using basic pattern matching only.`
                );
                const basicIssues = this.fallbackToBasicAnalysis(document);
                return this.filterIssuesWithContext(basicIssues, document, codeContext);
            }
            
            // Check cache for recent analysis results to reduce API costs
            const contextHash = this.getContextHash(codeContext);
            const cacheKey = this.getCacheKey(text, languageId, currentProvider.name) + '_' + contextHash + '_' + analysisMethod;
            const cached = this.cache.get(cacheKey);
            if (cached && Date.now() - cached.timestamp < this.CACHE_DURATION) {
                console.log('Using cached analysis result');
                const cachedIssues = this.convertAIResponseToSecurityIssues(cached.result);
                const enhancedIssues = await this.enhanceIssuesWithVectorContext(cachedIssues, document, codeContext);
                return this.filterIssuesWithContext(enhancedIssues, document, codeContext);
            }

            // Handle large files by breaking them into analyzable chunks
            let allIssues: SecurityIssue[] = [];
            if (text.length > this.MAX_CHUNK_SIZE) {
                console.log('File large, analyzing in chunks...');
                allIssues = await this.analyzeInChunks(text, languageId);
            } else {
                // Use AST-guided analysis if available, otherwise fall back to enhanced prompt
                let aiResponse: AISecurityResponse;
                
                if (useASTAnalysis) {
                    console.log('Using AST-guided analysis for precise vulnerability detection');
                    aiResponse = await this.apiProviderManager.analyzeCode(text, languageId);
                } else {
                    // Build enhanced prompt with context and vector-based insights for non-AST languages
                    const contextEnhancedCode = await this.buildVectorEnhancedPrompt(text, languageId, codeContext, document);
                    aiResponse = await this.apiProviderManager.analyzeCode(contextEnhancedCode, languageId);
                }
                
                // Store result in cache for future use
                this.cache.set(cacheKey, { result: aiResponse, timestamp: Date.now() });
                
                allIssues = this.convertAIResponseToSecurityIssues(aiResponse);
            }
            
            // For AST-guided analysis, issues are already precise; for others, refine locations
            let refinedIssues: SecurityIssue[];
            if (useASTAnalysis) {
                console.log('Using precise AST-guided issue locations');
                refinedIssues = allIssues; // Already precise from AST analysis
            } else {
                // Improve issue location accuracy by analyzing surrounding code
                refinedIssues = this.refineIssueLocations(allIssues, document);
            }
            
            // Add vector-based context and similar vulnerability examples
            const vectorEnhancedIssues = await this.enhanceIssuesWithVectorContext(refinedIssues, document, codeContext);
            
            // Filter out likely false positives based on code context
            const contextFilteredIssues = this.filterIssuesWithContext(vectorEnhancedIssues, document, codeContext);
            
            const preciseCount = contextFilteredIssues.filter(issue => (issue as any).precise).length;
            console.log(`Analysis complete: found ${contextFilteredIssues.length} issues (${preciseCount} precise, filtered from ${refinedIssues.length} total)`);
            return contextFilteredIssues;
        } catch (error) {
            console.error('AI analysis failed:', error);
            vscode.window.showErrorMessage(`AI analysis failed: ${error}`);
            const basicIssues = this.fallbackToBasicAnalysis(document);
            return this.filterIssuesWithContext(basicIssues, document, codeContext);
        }
    }

    /**
     * Breaks large files into overlapping chunks for analysis
     * Ensures no vulnerabilities are missed at chunk boundaries
     */
    private async analyzeInChunks(code: string, language: string): Promise<SecurityIssue[]> {
        const lines = code.split('\n');
        const chunks: { text: string; startLine: number }[] = [];
        
        // Create overlapping chunks to catch vulnerabilities spanning boundaries
        let currentChunk = '';
        let currentStartLine = 0;
        let currentLineCount = 0;
        const linesPerChunk = Math.floor(this.MAX_CHUNK_SIZE / 50); // Estimate ~50 chars per line
        
        for (let i = 0; i < lines.length; i++) {
            currentChunk += lines[i] + '\n';
            currentLineCount++;
            
            if (currentChunk.length >= this.MAX_CHUNK_SIZE || currentLineCount >= linesPerChunk) {
                chunks.push({ text: currentChunk, startLine: currentStartLine });
                
                // Create overlap with previous chunk to avoid missing boundary issues
                const overlapLines = Math.min(10, currentLineCount);
                const overlapStart = Math.max(0, i - overlapLines + 1);
                currentChunk = lines.slice(overlapStart, i + 1).join('\n') + '\n';
                currentStartLine = overlapStart;
                currentLineCount = i - overlapStart + 1;
            }
        }
        
        // Process any remaining content
        if (currentChunk.trim()) {
            chunks.push({ text: currentChunk, startLine: currentStartLine });
        }
        
        console.log(`Analyzing ${chunks.length} chunks`);
        
        // Analyze each chunk independently
        const allIssues: SecurityIssue[] = [];
        for (let i = 0; i < chunks.length; i++) {
            try {
                console.log(`Analyzing chunk ${i + 1}/${chunks.length}`);
                const aiResponse = await this.apiProviderManager.analyzeCode(chunks[i].text, language);
                const chunkIssues = this.convertAIResponseToSecurityIssues(aiResponse);
                
                // Adjust line numbers to account for chunk positioning in the original file
                chunkIssues.forEach(issue => {
                    issue.line += chunks[i].startLine;
                    issue.endLine += chunks[i].startLine;
                });
                
                allIssues.push(...chunkIssues);
            } catch (error) {
                console.error(`Failed to analyze chunk ${i + 1}:`, error);
                // Continue with remaining chunks even if one fails
            }
        }
        
        // Remove duplicates that may occur at chunk boundaries
        const uniqueIssues = this.removeDuplicateIssues(allIssues);
        return uniqueIssues;
    }

    /**
     * Removes duplicate security issues based on location and content
     */
    private removeDuplicateIssues(issues: SecurityIssue[]): SecurityIssue[] {
        const seen = new Set<string>();
        return issues.filter(issue => {
            const key = `${issue.line}-${issue.column}-${issue.code}-${issue.message}`;
            if (seen.has(key)) {
                return false;
            }
            seen.add(key);
            return true;
        });
    }

    private convertAIResponseToSecurityIssues(aiResponse: AISecurityResponse): SecurityIssue[] {
        console.log('SecurityAnalyzer: Converting AI response to security issues');
        console.log('AI Response:', JSON.stringify(aiResponse, null, 2));

        const issues = aiResponse.issues.map(issue => ({
            line: issue.line,
            column: issue.column,
            endLine: issue.endLine,
            endColumn: issue.endColumn,
            message: issue.message,
            severity: this.convertSeverity(issue.severity),
            code: issue.code,
            suggestion: issue.suggestion,
            confidence: issue.confidence,
            cve: issue.cve,
            searchResults: (issue as any).searchResults
        }));

        console.log('Converted issues before filtering:', JSON.stringify(issues, null, 2));

        // Filter out low-confidence issues and false positives
        const filteredIssues = this.filterHighConfidenceIssues(issues);
        console.log('Final filtered issues:', JSON.stringify(filteredIssues, null, 2));
        
        return filteredIssues;
    }

    /**
     * Refines the positioning of security issues to point to the exact vulnerable code
     * @param issues Array of security issues with potentially imprecise locations
     * @param document The text document being analyzed
     * @returns Array of security issues with refined locations
     */
    private refineIssueLocations(issues: SecurityIssue[], document: vscode.TextDocument): SecurityIssue[] {
        return issues.map(issue => {
            const refinedIssue = { ...issue };
            
            try {
                const lineText = document.lineAt(issue.line).text;
                const preciseLocation = this.locateVulnerableCode(lineText, issue.code, issue.message);
                
                if (preciseLocation) {
                    refinedIssue.column = preciseLocation.startColumn;
                    refinedIssue.endColumn = preciseLocation.endColumn;
                }
            } catch (error) {
                console.error('Failed to refine issue location:', error);
            }
            
            return refinedIssue;
        });
    }

    /**
     * Locates the exact position of vulnerable code within a line of text
     * @param lineText The text content of the line
     * @param code The security issue code
     * @param message The security issue message
     * @returns Object with start and end column positions, or null if not found
     */
    private locateVulnerableCode(lineText: string, code: string, message: string): { startColumn: number; endColumn: number } | null {
        const lowerLineText = lineText.toLowerCase();
        const lowerMessage = message.toLowerCase();
        
        // Security vulnerability patterns organized by category
        const vulnerabilityPatterns: { [key: string]: RegExp[] } = {
            // Cross-Site Scripting (XSS) patterns
            'innerHTML': [/innerHTML\s*=/g, /\.innerHTML/g],
            'xss': [/innerHTML\s*=/g, /document\.write\s*\(/g, /\.html\s*\(/g],
            'document.write': [/document\.write\s*\(/g],
            
            // Code injection patterns
            'eval': [/eval\s*\(/g],
            'exec': [/exec\s*\(/g],
            
            // Weak cryptography patterns
            'Math.random': [/Math\.random\s*\(\s*\)/g],
            'crypto': [/Math\.random/g, /Math\.floor\s*\(\s*Math\.random/g],
            'md5': [/createHash\s*\(\s*['"`]md5['"`]\s*\)/g, /md5\s*\(/g],
            'weak_crypto': [/createHash\s*\(\s*['"`](md5|sha1)['"`]\s*\)/g],
            
            // Hardcoded secrets patterns
            'api_key': [/api.{0,10}key.{0,20}[:=]\s*['"`][^'"`\s]{10,}['"`]/gi, /['"`][a-zA-Z0-9]{20,}['"`]/g],
            'secret': [/secret.{0,10}[:=]\s*['"`][^'"`\s]{8,}['"`]/gi, /password.{0,10}[:=]\s*['"`][^'"`\s]{6,}['"`]/gi],
            'hardcoded': [/['"`][a-zA-Z0-9_-]{15,}['"`]/g],
            
            // Command injection patterns
            'os.system': [/os\.system\s*\(/g],
            'subprocess': [/subprocess\.\w+/g],
            
            // SQL injection patterns
            'sql': [/(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)\s+/gi]
        };

        // Try to match based on the vulnerability code or message content
        let patternsToTry: RegExp[] = [];
        
        // Check message content for common vulnerability types
        if (lowerMessage.includes('innerHTML') || lowerMessage.includes('xss')) {
            patternsToTry = vulnerabilityPatterns['innerHTML'] || [];
        } else if (lowerMessage.includes('eval')) {
            patternsToTry = vulnerabilityPatterns['eval'] || [];
        } else if (lowerMessage.includes('math.random') || lowerMessage.includes('weak') || lowerMessage.includes('random')) {
            patternsToTry = vulnerabilityPatterns['Math.random'] || [];
        } else if (lowerMessage.includes('document.write')) {
            patternsToTry = vulnerabilityPatterns['document.write'] || [];
        } else if (lowerMessage.includes('os.system') || lowerMessage.includes('system')) {
            patternsToTry = vulnerabilityPatterns['os.system'] || [];
        } else if (lowerMessage.includes('md5') || lowerMessage.includes('weak') && lowerMessage.includes('hash')) {
            patternsToTry = vulnerabilityPatterns['md5'] || [];
        } else if (lowerMessage.includes('api key') || lowerMessage.includes('hardcoded') || lowerMessage.includes('secret')) {
            patternsToTry = vulnerabilityPatterns['api_key'] || [];
        }

        // Try each pattern
        for (const pattern of patternsToTry) {
            pattern.lastIndex = 0; // Reset regex
            const match = pattern.exec(lineText);
            if (match) {
                return {
                    startColumn: match.index,
                    endColumn: match.index + match[0].length
                };
            }
        }

        // Fallback: try to find any suspicious keywords in the line
        const suspiciousKeywords = ['innerHTML', 'eval', 'Math.random', 'document.write', 'os.system', 'exec'];
        for (const keyword of suspiciousKeywords) {
            const index = lowerLineText.indexOf(keyword.toLowerCase());
            if (index !== -1) {
                return {
                    startColumn: index,
                    endColumn: index + keyword.length
                };
            }
        }

        return null;
    }

    /**
     * Filters security issues based on confidence threshold and removes false positives
     * @param issues Array of security issues to filter
     * @returns Filtered array of high-confidence security issues
     */
    private filterHighConfidenceIssues(issues: SecurityIssue[]): SecurityIssue[] {
        const minConfidence = vscode.workspace.getConfiguration('vulnzap').get<number>('confidenceThreshold', 80);
        
        return issues.filter(issue => {
            // Apply confidence threshold
            if (issue.confidence && issue.confidence < minConfidence) {
                console.log(`Filtering out low-confidence issue: ${issue.message} (confidence: ${issue.confidence}%)`);
                return false;
            }

            // Filter out common false positives
            if (this.isFalsePositive(issue)) {
                console.log(`Filtering out false positive: ${issue.message}`);
                return false;
            }

            return true;
        });
    }

    /**
     * Determines if a security issue is likely a false positive
     * @param issue The security issue to evaluate
     * @returns true if the issue appears to be a false positive
     */
    private isFalsePositive(issue: SecurityIssue): boolean {
        const message = issue.message.toLowerCase();
        
        // Patterns that commonly indicate false positive security warnings
        const falsePositivePatterns = [
            // Uncertain language suggesting possibilities rather than actual issues
            /might contain/i,
            /could potentially/i,
            /may be vulnerable/i,
            /consider checking/i,
            /should verify/i,
            /appears to/i,
            
            // Legitimate development and debugging practices
            /console\.log/i,
            /debug/i,
            /test.*file/i,
            /logging/i,
            /print\s*\(/i,
            
            // False alarms on file paths and naming conventions
            /file.*path.*suspicious/i,
            /variable.*name.*suspicious/i,
            /string.*contains.*test/i,
            /filename.*indicates/i,
            
            // Generic security advice without concrete evidence
            /file.*check.*secret/i,
            /ensure.*no.*secret/i,
            /review.*for.*security/i,
            /general.*security.*practice/i
        ];

        return falsePositivePatterns.some(pattern => pattern.test(message));
    }

    private convertSeverity(severity: string): vscode.DiagnosticSeverity {
        switch (severity.toLowerCase()) {
            case 'error':
                return vscode.DiagnosticSeverity.Error;
            case 'warning':
                return vscode.DiagnosticSeverity.Warning;
            case 'info':
                return vscode.DiagnosticSeverity.Information;
            default:
                return vscode.DiagnosticSeverity.Warning;
        }
    }

    private getCacheKey(text: string, language: string, provider?: string): string {
        // Simple hash function for caching
        let hash = 0;
        const str = text + language + (provider || 'default');
        for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // Convert to 32-bit integer
        }
        return hash.toString();
    }

    public fallbackToBasicAnalysis(document: vscode.TextDocument): SecurityIssue[] {
        // Fallback to basic pattern matching if AI fails
        const basicRules = this.getBasicSecurityRules(document.languageId);
        const issues: SecurityIssue[] = [];
        const text = document.getText();
        const lines = text.split('\n');

        for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
            const line = lines[lineIndex];
            
            for (const rule of basicRules) {
                const matches = rule.pattern.exec(line);
                if (matches) {
                    issues.push({
                        line: lineIndex,
                        column: matches.index,
                        endLine: lineIndex,
                        endColumn: matches.index + matches[0].length,
                        message: rule.message,
                        severity: rule.severity,
                        code: rule.code,
                        suggestion: rule.suggestion,
                        confidence: 70
                    });
                }
                rule.pattern.lastIndex = 0;
            }
        }

        return this.refineIssueLocations(issues, document);
    }

    private getBasicSecurityRules(languageId: string): Array<{code: string, pattern: RegExp, message: string, severity: vscode.DiagnosticSeverity, suggestion?: string}> {
        const commonRules = [
            {
                code: 'SEC001',
                pattern: /eval\s*\(/g,
                message: 'Avoid using eval() - potential code injection',
                severity: vscode.DiagnosticSeverity.Error,
                suggestion: 'Use safer alternatives like JSON.parse()'
            },
            {
                code: 'SEC002',
                pattern: /innerHTML\s*=/g,
                message: 'innerHTML assignment - potential XSS vulnerability',
                severity: vscode.DiagnosticSeverity.Warning,
                suggestion: 'Use textContent or sanitize input'
            }
        ];

        return commonRules;
    }

    /**
     * Filter security issues using context analysis to reduce false positives
     */
    private filterIssuesWithContext(
        issues: SecurityIssue[], 
        document: vscode.TextDocument, 
        codeContext: CodeContext
    ): SecurityIssue[] {
        return issues.filter(issue => {
            const securityContext = this.contextAnalyzer.analyzeSecurityContext(
                document, 
                issue.line, 
                issue.column, 
                codeContext
            );

            const isLikelyFalsePositive = this.contextAnalyzer.isLikelyFalsePositive(
                issue, 
                codeContext, 
                securityContext
            );

            if (isLikelyFalsePositive) {
                console.log(`Filtered false positive: ${issue.message} (context: ${this.getContextDescription(securityContext)})`);
                return false;
            }

            // Adjust confidence based on context
            if (issue.confidence) {
                issue.confidence = this.adjustConfidenceBasedOnContext(issue.confidence, securityContext);
            }

            return true;
        });
    }

    /**
     * Generate a hash of the code context for caching purposes
     */
    private getContextHash(codeContext: CodeContext): string {
        const contextString = JSON.stringify({
            fileType: codeContext.fileType,
            framework: codeContext.framework,
            isTestFile: codeContext.isTestFile,
            isConfigFile: codeContext.isConfigFile,
            dependencies: codeContext.dependencies.slice(0, 10) // Limit for performance
        });

        let hash = 0;
        for (let i = 0; i < contextString.length; i++) {
            const char = contextString.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // Convert to 32-bit integer
        }
        return hash.toString();
    }

    /**
     * Build an enhanced prompt that includes context information for better AI analysis
     */
    private buildContextEnhancedPrompt(code: string, language: string, codeContext: CodeContext): string {
        let contextInfo = `Context: This is a ${codeContext.fileType} file`;
        
        if (codeContext.framework) {
            contextInfo += ` using ${codeContext.framework} framework`;
        }
        
        if (codeContext.isTestFile) {
            contextInfo += `. This appears to be a test file - be more lenient with security patterns that are acceptable in testing contexts.`;
        }
        
        if (codeContext.isConfigFile) {
            contextInfo += `. This is a configuration file - hardcoded values may be acceptable.`;
        }

        if (codeContext.dependencies.length > 0) {
            const securityLibs = codeContext.dependencies.filter(dep => 
                ['helmet', 'cors', 'bcrypt', 'validator', 'joi', 'yup', 'sanitize', 'escape'].some(lib => 
                    dep.includes(lib)
                )
            );
            if (securityLibs.length > 0) {
                contextInfo += ` Security libraries detected: ${securityLibs.slice(0, 3).join(', ')}.`;
            }
        }

        return `${contextInfo}\n\nCode to analyze:\n\`\`\`${language}\n${code}\n\`\`\``;
    }

    /**
     * Adjust confidence score based on security context
     */
    private adjustConfidenceBasedOnContext(originalConfidence: number, securityContext: SecurityContext): number {
        let adjustedConfidence = originalConfidence;

        // Increase confidence for issues in production code with real user input
        if (securityContext.dataFlowContext.hasUserInput && !securityContext.isInTestContext) {
            adjustedConfidence = Math.min(100, adjustedConfidence + 10);
        }

        // Decrease confidence for issues with proper validation/sanitization
        if (securityContext.hasInputValidation && securityContext.hasOutputSanitization) {
            adjustedConfidence = Math.max(0, adjustedConfidence - 20);
        }

        // Decrease confidence for issues in string literals without user input
        if (securityContext.isInStringLiteral && !securityContext.dataFlowContext.hasUserInput) {
            adjustedConfidence = Math.max(0, adjustedConfidence - 15);
        }

        // Increase confidence when using security libraries
        if (securityContext.usesSecurityLibrary) {
            adjustedConfidence = Math.min(100, adjustedConfidence + 5);
        }

        return adjustedConfidence;
    }

    /**
     * Get a human-readable description of the security context for logging
     */
    private getContextDescription(securityContext: SecurityContext): string {
        const descriptions: string[] = [];
        
        if (securityContext.isInTestContext) descriptions.push('test');
        if (securityContext.isInMockContext) descriptions.push('mock');
        if (securityContext.isInCommentBlock) descriptions.push('comment');
        if (securityContext.isInStringLiteral) descriptions.push('string');
        if (securityContext.hasInputValidation) descriptions.push('validated');
        if (securityContext.hasOutputSanitization) descriptions.push('sanitized');
        if (securityContext.usesSecurityLibrary) descriptions.push('secured');
        
        return descriptions.join(', ') || 'unknown';
    }

    /**
     * Enhance security issues with vector context from similar code patterns
     */
    private async enhanceIssuesWithVectorContext(
        issues: SecurityIssue[], 
        document: vscode.TextDocument, 
        codeContext: CodeContext
    ): Promise<SecurityIssue[]> {
        if (!this.vectorIndexer) {
            return issues;
        }

        const enhancedIssues: SecurityIssue[] = [];

        for (const issue of issues) {
            try {
                // Get the problematic code snippet
                const line = document.lineAt(issue.line);
                const codeSnippet = this.getExpandedCodeSnippet(document, issue.line, 3);

                // Find vector context for this issue
                const vectorContext = await this.vectorIndexer.getSecurityAnalysisContext(
                    codeSnippet,
                    document.fileName,
                    issue.line
                );

                // Enhance the issue with vector context
                const enhancedIssue: SecurityIssue = {
                    ...issue,
                    relatedCode: vectorContext.relatedSecurityPatterns,
                    similarVulnerabilities: vectorContext.similarVulnerabilities
                };

                // Enhance suggestion with similar code patterns
                if (vectorContext.similarVulnerabilities.length > 0) {
                    const suggestions = this.generateContextualSuggestions(issue, vectorContext.similarVulnerabilities);
                    enhancedIssue.suggestion = enhancedIssue.suggestion 
                        ? `${enhancedIssue.suggestion}\n\nRelated patterns found: ${suggestions}`
                        : `Related patterns found: ${suggestions}`;
                }

                // Adjust confidence based on similar vulnerability patterns
                if (vectorContext.similarVulnerabilities.length > 2) {
                    enhancedIssue.confidence = Math.min((enhancedIssue.confidence || 0.5) + 0.2, 1.0);
                }

                enhancedIssues.push(enhancedIssue);
            } catch (error) {
                console.error(`Failed to enhance issue with vector context:`, error);
                enhancedIssues.push(issue); // Fall back to original issue
            }
        }

        return enhancedIssues;
    }

    /**
     * Build a vector-enhanced prompt that includes context from similar code patterns
     */
    private async buildVectorEnhancedPrompt(
        code: string, 
        language: string, 
        codeContext: CodeContext,
        document: vscode.TextDocument
    ): Promise<string> {
        let enhancedPrompt = this.buildContextEnhancedPrompt(code, language, codeContext);

        if (!this.vectorIndexer) {
            return enhancedPrompt;
        }

        try {
            // Find similar security-relevant code patterns
            const similarPatterns = await this.vectorIndexer.findSimilarCode(code, {
                maxResults: 3,
                securityRelevanceOnly: true,
                similarityThreshold: 0.6
            });

            if (similarPatterns.length > 0) {
                enhancedPrompt += '\n\n## Similar Security Patterns Found:\n';
                enhancedPrompt += 'The following similar code patterns were found in the codebase that may help inform your analysis:\n\n';

                for (const pattern of similarPatterns) {
                    // Add null check for pattern.chunk.content
                    if (!pattern.chunk.content) {
                        console.warn(`Pattern chunk has undefined content for ${pattern.chunk.filePath}`);
                        continue;
                    }
                    
                    enhancedPrompt += `### Pattern from ${pattern.chunk.filePath} (similarity: ${(pattern.similarity * 100).toFixed(1)}%):\n`;
                    enhancedPrompt += `Security relevance: ${pattern.chunk.securityRelevance}\n`;
                    enhancedPrompt += '```\n';
                    enhancedPrompt += pattern.chunk.content.substring(0, 500) + (pattern.chunk.content.length > 500 ? '...' : '');
                    enhancedPrompt += '\n```\n\n';
                }

                enhancedPrompt += 'Please consider these patterns when analyzing the target code for potential security issues.\n';
            }

            // Add framework-specific context if available
            if (codeContext.framework) {
                const frameworkPatterns = await this.vectorIndexer.findSimilarCode(`${codeContext.framework} security`, {
                    maxResults: 2,
                    securityRelevanceOnly: true,
                    similarityThreshold: 0.5
                });

                if (frameworkPatterns.length > 0) {
                    enhancedPrompt += '\n## Framework-Specific Security Patterns:\n';
                    for (const pattern of frameworkPatterns) {
                        // Add null check for pattern.chunk.content
                        if (pattern.chunk.content) {
                            enhancedPrompt += `- Pattern: ${pattern.chunk.content.substring(0, 200)}...\n`;
                        }
                    }
                }
            }

        } catch (error) {
            console.error('Failed to enhance prompt with vector context:', error);
        }

        return enhancedPrompt;
    }

    /**
     * Generate contextual suggestions based on similar vulnerability patterns
     */
    private generateContextualSuggestions(issue: SecurityIssue, similarVulnerabilities: CodeChunk[]): string {
        const suggestions: string[] = [];

        for (const vuln of similarVulnerabilities.slice(0, 3)) {
            // Add null check for vuln.content
            if (!vuln.content) {
                continue;
            }
            
            // Extract potential fixes from similar patterns
            if (vuln.content.includes('sanitize') || vuln.content.includes('escape')) {
                suggestions.push(`Consider sanitization (similar pattern in ${vuln.filePath})`);
            }
            if (vuln.content.includes('validate') || vuln.content.includes('check')) {
                suggestions.push(`Add input validation (pattern found in ${vuln.filePath})`);
            }
            if (vuln.content.includes('jwt') || vuln.content.includes('token')) {
                suggestions.push(`Consider token-based authentication (pattern in ${vuln.filePath})`);
            }
        }

        return suggestions.length > 0 ? suggestions.join('; ') : 'Review similar patterns in related files';
    }

    /**
     * Get expanded code snippet around a specific line
     */
    private getExpandedCodeSnippet(document: vscode.TextDocument, centerLine: number, radius: number): string {
        const startLine = Math.max(0, centerLine - radius);
        const endLine = Math.min(document.lineCount - 1, centerLine + radius);
        
        let snippet = '';
        for (let i = startLine; i <= endLine; i++) {
            snippet += document.lineAt(i).text + '\n';
        }
        
        return snippet;
    }
}