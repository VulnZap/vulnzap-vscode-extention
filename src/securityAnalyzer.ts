import * as vscode from 'vscode';
import axios from 'axios';
import { APIProviderManager, AISecurityResponse } from './apiProviders';

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
}

export class SecurityAnalyzer {
    private apiProviderManager: APIProviderManager;
    private cache = new Map<string, { result: AISecurityResponse; timestamp: number }>();
    private readonly CACHE_DURATION = 5 * 60 * 1000; // 5 minutes
    private readonly MAX_CHUNK_SIZE = 4000; // Increased from 10000, but we'll chunk it
    private readonly MAX_FILE_SIZE = 50000; // Increased limit

    constructor() {
        this.apiProviderManager = new APIProviderManager();
        
        // Listen for configuration changes to update the current provider
        vscode.workspace.onDidChangeConfiguration((event) => {
            if (event.affectsConfiguration('inlineSecurityReviewer.apiProvider')) {
                this.apiProviderManager.updateCurrentProvider();
            }
        });
    }

    async analyzeDocument(document: vscode.TextDocument): Promise<SecurityIssue[]> {
        const aiEnabled = vscode.workspace.getConfiguration('inlineSecurityReviewer').get('enableAIAnalysis', true);
        
        if (!aiEnabled) {
            console.log('AI analysis disabled, using basic analysis');
            return this.fallbackToBasicAnalysis(document);
        }

        const currentProvider = this.apiProviderManager.getCurrentProvider();
        if (!currentProvider) {
            console.log('No API provider configured, falling back to basic analysis');
            return this.fallbackToBasicAnalysis(document);
        }

        if (!currentProvider.isConfigured()) {
            console.log(`${currentProvider.displayName} not configured, falling back to basic analysis`);
            return this.fallbackToBasicAnalysis(document);
        }

        try {
            const text = document.getText();
            const languageId = document.languageId;
            
            console.log(`Analyzing ${languageId} file with ${text.length} characters using ${currentProvider.displayName}`);
            
            // Handle large files by chunking
            if (text.length > this.MAX_FILE_SIZE) {
                vscode.window.showWarningMessage(
                    `File too large (${text.length} chars). Using basic pattern matching only.`
                );
                return this.fallbackToBasicAnalysis(document);
            }
            
            // Check cache first
            const cacheKey = this.getCacheKey(text, languageId, currentProvider.name);
            const cached = this.cache.get(cacheKey);
            if (cached && Date.now() - cached.timestamp < this.CACHE_DURATION) {
                console.log('Using cached analysis result');
                return this.convertAIResponseToSecurityIssues(cached.result);
            }

            // For files larger than chunk size, analyze in chunks
            let allIssues: SecurityIssue[] = [];
            if (text.length > this.MAX_CHUNK_SIZE) {
                console.log('File large, analyzing in chunks...');
                allIssues = await this.analyzeInChunks(text, languageId);
            } else {
                // Get AI analysis through the provider manager
                const aiResponse = await this.apiProviderManager.analyzeCode(text, languageId);
                
                // Enhance with search results if enabled
                const enhancedResponse = await this.enhanceWithSearchResults(aiResponse, languageId);
                
                // Cache the result
                this.cache.set(cacheKey, { result: enhancedResponse, timestamp: Date.now() });
                
                allIssues = this.convertAIResponseToSecurityIssues(enhancedResponse);
            }
            
            // Refine issue positioning for better accuracy
            const refinedIssues = this.refineIssueLocations(allIssues, document);
            
            console.log(`Analysis complete: found ${refinedIssues.length} issues`);
            return refinedIssues;
        } catch (error) {
            console.error('AI analysis failed:', error);
            vscode.window.showErrorMessage(`AI analysis failed: ${error}`);
            return this.fallbackToBasicAnalysis(document);
        }
    }

    private async analyzeInChunks(code: string, language: string): Promise<SecurityIssue[]> {
        const lines = code.split('\n');
        const chunks: { text: string; startLine: number }[] = [];
        
        // Create overlapping chunks to avoid missing issues at boundaries
        let currentChunk = '';
        let currentStartLine = 0;
        let currentLineCount = 0;
        const linesPerChunk = Math.floor(this.MAX_CHUNK_SIZE / 50); // Estimate ~50 chars per line
        
        for (let i = 0; i < lines.length; i++) {
            currentChunk += lines[i] + '\n';
            currentLineCount++;
            
            if (currentChunk.length >= this.MAX_CHUNK_SIZE || currentLineCount >= linesPerChunk) {
                chunks.push({ text: currentChunk, startLine: currentStartLine });
                
                // Start next chunk with some overlap (last 10 lines)
                const overlapLines = Math.min(10, currentLineCount);
                const overlapStart = Math.max(0, i - overlapLines + 1);
                currentChunk = lines.slice(overlapStart, i + 1).join('\n') + '\n';
                currentStartLine = overlapStart;
                currentLineCount = i - overlapStart + 1;
            }
        }
        
        // Add remaining chunk
        if (currentChunk.trim()) {
            chunks.push({ text: currentChunk, startLine: currentStartLine });
        }
        
        console.log(`Analyzing ${chunks.length} chunks`);
        
        // Analyze each chunk
        const allIssues: SecurityIssue[] = [];
        for (let i = 0; i < chunks.length; i++) {
            try {
                console.log(`Analyzing chunk ${i + 1}/${chunks.length}`);
                const aiResponse = await this.apiProviderManager.analyzeCode(chunks[i].text, language);
                const enhancedResponse = await this.enhanceWithSearchResults(aiResponse, language);
                const chunkIssues = this.convertAIResponseToSecurityIssues(enhancedResponse);
                
                // Adjust line numbers for chunk offset
                chunkIssues.forEach(issue => {
                    issue.line += chunks[i].startLine;
                    issue.endLine += chunks[i].startLine;
                });
                
                allIssues.push(...chunkIssues);
            } catch (error) {
                console.error(`Failed to analyze chunk ${i + 1}:`, error);
                // Continue with other chunks
            }
        }
        
        // Remove duplicates based on line and message
        const uniqueIssues = this.removeDuplicateIssues(allIssues);
        return uniqueIssues;
    }

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

    private async performSecuritySearch(searchQuery: string, language: string): Promise<{cves: string[], summaries: string[]}> {
        try {
            const enhancedQuery = `${searchQuery} ${language} security vulnerability CVE`;
            const searchApiKey = vscode.workspace.getConfiguration('inlineSecurityReviewer').get<string>('googleSearchApiKey');
            const searchEngineId = vscode.workspace.getConfiguration('inlineSecurityReviewer').get<string>('googleSearchEngineId');
            
            if (!searchApiKey || !searchEngineId) {
                return { cves: [], summaries: [] };
            }

            const response = await axios.get('https://www.googleapis.com/customsearch/v1', {
                params: {
                    key: searchApiKey,
                    cx: searchEngineId,
                    q: enhancedQuery,
                    num: 5
                },
                timeout: 5000
            });

            const items = response.data.items || [];
            const cves: string[] = [];
            const summaries: string[] = [];

            for (const item of items) {
                // Extract CVE numbers from title and snippet
                const cveMatches = (item.title + ' ' + item.snippet).match(/CVE-\d{4}-\d{4,}/g);
                if (cveMatches) {
                    cves.push(...cveMatches);
                }
                
                summaries.push(item.snippet);
            }

            return { 
                cves: [...new Set(cves)].slice(0, 3), // Remove duplicates and limit
                summaries: summaries.slice(0, 3)
            };
        } catch (error) {
            console.error('Search API failed:', error);
            return { cves: [], summaries: [] };
        }
    }

    private convertAIResponseToSecurityIssues(aiResponse: AISecurityResponse): SecurityIssue[] {
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

        // Filter out low-confidence issues and false positives
        return this.filterHighConfidenceIssues(issues);
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
        const minConfidence = vscode.workspace.getConfiguration('inlineSecurityReviewer').get<number>('confidenceThreshold', 80);
        
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

    private async enhanceWithSearchResults(aiResponse: AISecurityResponse, language: string): Promise<AISecurityResponse> {
        const searchEnabled = vscode.workspace.getConfiguration('inlineSecurityReviewer').get('enableSearchEnhancement', true);
        
        if (!searchEnabled) {
            return aiResponse;
        }

        // Only enhance issues that have search queries
        const enhancedIssues = await Promise.all(
            aiResponse.issues.map(async (issue) => {
                if (issue.searchQuery) {
                    try {
                        const searchResults = await this.performSecuritySearch(issue.searchQuery, language);
                        return {
                            ...issue,
                            cve: [...(issue.cve || []), ...searchResults.cves],
                            searchResults: searchResults.summaries
                        };
                    } catch (error) {
                        console.error('Search enhancement failed:', error);
                        return issue;
                    }
                }
                return issue;
            })
        );

        return {
            ...aiResponse,
            issues: enhancedIssues
        };
    }

    private fallbackToBasicAnalysis(document: vscode.TextDocument): SecurityIssue[] {
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
}