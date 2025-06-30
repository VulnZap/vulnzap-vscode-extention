import * as vscode from 'vscode';
import { SecurityIssue } from '../security/securityAnalyzer';
import { ASTSecurityAnalyzer, PreciseVulnerability } from '../security/astAnalyzer';

/**
 * Enhanced security issue with AST positioning information
 */
interface EnhancedSecurityIssue extends SecurityIssue {
    astNode?: {
        type: string;
        riskType: string;
        context: any;
    };
    precise?: boolean;
    absoluteStart?: number;
    absoluteEnd?: number;
}

/**
 * Handles VS Code diagnostic integration for security issues
 * Manages the display of security problems in the editor and provides AST-guided precision
 */
export class DiagnosticProvider implements vscode.Disposable {
    private diagnosticCollection: vscode.DiagnosticCollection;
    private codeActionProvider: vscode.Disposable;
    private securityViewProvider?: any; // Will be set by extension.ts
    private astAnalyzer: ASTSecurityAnalyzer;

    constructor(context: vscode.ExtensionContext) {
        // Create a diagnostic collection for security issues
        this.diagnosticCollection = vscode.languages.createDiagnosticCollection('security-reviewer');
        
        // Initialize AST analyzer for precise positioning
        this.astAnalyzer = new ASTSecurityAnalyzer('javascript');
        
        // Register quick fix provider for automatic issue resolution
        this.codeActionProvider = vscode.languages.registerCodeActionsProvider(
            ['javascript', 'typescript', 'python', 'java'],
            new SecurityCodeActionProvider(),
            {
                providedCodeActionKinds: [vscode.CodeActionKind.QuickFix]
            }
        );

        context.subscriptions.push(this.diagnosticCollection, this.codeActionProvider);
    }

    /**
     * Updates VS Code diagnostics with security issues using AST-guided precision
     * Converts SecurityIssue objects to VS Code Diagnostic objects with enhanced positioning
     */
    async updateDiagnostics(document: vscode.TextDocument, issues: SecurityIssue[]) {
        console.log(`DiagnosticProvider: Updating diagnostics for ${document.uri.fsPath} with ${issues.length} issues`);
        console.log('Issues received:', JSON.stringify(issues, null, 2));

        // Try to get AST-guided precise positioning for JavaScript/TypeScript files
        let astVulnerabilities: PreciseVulnerability[] = [];
        const language = this.getLanguageFromDocument(document);
        
        if (language === 'javascript' || language === 'typescript') {
            console.log(`Attempting AST analysis for ${language} file`);
            try {
                // Update AST analyzer language
                this.astAnalyzer = new ASTSecurityAnalyzer(language);
                
                // Perform AST analysis for precise positioning
                const astAnalysis = await this.astAnalyzer.analyzeCode(document.getText());
                astVulnerabilities = astAnalysis.vulnerabilities;
                
                console.log(`AST analysis found ${astVulnerabilities.length} precise vulnerabilities`);
            } catch (error) {
                console.warn('AST analysis failed, falling back to basic positioning:', error);
            }
        }

        const diagnostics: vscode.Diagnostic[] = issues.map((issue, index) => {
            console.log(`Creating diagnostic for issue ${index + 1} at line ${issue.line}, column ${issue.column}`);
            
            // Try to match this issue with an AST vulnerability for precise positioning
            const astMatch = this.findMatchingASTVulnerability(issue, astVulnerabilities, document);
            
            if (astMatch) {
                console.log(`Found AST match for issue ${index + 1}, using precise positioning`);
                return this.createDiagnosticFromAST(document, issue, astMatch);
            } else {
                console.log(`No AST match for issue ${index + 1}, using enhanced pattern-based positioning`);
                return this.createDiagnosticWithEnhancedPositioning(document, issue);
            }
        });

        console.log(`Setting ${diagnostics.length} diagnostics on diagnostic collection`);
        this.diagnosticCollection.set(document.uri, diagnostics);
        console.log('Diagnostics set successfully');
    }

    /**
     * Get language identifier from document
     */
    private getLanguageFromDocument(document: vscode.TextDocument): string {
        const languageMap: { [key: string]: string } = {
            'javascript': 'javascript',
            'typescript': 'typescript',
            'javascriptreact': 'javascript',
            'typescriptreact': 'typescript',
            'js': 'javascript',
            'ts': 'typescript',
            'jsx': 'javascript',
            'tsx': 'typescript'
        };
        
        return languageMap[document.languageId] || document.languageId;
    }

    /**
     * Find matching AST vulnerability for a security issue
     */
    private findMatchingASTVulnerability(
        issue: SecurityIssue, 
        astVulnerabilities: PreciseVulnerability[], 
        document: vscode.TextDocument
    ): PreciseVulnerability | null {
        // Try to find AST vulnerability that matches this issue by proximity and type
        for (const astVuln of astVulnerabilities) {
            // Check if line numbers are close (within 2 lines)
            const lineDistance = Math.abs(astVuln.line - (issue.line + 1)); // AST uses 1-based, issue might be 0-based
            
            if (lineDistance <= 2) {
                // Check if vulnerability types are related
                if (this.areVulnerabilityTypesRelated(issue.code, astVuln.vulnerability)) {
                    console.log(`Matched issue "${issue.code}" with AST vulnerability "${astVuln.vulnerability}" on line ${astVuln.line}`);
                    return astVuln;
                }
            }
        }
        
        return null;
    }

    /**
     * Check if vulnerability types are related
     */
    private areVulnerabilityTypesRelated(issueCode: string, astVulnType: string): boolean {
        const codeToTypeMap: { [key: string]: string[] } = {
            'SEC001': ['eval', 'code injection', 'dynamic code'],
            'SEC002': ['innerHTML', 'xss', 'cross-site scripting'],
            'SEC003': ['document.write', 'xss', 'cross-site scripting'],
            'SEC004': ['sql injection', 'template literal', 'query'],
            'SEC005': ['hardcoded secret', 'api key', 'password', 'token'],
            'SEC006': ['weak crypto', 'md5', 'sha1', 'random'],
            'SEC007': ['file operation', 'path traversal', 'file access']
        };
        
        const relatedTypes = codeToTypeMap[issueCode] || [];
        const lowerAstType = astVulnType.toLowerCase();
        
        return relatedTypes.some(type => lowerAstType.includes(type.toLowerCase()));
    }

    /**
     * Create diagnostic from AST analysis with precise positioning
     */
    private createDiagnosticFromAST(
        document: vscode.TextDocument, 
        issue: SecurityIssue, 
        astVuln: PreciseVulnerability
    ): vscode.Diagnostic {
        // Use AST-provided precise positioning
        const range = new vscode.Range(
            new vscode.Position(astVuln.line - 1, astVuln.column), // Convert to 0-based
            new vscode.Position(astVuln.endLine - 1, astVuln.endColumn)
        );

        console.log(`AST-guided range: line ${range.start.line}, char ${range.start.character} to line ${range.end.line}, char ${range.end.character}`);

        // Build enhanced message with AST confidence and context
        let enhancedMessage = `${issue.message} (AST-guided, ${astVuln.confidence}% confidence)`;
        if (issue.cve && issue.cve.length > 0) {
            enhancedMessage += ` [CVE: ${issue.cve.join(', ')}]`;
        }

        const diagnostic = new vscode.Diagnostic(
            range,
            enhancedMessage,
            issue.severity
        );

        diagnostic.code = issue.code;
        diagnostic.source = 'AI Security Reviewer (AST-Enhanced)';
        
        // Add AST-specific context information
        const relatedInfo: vscode.DiagnosticRelatedInformation[] = [];
        
        relatedInfo.push(new vscode.DiagnosticRelatedInformation(
            new vscode.Location(document.uri, range),
            `🎯 AST Context: ${astVuln.context.nodeType} in ${astVuln.context.parentContext}`
        ));

        if (astVuln.explanation) {
            relatedInfo.push(new vscode.DiagnosticRelatedInformation(
                new vscode.Location(document.uri, range),
                `📝 Explanation: ${astVuln.explanation}`
            ));
        }

        if (issue.suggestion) {
            relatedInfo.push(new vscode.DiagnosticRelatedInformation(
                new vscode.Location(document.uri, range),
                `💡 Suggestion: ${issue.suggestion}`
            ));
        }

        if (issue.cve && issue.cve.length > 0) {
            relatedInfo.push(new vscode.DiagnosticRelatedInformation(
                new vscode.Location(document.uri, range),
                `🔍 Related CVEs: ${issue.cve.join(', ')}`
            ));
        }

        diagnostic.relatedInformation = relatedInfo;
        return diagnostic;
    }

    /**
     * Create diagnostic with enhanced pattern-based positioning (fallback)
     */
    private createDiagnosticWithEnhancedPositioning(document: vscode.TextDocument, issue: SecurityIssue): vscode.Diagnostic {
        // Validate line numbers are within document bounds
        const maxLine = document.lineCount - 1;
        let safeLine = Math.min(Math.max(0, issue.line), maxLine);
        let safeEndLine = Math.min(Math.max(0, issue.endLine), maxLine);
        
        console.log(`Document has ${document.lineCount} lines, using line ${safeLine} to ${safeEndLine}`);
        
        // Get the actual line text to validate column positions
        const lineText = document.lineAt(safeLine).text;
        console.log(`Line ${safeLine} text: "${lineText}" (length: ${lineText.length})`);
        
        // For end line, check if it's different from start line
        let endLineText = lineText;
        if (safeEndLine !== safeLine && safeEndLine < document.lineCount) {
            endLineText = document.lineAt(safeEndLine).text;
            console.log(`End line ${safeEndLine} text: "${endLineText}" (length: ${endLineText.length})`);
        }
        
        // Use enhanced pattern matching for better positioning
        const { startColumn, endColumn } = this.findPreciseColumnPositions(lineText, issue);
        
        console.log(`Enhanced positioning: line ${safeLine}, column ${startColumn} to line ${safeEndLine}, column ${endColumn}`);
        
        const range = new vscode.Range(
            new vscode.Position(safeLine, startColumn),
            new vscode.Position(safeEndLine, endColumn)
        );

        // Build enhanced message with confidence and CVE information
        let enhancedMessage = issue.message;
        if (issue.confidence) {
            enhancedMessage += ` (Confidence: ${issue.confidence}%)`;
        }
        if (issue.cve && issue.cve.length > 0) {
            enhancedMessage += ` [CVE: ${issue.cve.join(', ')}]`;
        }

        const diagnostic = new vscode.Diagnostic(
            range,
            enhancedMessage,
            issue.severity
        );

        diagnostic.code = issue.code;
        diagnostic.source = 'AI Security Reviewer';
        
        // Add related information for enhanced context
        const relatedInfo: vscode.DiagnosticRelatedInformation[] = [];
        
        if (issue.suggestion) {
            relatedInfo.push(new vscode.DiagnosticRelatedInformation(
                new vscode.Location(document.uri, range),
                `💡 Suggestion: ${issue.suggestion}`
            ));
        }

        if (issue.cve && issue.cve.length > 0) {
            relatedInfo.push(new vscode.DiagnosticRelatedInformation(
                new vscode.Location(document.uri, range),
                `🔍 Related CVEs: ${issue.cve.join(', ')}`
            ));
        }

        if (issue.searchResults && issue.searchResults.length > 0) {
            for (let i = 0; i < Math.min(2, issue.searchResults.length); i++) {
                relatedInfo.push(new vscode.DiagnosticRelatedInformation(
                    new vscode.Location(document.uri, range),
                    `📖 Research: ${issue.searchResults[i]}`
                ));
            }
        }

        if (relatedInfo.length > 0) {
            diagnostic.relatedInformation = relatedInfo;
        }

        console.log(`Created diagnostic: ${diagnostic.message} at range ${diagnostic.range.start.line}:${diagnostic.range.start.character}-${diagnostic.range.end.line}:${diagnostic.range.end.character}`);
        return diagnostic;
    }

    /**
     * Find precise column positions using enhanced pattern matching
     */
    private findPreciseColumnPositions(lineText: string, issue: SecurityIssue): { startColumn: number, endColumn: number } {
        // Enhanced patterns based on vulnerability type
        const patterns = this.getVulnerabilityPatterns(issue.code);
        
        for (const pattern of patterns) {
            const match = pattern.exec(lineText);
            if (match) {
                const startColumn = match.index;
                const endColumn = match.index + match[0].length;
                console.log(`Found enhanced pattern match: "${match[0]}" at column ${startColumn}-${endColumn}`);
                return { startColumn, endColumn };
            }
        }
        
        // Fallback to original positioning or line-based
        let startColumn = Math.min(Math.max(0, issue.column), lineText.length);
        let endColumn = Math.min(Math.max(0, issue.endColumn), lineText.length);
        
        // If columns are still invalid, use entire line
        if (startColumn >= lineText.length || endColumn <= startColumn) {
            startColumn = 0;
            endColumn = lineText.length;
        }
        
        return { startColumn, endColumn };
    }

    /**
     * Get vulnerability-specific patterns for precise matching
     */
    private getVulnerabilityPatterns(code: string): RegExp[] {
        const patternMap: { [key: string]: RegExp[] } = {
            'SEC001': [
                /eval\s*\([^)]*\)/g,
                /Function\s*\([^)]*\)/g,
                /setTimeout\s*\([^,)]*,/g,
                /setInterval\s*\([^,)]*,/g
            ],
            'SEC002': [
                /\.innerHTML\s*=\s*[^;]+/g,
                /\.outerHTML\s*=\s*[^;]+/g
            ],
            'SEC003': [
                /document\.write\s*\([^)]*\)/g,
                /document\.writeln\s*\([^)]*\)/g
            ],
            'SEC004': [
                /`[^`]*\$\{[^}]*\}[^`]*`/g, // Template literals with interpolation
                /['"][^'"]*\+[^'"]*['"]/g   // String concatenation
            ],
            'SEC005': [
                /['"][a-zA-Z0-9_-]{20,}['"]/g,     // Long alphanumeric strings
                /['"]sk_[a-zA-Z0-9]{24,}['"]/g,    // Stripe keys
                /['"]pk_[a-zA-Z0-9]{24,}['"]/g,    // Stripe public keys
                /['"]AKIA[0-9A-Z]{16}['"]/g,       // AWS access keys
                /['"]ghp_[a-zA-Z0-9]{36}['"]/g,    // GitHub tokens
                /['"][^'"]*(?:api[_-]?key|password|secret|token)[^'"]*['"]/gi
            ],
            'SEC006': [
                /Math\.random\s*\(\s*\)/g,
                /\.md5\s*\(/g,
                /\.sha1\s*\(/g,
                /['"]md5['"]/gi,
                /['"]sha1['"]/gi
            ],
            'SEC007': [
                /fs\.\w+Sync\s*\(/g,
                /readFile\s*\(/g,
                /writeFile\s*\(/g,
                /path\.join\s*\(/g
            ]
        };
        
        return patternMap[code] || [
            /"[^"]{8,}"/g,  // Generic quoted strings
            /'[^']{8,}'/g,  // Generic single quoted strings
            /`[^`]{8,}`/g,  // Generic template literals
            /\w+\s*\([^)]*\)/g // Generic function calls
        ];
    }

    /**
     * Clears diagnostics for a specific document
     */
    clearDiagnostics(document: vscode.TextDocument) {
        this.diagnosticCollection.delete(document.uri);
        if (this.securityViewProvider) {
            this.securityViewProvider.clearSecurityIssues(document);
        }
    }

    /**
     * Clears all diagnostics across all documents
     */
    clearAll() {
        this.diagnosticCollection.clear();
        if (this.securityViewProvider) {
            this.securityViewProvider.clearAllSecurityIssues();
        }
    }

    /**
     * Links this provider with the security view for synchronized updates
     */
    setSecurityViewProvider(provider: any) {
        this.securityViewProvider = provider;
    }

    /**
     * Cleans up resources when the extension is deactivated
     */
    dispose() {
        this.diagnosticCollection.dispose();
        this.codeActionProvider.dispose();
    }
}

/**
 * Provides quick fix code actions for common security issues
 * Offers automatic remediation suggestions that users can apply with one click
 */
class SecurityCodeActionProvider implements vscode.CodeActionProvider {
    provideCodeActions(
        document: vscode.TextDocument,
        range: vscode.Range | vscode.Selection,
        context: vscode.CodeActionContext,
        token: vscode.CancellationToken
    ): vscode.ProviderResult<(vscode.Command | vscode.CodeAction)[]> {
        
        const actions: vscode.CodeAction[] = [];
        
        // Filter diagnostics from our extension (including AST-enhanced ones)
        const securityDiagnostics = context.diagnostics.filter(
            diagnostic => diagnostic.source === 'AI Security Reviewer' || 
                         diagnostic.source === 'AI Security Reviewer (AST-Enhanced)'
        );

        for (const diagnostic of securityDiagnostics) {
            const action = this.createQuickFix(document, diagnostic);
            if (action) {
                actions.push(action);
            }
        }

        return actions;
    }

    private createQuickFix(document: vscode.TextDocument, diagnostic: vscode.Diagnostic): vscode.CodeAction | undefined {
        const code = diagnostic.code as string;
        const range = diagnostic.range;
        const text = document.getText(range);

        let fix: vscode.CodeAction | undefined;

        switch (code) {
            case 'SEC001': // eval()
                fix = new vscode.CodeAction('Replace eval() with JSON.parse()', vscode.CodeActionKind.QuickFix);
                if (text.includes('eval(')) {
                    const newText = text.replace(/eval\s*\(\s*([^)]+)\s*\)/, 'JSON.parse($1)');
                    fix.edit = new vscode.WorkspaceEdit();
                    fix.edit.replace(document.uri, range, newText);
                }
                break;

            case 'SEC002': // innerHTML
                fix = new vscode.CodeAction('Replace innerHTML with textContent', vscode.CodeActionKind.QuickFix);
                if (text.includes('innerHTML')) {
                    const newText = text.replace(/innerHTML\s*=/, 'textContent =');
                    fix.edit = new vscode.WorkspaceEdit();
                    fix.edit.replace(document.uri, range, newText);
                }
                break;

            case 'SEC003': // document.write
                fix = new vscode.CodeAction('Add comment about document.write risks', vscode.CodeActionKind.QuickFix);
                fix.edit = new vscode.WorkspaceEdit();
                const lineStart = new vscode.Position(range.start.line, 0);
                fix.edit.insert(document.uri, lineStart, '// SECURITY: document.write is deprecated and potentially dangerous\n');
                break;

            case 'SEC006': // Math.random
                fix = new vscode.CodeAction('Replace Math.random() with crypto.getRandomValues()', vscode.CodeActionKind.QuickFix);
                if (text.includes('Math.random()')) {
                    const newText = text.replace(/Math\.random\s*\(\s*\)/, 'crypto.getRandomValues(new Uint32Array(1))[0] / 4294967295');
                    fix.edit = new vscode.WorkspaceEdit();
                    fix.edit.replace(document.uri, range, newText);
                }
                break;

            case 'SEC102': // Python eval
                fix = new vscode.CodeAction('Replace eval() with ast.literal_eval()', vscode.CodeActionKind.QuickFix);
                if (text.includes('eval(')) {
                    // Add import at the top of the file
                    const importEdit = new vscode.WorkspaceEdit();
                    importEdit.insert(document.uri, new vscode.Position(0, 0), 'import ast\n');
                    
                    const newText = text.replace(/eval\s*\(\s*([^)]+)\s*\)/, 'ast.literal_eval($1)');
                    fix.edit = new vscode.WorkspaceEdit();
                    fix.edit.replace(document.uri, range, newText);
                }
                break;

            case 'SEC103': // os.system
                fix = new vscode.CodeAction('Replace os.system() with subprocess.run()', vscode.CodeActionKind.QuickFix);
                if (text.includes('os.system(')) {
                    // Add import at the top of the file
                    const importEdit = new vscode.WorkspaceEdit();
                    importEdit.insert(document.uri, new vscode.Position(0, 0), 'import subprocess\n');
                    
                    const newText = text.replace(/os\.system\s*\(\s*([^)]+)\s*\)/, 'subprocess.run($1, shell=False)');
                    fix.edit = new vscode.WorkspaceEdit();
                    fix.edit.replace(document.uri, range, newText);
                }
                break;
        }

        if (fix) {
            fix.diagnostics = [diagnostic];
            fix.isPreferred = true;
        }

        return fix;
    }
}