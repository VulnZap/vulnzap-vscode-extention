import * as vscode from 'vscode';
import { SecurityIssue } from './securityAnalyzer';

export class DiagnosticProvider implements vscode.Disposable {
    private diagnosticCollection: vscode.DiagnosticCollection;
    private codeActionProvider: vscode.Disposable;
    private securityViewProvider?: any; // Will be set by extension.ts

    constructor(context: vscode.ExtensionContext) {
        this.diagnosticCollection = vscode.languages.createDiagnosticCollection('security-reviewer');
        
        // Register code action provider for quick fixes
        this.codeActionProvider = vscode.languages.registerCodeActionsProvider(
            ['javascript', 'typescript', 'python', 'java'],
            new SecurityCodeActionProvider(),
            {
                providedCodeActionKinds: [vscode.CodeActionKind.QuickFix]
            }
        );

        context.subscriptions.push(this.diagnosticCollection, this.codeActionProvider);
    }

    updateDiagnostics(document: vscode.TextDocument, issues: SecurityIssue[]) {
        const diagnostics: vscode.Diagnostic[] = issues.map(issue => {
            const range = new vscode.Range(
                new vscode.Position(issue.line, issue.column),
                new vscode.Position(issue.endLine, issue.endColumn)
            );

            // Enhanced message with confidence and CVE information
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
            
            // Add related information for suggestions, CVEs, and search results
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

            return diagnostic;
        });

        this.diagnosticCollection.set(document.uri, diagnostics);
    }

    clearDiagnostics(document: vscode.TextDocument) {
        this.diagnosticCollection.delete(document.uri);
        if (this.securityViewProvider) {
            this.securityViewProvider.clearSecurityIssues(document);
        }
    }

    clearAll() {
        this.diagnosticCollection.clear();
        if (this.securityViewProvider) {
            this.securityViewProvider.clearAllSecurityIssues();
        }
    }

    setSecurityViewProvider(provider: any) {
        this.securityViewProvider = provider;
    }

    dispose() {
        this.diagnosticCollection.dispose();
        this.codeActionProvider.dispose();
    }
}

class SecurityCodeActionProvider implements vscode.CodeActionProvider {
    provideCodeActions(
        document: vscode.TextDocument,
        range: vscode.Range | vscode.Selection,
        context: vscode.CodeActionContext,
        token: vscode.CancellationToken
    ): vscode.ProviderResult<(vscode.Command | vscode.CodeAction)[]> {
        
        const actions: vscode.CodeAction[] = [];
        
        // Filter diagnostics from our extension
        const securityDiagnostics = context.diagnostics.filter(
            diagnostic => diagnostic.source === 'AI Security Reviewer'
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