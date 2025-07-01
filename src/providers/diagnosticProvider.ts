import * as vscode from 'vscode';
import { Logger } from '../utils/logger';

// Simple security issue interface for compatibility
interface SecurityIssue {
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
    relatedCode?: any[];
    similarVulnerabilities?: any[];
}

/**
 * Manages diagnostic information for security vulnerabilities in VS Code
 * Provides real-time feedback through squiggly underlines and Problems panel
 */
export class DiagnosticProvider {
    private diagnosticCollection: vscode.DiagnosticCollection;
    private context: vscode.ExtensionContext;
    private securityViewProvider?: any;

    constructor(context: vscode.ExtensionContext) {
        this.context = context;
        this.diagnosticCollection = vscode.languages.createDiagnosticCollection('vulnzap-security');
    }

    /**
     * Links this provider with the security view for synchronized updates
     */
    setSecurityViewProvider(provider: any): void {
        this.securityViewProvider = provider;
    }

    /**
     * Updates diagnostics for a specific document
     */
    updateDiagnostics(document: vscode.TextDocument, issues: SecurityIssue[]): void {
        Logger.debug(`Updating diagnostics for ${document.uri.fsPath} with ${issues.length} issues`);
        
        const diagnostics: vscode.Diagnostic[] = issues.map(issue => {
            const range = new vscode.Range(
                new vscode.Position(Math.max(0, issue.line), Math.max(0, issue.column)),
                new vscode.Position(Math.max(0, issue.endLine), Math.max(0, issue.endColumn))
            );

            const diagnostic = new vscode.Diagnostic(range, issue.message, issue.severity);
            diagnostic.code = issue.code;
            diagnostic.source = 'VulnZap';
            
            // Add additional information for hover tooltips
            if (issue.suggestion) {
                diagnostic.relatedInformation = [
                    new vscode.DiagnosticRelatedInformation(
                        new vscode.Location(document.uri, range),
                        `Suggestion: ${issue.suggestion}`
                    )
                ];
            }

            return diagnostic;
        });

        this.diagnosticCollection.set(document.uri, diagnostics);
        Logger.debug(`Set ${diagnostics.length} diagnostics for ${document.uri.fsPath}`);
    }

    /**
     * Clears diagnostics for a specific document
     */
    clearDiagnostics(document: vscode.TextDocument): void {
        this.diagnosticCollection.set(document.uri, []);
    }

    /**
     * Clears all diagnostics
     */
    clearAll(): void {
        this.diagnosticCollection.clear();
    }

    /**
     * Gets current diagnostics for a document
     */
    getDiagnostics(document: vscode.TextDocument): readonly vscode.Diagnostic[] {
        return this.diagnosticCollection.get(document.uri) || [];
    }

    /**
     * Disposes of the diagnostic provider
     */
    dispose(): void {
        this.diagnosticCollection.dispose();
    }
}