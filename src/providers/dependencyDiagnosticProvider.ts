import * as vscode from 'vscode';
import { VulnerabilityInfo, DependencyScanResult } from '../dependencies/dependencyCache';
import { Dependency } from '../dependencies/dependencyParser';

interface DependencyQuickFix {
    title: string;
    command: string;
    arguments?: any[];
    kind: vscode.CodeActionKind;
}

/**
 * Handles VS Code diagnostic integration for dependency vulnerabilities
 * Shows inline warnings for high severity vulnerabilities with quick fix options
 */
export class DependencyDiagnosticProvider implements vscode.Disposable {
    private diagnosticCollection: vscode.DiagnosticCollection;
    private codeActionProvider: vscode.Disposable;
    private securityViewProvider?: any; // Will be set by extension.ts
    private vulnerabilityData: Map<string, VulnerabilityInfo[]> = new Map();
    private dependencyData: Map<string, Dependency[]> = new Map();

    constructor(context: vscode.ExtensionContext) {
        // Create a diagnostic collection for dependency vulnerabilities
        this.diagnosticCollection = vscode.languages.createDiagnosticCollection('dependency-vulnerabilities');
        
        // Register quick fix provider for dependency updates
        this.codeActionProvider = vscode.languages.registerCodeActionsProvider(
            ['json'], // Focus on package.json files
            new DependencyCodeActionProvider(this),
            {
                providedCodeActionKinds: [vscode.CodeActionKind.QuickFix]
            }
        );

        context.subscriptions.push(this.diagnosticCollection, this.codeActionProvider);
    }

    /**
     * Updates VS Code diagnostics with high severity dependency vulnerabilities
     */
    updateDependencyDiagnostics(scanResult: DependencyScanResult, projectPath: string) {
        // Filter for high severity vulnerabilities only
        const highSeverityVulns = scanResult.vulnerabilities.filter(
            vuln => vuln.severity === 'high' || vuln.severity === 'critical'
        );

        this.vulnerabilityData.set(projectPath, highSeverityVulns);
        this.dependencyData.set(projectPath, scanResult.dependencies);

        // Find package.json files in the workspace to show inline diagnostics
        this.updatePackageJsonDiagnostics(highSeverityVulns, projectPath);

        // Update security view if available
        if (this.securityViewProvider) {
            this.securityViewProvider.updateDependencyVulnerabilities(scanResult);
        }
    }

    /**
     * Updates diagnostics for package.json files to show inline vulnerability warnings
     */
    private async updatePackageJsonDiagnostics(vulnerabilities: VulnerabilityInfo[], projectPath: string) {
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (!workspaceFolders) return;

        for (const folder of workspaceFolders) {
            const packageJsonUri = vscode.Uri.file(`${folder.uri.fsPath}/package.json`);
            
            try {
                const document = await vscode.workspace.openTextDocument(packageJsonUri);
                const diagnostics = this.createDiagnosticsForDocument(document, vulnerabilities);
                this.diagnosticCollection.set(packageJsonUri, diagnostics);
            } catch (error) {
                // package.json might not exist, which is fine
                console.log(`No package.json found at ${packageJsonUri.fsPath}`);
            }
        }
    }

    /**
     * Creates diagnostic objects for vulnerable dependencies in a package.json file
     */
    private createDiagnosticsForDocument(document: vscode.TextDocument, vulnerabilities: VulnerabilityInfo[]): vscode.Diagnostic[] {
        const diagnostics: vscode.Diagnostic[] = [];
        const text = document.getText();

        for (const vuln of vulnerabilities) {
            // Find the line containing this package in package.json
            const packageRegex = new RegExp(`"${vuln.packageName}"\\s*:\\s*"([^"]*)"`, 'g');
            const lines = text.split('\n');

            for (let i = 0; i < lines.length; i++) {
                const line = lines[i];
                const match = packageRegex.exec(line);
                if (match) {
                    const startIndex = line.indexOf(`"${vuln.packageName}"`);
                    const endIndex = startIndex + `"${vuln.packageName}"`.length;
                    
                    const range = new vscode.Range(
                        new vscode.Position(i, startIndex),
                        new vscode.Position(i, line.length)
                    );

                    const severity = vuln.severity === 'critical' 
                        ? vscode.DiagnosticSeverity.Error 
                        : vscode.DiagnosticSeverity.Warning;

                    const message = `${vuln.severity.toUpperCase()} vulnerability in ${vuln.packageName}@${vuln.packageVersion}: ${vuln.description}`;

                    const diagnostic = new vscode.Diagnostic(range, message, severity);
                    diagnostic.code = `VULN-${vuln.severity.toUpperCase()}`;
                    diagnostic.source = 'VulnZap Dependency Scanner';

                    // Add related information
                    const relatedInfo: vscode.DiagnosticRelatedInformation[] = [];
                    
                    if (vuln.fixedIn) {
                        relatedInfo.push(new vscode.DiagnosticRelatedInformation(
                            new vscode.Location(document.uri, range),
                            `💡 Fixed in version: ${vuln.fixedIn}`
                        ));
                    }

                    if (vuln.cveId) {
                        relatedInfo.push(new vscode.DiagnosticRelatedInformation(
                            new vscode.Location(document.uri, range),
                            `🔍 CVE: ${vuln.cveId}`
                        ));
                    }

                    relatedInfo.push(new vscode.DiagnosticRelatedInformation(
                        new vscode.Location(document.uri, range),
                        `📋 Recommendation: ${vuln.recommendation}`
                    ));

                    if (relatedInfo.length > 0) {
                        diagnostic.relatedInformation = relatedInfo;
                    }

                    diagnostics.push(diagnostic);
                    break; // Found the package, move to next vulnerability
                }
            }
        }

        return diagnostics;
    }

    /**
     * Gets quick fix options for a specific vulnerability
     */
    getQuickFixesForVulnerability(vuln: VulnerabilityInfo, document: vscode.TextDocument): DependencyQuickFix[] {
        const fixes: DependencyQuickFix[] = [];

        if (vuln.fixedIn) {
            // If there's a patched version, offer to update to it
            fixes.push({
                title: `Update ${vuln.packageName} to ${vuln.fixedIn} (patched version)`,
                command: 'vulnzap.updateDependencyToVersion',
                arguments: [document.uri, vuln.packageName, vuln.fixedIn],
                kind: vscode.CodeActionKind.QuickFix
            });
        } else {
            // If no specific patch, suggest updating to latest
            fixes.push({
                title: `Update ${vuln.packageName} to latest version`,
                command: 'vulnzap.showUpdateCommand',
                arguments: [vuln.packageName],
                kind: vscode.CodeActionKind.QuickFix
            });
        }

        return fixes;
    }

    /**
     * Gets all vulnerabilities for a project
     */
    getVulnerabilitiesForProject(projectPath: string): VulnerabilityInfo[] {
        return this.vulnerabilityData.get(projectPath) || [];
    }

    /**
     * Gets all dependencies for a project
     */
    getDependenciesForProject(projectPath: string): Dependency[] {
        return this.dependencyData.get(projectPath) || [];
    }

    /**
     * Clears diagnostics for a specific project
     */
    clearDiagnosticsForProject(projectPath: string) {
        this.vulnerabilityData.delete(projectPath);
        this.dependencyData.delete(projectPath);
        
        // Clear diagnostics for package.json files
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (workspaceFolders) {
            for (const folder of workspaceFolders) {
                const packageJsonUri = vscode.Uri.file(`${folder.uri.fsPath}/package.json`);
                this.diagnosticCollection.delete(packageJsonUri);
            }
        }
    }

    /**
     * Clears all dependency diagnostics
     */
    clearAll() {
        this.diagnosticCollection.clear();
        this.vulnerabilityData.clear();
        this.dependencyData.clear();
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
 * Provides quick fix code actions for dependency vulnerabilities
 */
class DependencyCodeActionProvider implements vscode.CodeActionProvider {
    constructor(private dependencyDiagnosticProvider: DependencyDiagnosticProvider) {}

    provideCodeActions(
        document: vscode.TextDocument,
        range: vscode.Range | vscode.Selection,
        context: vscode.CodeActionContext,
        token: vscode.CancellationToken
    ): vscode.ProviderResult<(vscode.Command | vscode.CodeAction)[]> {
        
        const actions: vscode.CodeAction[] = [];
        
        // Filter diagnostics from our dependency scanner
        const dependencyDiagnostics = context.diagnostics.filter(
            diagnostic => diagnostic.source === 'VulnZap Dependency Scanner'
        );

        for (const diagnostic of dependencyDiagnostics) {
            // Extract package name from diagnostic message
            const packageMatch = diagnostic.message.match(/vulnerability in ([^@]+)@/);
            if (packageMatch) {
                const packageName = packageMatch[1];
                
                // Get vulnerabilities for current workspace
                const workspaceFolders = vscode.workspace.workspaceFolders;
                if (workspaceFolders) {
                    const projectPath = workspaceFolders[0].uri.fsPath;
                    const vulnerabilities = this.dependencyDiagnosticProvider.getVulnerabilitiesForProject(projectPath);
                    
                    const vuln = vulnerabilities.find(v => v.packageName === packageName);
                    if (vuln) {
                        const quickFixes = this.dependencyDiagnosticProvider.getQuickFixesForVulnerability(vuln, document);
                        
                        for (const fix of quickFixes) {
                            const action = new vscode.CodeAction(fix.title, fix.kind);
                            action.command = {
                                command: fix.command,
                                title: fix.title,
                                arguments: fix.arguments
                            };
                            actions.push(action);
                        }
                    }
                }
            }
        }

        return actions;
    }
} 