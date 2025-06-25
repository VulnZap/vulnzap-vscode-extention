import * as vscode from 'vscode';
import { SecurityIssue } from './securityAnalyzer';
import { APIProviderManager } from './apiProviders';

export interface SecurityTreeItem {
    label: string;
    description?: string;
    tooltip?: string;
    iconPath?: vscode.ThemeIcon | { light: vscode.Uri; dark: vscode.Uri } | string;
    contextValue?: string;
    command?: vscode.Command;
    children?: SecurityTreeItem[];
    collapsibleState?: vscode.TreeItemCollapsibleState;
    resourceUri?: vscode.Uri;
    issue?: SecurityIssue;
    severity?: vscode.DiagnosticSeverity;
}

export class SecurityViewProvider implements vscode.TreeDataProvider<SecurityTreeItem> {
    private _onDidChangeTreeData: vscode.EventEmitter<SecurityTreeItem | undefined | null | void> = new vscode.EventEmitter<SecurityTreeItem | undefined | null | void>();
    readonly onDidChangeTreeData: vscode.Event<SecurityTreeItem | undefined | null | void> = this._onDidChangeTreeData.event;

    private securityIssues: Map<string, SecurityIssue[]> = new Map();
    private scanResults: Map<string, { timestamp: Date; issueCount: number; isEnabled: boolean }> = new Map();
    private apiProviderManager: APIProviderManager;

    constructor(private context: vscode.ExtensionContext) {
        this.apiProviderManager = new APIProviderManager();
    }

    refresh(): void {
        this._onDidChangeTreeData.fire();
    }

    getTreeItem(element: SecurityTreeItem): vscode.TreeItem {
        const treeItem = new vscode.TreeItem(element.label, element.collapsibleState);
        treeItem.description = element.description;
        treeItem.tooltip = element.tooltip;
        treeItem.iconPath = element.iconPath;
        treeItem.contextValue = element.contextValue;
        treeItem.command = element.command;
        treeItem.resourceUri = element.resourceUri;
        return treeItem;
    }

    getChildren(element?: SecurityTreeItem): Thenable<SecurityTreeItem[]> {
        if (!element) {
            // Root level items
            return Promise.resolve(this.getRootItems());
        } else if (element.children) {
            return Promise.resolve(element.children);
        } else if (element.contextValue === 'file') {
            // Get issues for a specific file
            const issues = this.securityIssues.get(element.resourceUri!.toString()) || [];
            return Promise.resolve(this.getIssueItems(issues, element.resourceUri!));
        } else if (element.contextValue === 'severityGroup') {
            // Get issues for a specific severity level
            const allIssues = Array.from(this.securityIssues.values()).flat();
            const filteredIssues = allIssues.filter(issue => issue.severity === element.severity);
            return Promise.resolve(this.getIssueItemsGrouped(filteredIssues));
        }
        return Promise.resolve([]);
    }

    private getRootItems(): SecurityTreeItem[] {
        const items: SecurityTreeItem[] = [];
        
        // Configuration Section
        items.push(this.getConfigurationSection());
        
        // Statistics Section
        items.push(this.getStatisticsSection());
        
        // Issues by Severity Section
        if (this.hasAnyIssues()) {
            items.push(this.getIssuesBySeveritySection());
        }
        
        // Issues by File Section
        if (this.hasAnyIssues()) {
            items.push(this.getIssuesByFileSection());
        }
        
        // Recent Scans Section
        items.push(this.getRecentScansSection());

        return items;
    }

    private getConfigurationSection(): SecurityTreeItem {
        const config = vscode.workspace.getConfiguration('vulnzap');
        const isEnabled = config.get<boolean>('enabled', true);
        const apiProvider = config.get<string>('apiProvider', 'gemini');
        const provider = this.apiProviderManager.getProvider(apiProvider);
        const isConfigured = provider?.isConfigured() || false;

        const configItems: SecurityTreeItem[] = [
            {
                label: `Status: ${isEnabled ? 'Enabled' : 'Disabled'}`,
                description: isEnabled ? '✓' : '⚠',
                iconPath: isEnabled ? new vscode.ThemeIcon('check') : new vscode.ThemeIcon('warning'),
                contextValue: 'status',
                command: {
                    command: 'vulnzap.toggle',
                    title: 'Toggle Security Scanning'
                }
            },
            {
                label: `AI Provider: ${provider?.displayName || 'Unknown'}`,
                description: isConfigured ? '✓ Configured' : '⚠ Not configured',
                iconPath: isConfigured ? new vscode.ThemeIcon('check') : new vscode.ThemeIcon('warning'),
                contextValue: 'provider',
                command: {
                    command: 'vulnzap.selectApiProvider',
                    title: 'Select AI Provider'
                }
            },
            {
                label: 'Configure API Keys',
                iconPath: new vscode.ThemeIcon('key'),
                contextValue: 'configure',
                command: {
                    command: 'vulnzap.configureApiKeys',
                    title: 'Configure API Keys'
                }
            }
        ];

        return {
            label: 'Configuration',
            iconPath: new vscode.ThemeIcon('gear'),
            collapsibleState: vscode.TreeItemCollapsibleState.Expanded,
            contextValue: 'configSection',
            children: configItems
        };
    }

    private getStatisticsSection(): SecurityTreeItem {
        const allIssues = Array.from(this.securityIssues.values()).flat();
        const criticalCount = allIssues.filter(i => i.severity === vscode.DiagnosticSeverity.Error).length;
        const warningCount = allIssues.filter(i => i.severity === vscode.DiagnosticSeverity.Warning).length;
        const infoCount = allIssues.filter(i => i.severity === vscode.DiagnosticSeverity.Information).length;
        const filesScanned = this.securityIssues.size;

        const statsItems: SecurityTreeItem[] = [
            {
                label: `Files Scanned: ${filesScanned}`,
                iconPath: new vscode.ThemeIcon('files'),
                contextValue: 'stat'
            },
            {
                label: `Critical Issues: ${criticalCount}`,
                iconPath: new vscode.ThemeIcon('error'),
                contextValue: 'stat'
            },
            {
                label: `Warnings: ${warningCount}`,
                iconPath: new vscode.ThemeIcon('warning'),
                contextValue: 'stat'
            },
            {
                label: `Information: ${infoCount}`,
                iconPath: new vscode.ThemeIcon('info'),
                contextValue: 'stat'
            }
        ];

        return {
            label: 'Security Overview',
            iconPath: new vscode.ThemeIcon('dashboard'),
            collapsibleState: vscode.TreeItemCollapsibleState.Expanded,
            contextValue: 'statsSection',
            children: statsItems
        };
    }

    private getIssuesBySeveritySection(): SecurityTreeItem {
        const allIssues = Array.from(this.securityIssues.values()).flat();
        const severityGroups: SecurityTreeItem[] = [];

        const criticalIssues = allIssues.filter(i => i.severity === vscode.DiagnosticSeverity.Error);
        const warningIssues = allIssues.filter(i => i.severity === vscode.DiagnosticSeverity.Warning);
        const infoIssues = allIssues.filter(i => i.severity === vscode.DiagnosticSeverity.Information);

        if (criticalIssues.length > 0) {
            severityGroups.push({
                label: `Critical (${criticalIssues.length})`,
                iconPath: new vscode.ThemeIcon('error'),
                collapsibleState: vscode.TreeItemCollapsibleState.Collapsed,
                contextValue: 'severityGroup',
                severity: vscode.DiagnosticSeverity.Error
            });
        }

        if (warningIssues.length > 0) {
            severityGroups.push({
                label: `Warnings (${warningIssues.length})`,
                iconPath: new vscode.ThemeIcon('warning'),
                collapsibleState: vscode.TreeItemCollapsibleState.Collapsed,
                contextValue: 'severityGroup',
                severity: vscode.DiagnosticSeverity.Warning
            });
        }

        if (infoIssues.length > 0) {
            severityGroups.push({
                label: `Information (${infoIssues.length})`,
                iconPath: new vscode.ThemeIcon('info'),
                collapsibleState: vscode.TreeItemCollapsibleState.Collapsed,
                contextValue: 'severityGroup',
                severity: vscode.DiagnosticSeverity.Information
            });
        }

        return {
            label: 'Issues by Severity',
            iconPath: new vscode.ThemeIcon('list-tree'),
            collapsibleState: vscode.TreeItemCollapsibleState.Collapsed,
            contextValue: 'severitySection',
            children: severityGroups
        };
    }

    private getIssuesByFileSection(): SecurityTreeItem {
        const fileItems: SecurityTreeItem[] = [];

        for (const [fileUri, issues] of this.securityIssues.entries()) {
            if (issues.length > 0) {
                const uri = vscode.Uri.parse(fileUri);
                const fileName = uri.path.split('/').pop() || 'Unknown';
                const criticalCount = issues.filter(i => i.severity === vscode.DiagnosticSeverity.Error).length;
                
                fileItems.push({
                    label: fileName,
                    description: `${issues.length} issue${issues.length === 1 ? '' : 's'}`,
                    tooltip: `${uri.path}\n${issues.length} security issues found`,
                    iconPath: criticalCount > 0 ? new vscode.ThemeIcon('error') : new vscode.ThemeIcon('warning'),
                    collapsibleState: vscode.TreeItemCollapsibleState.Collapsed,
                    contextValue: 'file',
                    resourceUri: uri
                });
            }
        }

        return {
            label: 'Issues by File',
            iconPath: new vscode.ThemeIcon('file-directory'),
            collapsibleState: vscode.TreeItemCollapsibleState.Collapsed,
            contextValue: 'fileSection',
            children: fileItems
        };
    }

    private getRecentScansSection(): SecurityTreeItem {
        const recentItems: SecurityTreeItem[] = [];
        
        // Sort by timestamp, most recent first
        const sortedScans = Array.from(this.scanResults.entries())
            .sort(([,a], [,b]) => b.timestamp.getTime() - a.timestamp.getTime())
            .slice(0, 5); // Show last 5 scans

        for (const [fileUri, result] of sortedScans) {
            const uri = vscode.Uri.parse(fileUri);
            const fileName = uri.path.split('/').pop() || 'Unknown';
            const timeAgo = this.getTimeAgo(result.timestamp);
            
            recentItems.push({
                label: fileName,
                description: `${result.issueCount} issues • ${timeAgo}`,
                tooltip: `Scanned ${result.timestamp.toLocaleString()}\nFound ${result.issueCount} issues`,
                iconPath: result.issueCount > 0 ? new vscode.ThemeIcon('warning') : new vscode.ThemeIcon('check'),
                contextValue: 'recentScan',
                resourceUri: uri,
                command: {
                    command: 'vscode.open',
                    title: 'Open File',
                    arguments: [uri]
                }
            });
        }

        if (recentItems.length === 0) {
            recentItems.push({
                label: 'No recent scans',
                iconPath: new vscode.ThemeIcon('info'),
                contextValue: 'noScans'
            });
        }

        return {
            label: 'Recent Scans',
            iconPath: new vscode.ThemeIcon('history'),
            collapsibleState: vscode.TreeItemCollapsibleState.Collapsed,
            contextValue: 'recentSection',
            children: recentItems
        };
    }

    private getIssueItems(issues: SecurityIssue[], fileUri: vscode.Uri): SecurityTreeItem[] {
        return issues.map(issue => ({
            label: issue.message,
            description: `Line ${issue.line + 1}`,
            tooltip: `${issue.message}\n\nLine: ${issue.line + 1}\nSeverity: ${this.getSeverityLabel(issue.severity)}\nConfidence: ${issue.confidence || 'N/A'}%${issue.suggestion ? '\n\nSuggestion: ' + issue.suggestion : ''}`,
            iconPath: this.getSeverityIcon(issue.severity),
            contextValue: 'issue',
            issue: issue,
            command: {
                command: 'vscode.open',
                title: 'Go to Issue',
                arguments: [
                    fileUri,
                    {
                        selection: new vscode.Range(
                            new vscode.Position(issue.line, issue.column),
                            new vscode.Position(issue.endLine, issue.endColumn)
                        )
                    }
                ]
            }
        }));
    }

    private getIssueItemsGrouped(issues: SecurityIssue[]): SecurityTreeItem[] {
        // Group issues by file
        const issuesByFile = new Map<string, SecurityIssue[]>();
        
        for (const issue of issues) {
            // We need to find which file this issue belongs to
            for (const [fileUri, fileIssues] of this.securityIssues.entries()) {
                if (fileIssues.includes(issue)) {
                    if (!issuesByFile.has(fileUri)) {
                        issuesByFile.set(fileUri, []);
                    }
                    issuesByFile.get(fileUri)!.push(issue);
                    break;
                }
            }
        }

        const fileItems: SecurityTreeItem[] = [];
        for (const [fileUri, fileIssues] of issuesByFile.entries()) {
            const uri = vscode.Uri.parse(fileUri);
            const fileName = uri.path.split('/').pop() || 'Unknown';
            
            fileItems.push({
                label: fileName,
                description: `${fileIssues.length} issue${fileIssues.length === 1 ? '' : 's'}`,
                iconPath: new vscode.ThemeIcon('file'),
                collapsibleState: vscode.TreeItemCollapsibleState.Collapsed,
                contextValue: 'file',
                resourceUri: uri,
                children: this.getIssueItems(fileIssues, uri)
            });
        }

        return fileItems;
    }

    private getSeverityIcon(severity: vscode.DiagnosticSeverity): vscode.ThemeIcon {
        switch (severity) {
            case vscode.DiagnosticSeverity.Error:
                return new vscode.ThemeIcon('error');
            case vscode.DiagnosticSeverity.Warning:
                return new vscode.ThemeIcon('warning');
            case vscode.DiagnosticSeverity.Information:
                return new vscode.ThemeIcon('info');
            default:
                return new vscode.ThemeIcon('circle-outline');
        }
    }

    private getSeverityLabel(severity: vscode.DiagnosticSeverity): string {
        switch (severity) {
            case vscode.DiagnosticSeverity.Error:
                return 'Critical';
            case vscode.DiagnosticSeverity.Warning:
                return 'Warning';
            case vscode.DiagnosticSeverity.Information:
                return 'Information';
            default:
                return 'Unknown';
        }
    }

    private hasAnyIssues(): boolean {
        return Array.from(this.securityIssues.values()).some(issues => issues.length > 0);
    }

    private getTimeAgo(date: Date): string {
        const now = new Date();
        const diff = now.getTime() - date.getTime();
        const minutes = Math.floor(diff / 60000);
        const hours = Math.floor(minutes / 60);
        const days = Math.floor(hours / 24);

        if (days > 0) {
            return `${days}d ago`;
        } else if (hours > 0) {
            return `${hours}h ago`;
        } else if (minutes > 0) {
            return `${minutes}m ago`;
        } else {
            return 'Just now';
        }
    }

    // Public methods to update the tree view
    updateSecurityIssues(document: vscode.TextDocument, issues: SecurityIssue[]): void {
        this.securityIssues.set(document.uri.toString(), issues);
        this.scanResults.set(document.uri.toString(), {
            timestamp: new Date(),
            issueCount: issues.length,
            isEnabled: vscode.workspace.getConfiguration('vulnzap').get('enabled', true)
        });
        this.refresh();
    }

    clearSecurityIssues(document: vscode.TextDocument): void {
        this.securityIssues.delete(document.uri.toString());
        this.scanResults.delete(document.uri.toString());
        this.refresh();
    }

    clearAllSecurityIssues(): void {
        this.securityIssues.clear();
        this.scanResults.clear();
        this.refresh();
    }
} 