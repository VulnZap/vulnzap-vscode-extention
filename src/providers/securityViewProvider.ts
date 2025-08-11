import * as vscode from "vscode";
// Simple interface for compatibility with diagnostic provider
interface SecurityIssue {
  line: number;
  column: number;
  endLine: number;
  endColumn: number;
  message: string;
  severity: any;
  code: string;
  suggestion?: string;
  confidence?: number;
  cve?: string[];
  searchResults?: string[];
  relatedCode?: any[];
  similarVulnerabilities?: any[];
}
import { APIProviderManager } from "./apiProviders";
import {
  VulnerabilityInfo,
  DependencyScanResult,
} from "../dependencies/dependencyCache";

export interface SecurityTreeItem {
  label: string;
  description?: string;
  tooltip?: string;
  iconPath?:
    | vscode.ThemeIcon
    | { light: vscode.Uri; dark: vscode.Uri }
    | string;
  contextValue?: string;
  command?: vscode.Command;
  children?: SecurityTreeItem[];
  collapsibleState?: vscode.TreeItemCollapsibleState;
  resourceUri?: vscode.Uri;
  issue?: SecurityIssue;
  severity?: vscode.DiagnosticSeverity;
  vulnerability?: VulnerabilityInfo;
  dependencyScanResult?: DependencyScanResult;
}

export class SecurityViewProvider
  implements vscode.TreeDataProvider<SecurityTreeItem>
{
  private _onDidChangeTreeData: vscode.EventEmitter<
    SecurityTreeItem | undefined | null | void
  > = new vscode.EventEmitter<SecurityTreeItem | undefined | null | void>();
  readonly onDidChangeTreeData: vscode.Event<
    SecurityTreeItem | undefined | null | void
  > = this._onDidChangeTreeData.event;

  private securityIssues: Map<string, SecurityIssue[]> = new Map();
  private dependencyVulnerabilities: Map<string, DependencyScanResult> =
    new Map();
  private scanResults: Map<
    string,
    { timestamp: Date; issueCount: number; isEnabled: boolean }
  > = new Map();
  private loadingFiles: Set<string> = new Set(); // Track files currently being scanned
  private apiProviderManager: APIProviderManager;

  constructor(private context: vscode.ExtensionContext) {
    this.apiProviderManager = new APIProviderManager();
  }

  refresh(): void {
    this._onDidChangeTreeData.fire();
  }

  getTreeItem(element: SecurityTreeItem): vscode.TreeItem {
    const treeItem = new vscode.TreeItem(
      element.label,
      element.collapsibleState
    );
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
    } else if (element.contextValue === "file") {
      // Get issues for a specific file
      const issues =
        this.securityIssues.get(element.resourceUri!.toString()) || [];
      return Promise.resolve(this.getIssueItems(issues, element.resourceUri!));
    } else if (element.contextValue === "severityGroup") {
      // Get issues for a specific severity level
      const allIssues = Array.from(this.securityIssues.values()).flat();
      const filteredIssues = allIssues.filter(
        (issue) => issue.severity === element.severity
      );
      return Promise.resolve(this.getIssueItemsGrouped(filteredIssues));
    } else if (element.contextValue === "dependencySeverityGroup") {
      // Return vulnerabilities for this severity group
      return Promise.resolve(element.children || []);
    }
    return Promise.resolve([]);
  }

  private getRootItems(): SecurityTreeItem[] {
    const items: SecurityTreeItem[] = [];

    // Check if user is logged in
    const session = this.context.globalState.get("vulnzapSession");

    if (!session) {
      // User is not logged in - show only login interface
      items.push(this.getLoginOnlySection());
    } else {
      // User is logged in - show full interface
      // Configuration Section
      items.push(this.getConfigurationSection());

      // Statistics Section
      items.push(this.getStatisticsSection());

      // Dependency Vulnerabilities Section
      if (this.hasDependencyVulnerabilities()) {
        items.push(this.getDependencyVulnerabilitiesSection());
      }

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
    }

    return items;
  }

  private getLoginOnlySection(): SecurityTreeItem {
    return {
      label: "Welcome!",
      iconPath: new vscode.ThemeIcon("robot"),
      collapsibleState: vscode.TreeItemCollapsibleState.Expanded,
      contextValue: "loginOnlySection",
      children: [
        {
          label: "Please sign in below.",
          iconPath: new vscode.ThemeIcon("info"),
          contextValue: "loginPrompt",
          tooltip: "Authentication required to access VulnZap features",
        },
        {
          label: "Sign In",
          description: "🔑 Click to authenticate",
          iconPath: new vscode.ThemeIcon(
            "account",
            new vscode.ThemeColor("button.background")
          ),
          contextValue: "loginButton",
          command: {
            command: "vulnzap.login",
            title: "Sign In",
          },
          tooltip: "Sign in with your VulnZap account",
        },
        {
          label: "Augment Features:",
          iconPath: new vscode.ThemeIcon("star-full"),
          collapsibleState: vscode.TreeItemCollapsibleState.Expanded,
          contextValue: "featuresList",
          children: [
            {
              label: "• AI-Powered Security Analysis",
              iconPath: new vscode.ThemeIcon("shield"),
              contextValue: "feature",
              tooltip:
                "Advanced vulnerability detection using artificial intelligence",
            },
            {
              label: "• Real-time Code Scanning",
              iconPath: new vscode.ThemeIcon("search"),
              contextValue: "feature",
              tooltip: "Continuous security monitoring as you code",
            },
            {
              label: "• Dependency Vulnerability Checks",
              iconPath: new vscode.ThemeIcon("package"),
              contextValue: "feature",
              tooltip: "Automated scanning of third-party dependencies",
            },
            {
              label: "• Smart Remediation Suggestions",
              iconPath: new vscode.ThemeIcon("lightbulb"),
              contextValue: "feature",
              tooltip: "Intelligent fixes and security improvements",
            },
          ],
        },
        {
          label: "Need an account?",
          description: "Create one at vulnzap.com",
          iconPath: new vscode.ThemeIcon("link-external"),
          contextValue: "signupPrompt",
          command: {
            command: "vscode.open",
            title: "Open VulnZap Website",
            arguments: [vscode.Uri.parse("https://vulnzap.com")],
          },
          tooltip: "Visit vulnzap.com to create a new account",
        },
      ],
    };
  }

  private getConfigurationSection(): SecurityTreeItem {
    const config = vscode.workspace.getConfiguration("vulnzap");
    const isEnabled = config.get<boolean>("enabled", true);
    const provider = this.apiProviderManager.getCurrentProvider();
    const isConfigured = provider.isConfigured();

    // Check for session in global state
    const session = this.context.globalState.get("vulnzapSession");
    const configItems: SecurityTreeItem[] = [];

    // Add login/logout button based on session state
    if (!session) {
      configItems.push({
        label: "Log In to VulnZap",
        iconPath: new vscode.ThemeIcon("sign-in"),
        contextValue: "login",
        command: {
          command: "vulnzap.login",
          title: "Log In to VulnZap",
        },
      });
    } else {
      configItems.push({
        label: "Sign Out of VulnZap",
        description: "Currently signed in",
        iconPath: new vscode.ThemeIcon("sign-out"),
        contextValue: "logout",
        command: {
          command: "vulnzap.logout",
          title: "Sign Out of VulnZap",
        },
        tooltip: "Sign out of your VulnZap account",
      });
    }

    configItems.push(
      {
        label: `Status: ${isEnabled ? "Enabled" : "Disabled"}`,
        description: isEnabled ? "\u2713" : "\u26a0",
        iconPath: isEnabled
          ? new vscode.ThemeIcon("check")
          : new vscode.ThemeIcon("warning"),
        contextValue: "status",
        command: {
          command: "vulnzap.toggle",
          title: "Toggle Security Scanning",
        },
      },
      {
        label: `VulnZap API: ${isConfigured ? "Configured" : "Not Configured"}`,
        description: isConfigured ? "\u2713 Ready" : "\u26a0 Configure API",
        iconPath: isConfigured
          ? new vscode.ThemeIcon("check")
          : new vscode.ThemeIcon("warning"),
        contextValue: "provider",
        command: {
          command: "vulnzap.configureApiKeys",
          title: "Configure VulnZap API",
        },
      }
    );

    return {
      label: "Configuration",
      iconPath: new vscode.ThemeIcon("gear"),
      collapsibleState: vscode.TreeItemCollapsibleState.Expanded,
      contextValue: "configSection",
      children: configItems,
    };
  }

  private getStatisticsSection(): SecurityTreeItem {
    const allIssues = Array.from(this.securityIssues.values()).flat();
    const criticalCount = allIssues.filter(
      (i) => i.severity === vscode.DiagnosticSeverity.Error
    ).length;
    const warningCount = allIssues.filter(
      (i) => i.severity === vscode.DiagnosticSeverity.Warning
    ).length;
    const infoCount = allIssues.filter(
      (i) => i.severity === vscode.DiagnosticSeverity.Information
    ).length;
    const filesScanned = this.securityIssues.size;

    const statsItems: SecurityTreeItem[] = [
      {
        label: `Files Scanned: ${filesScanned}`,
        iconPath: new vscode.ThemeIcon("files"),
        contextValue: "stat",
      },
      {
        label: `Critical Issues: ${criticalCount}`,
        iconPath: new vscode.ThemeIcon("error"),
        contextValue: "stat",
      },
      {
        label: `Warnings: ${warningCount}`,
        iconPath: new vscode.ThemeIcon("warning"),
        contextValue: "stat",
      },
      {
        label: `Information: ${infoCount}`,
        iconPath: new vscode.ThemeIcon("info"),
        contextValue: "stat",
      },
    ];

    return {
      label: "Security Overview",
      iconPath: new vscode.ThemeIcon("dashboard"),
      collapsibleState: vscode.TreeItemCollapsibleState.Expanded,
      contextValue: "statsSection",
      children: statsItems,
    };
  }

  private getIssuesBySeveritySection(): SecurityTreeItem {
    const allIssues = Array.from(this.securityIssues.values()).flat();
    const severityGroups: SecurityTreeItem[] = [];

    const criticalIssues = allIssues.filter(
      (i) => i.severity === vscode.DiagnosticSeverity.Error
    );
    const warningIssues = allIssues.filter(
      (i) => i.severity === vscode.DiagnosticSeverity.Warning
    );
    const infoIssues = allIssues.filter(
      (i) => i.severity === vscode.DiagnosticSeverity.Information
    );

    if (criticalIssues.length > 0) {
      severityGroups.push({
        label: `Critical (${criticalIssues.length})`,
        iconPath: new vscode.ThemeIcon("error"),
        collapsibleState: vscode.TreeItemCollapsibleState.Collapsed,
        contextValue: "severityGroup",
        severity: vscode.DiagnosticSeverity.Error,
      });
    }

    if (warningIssues.length > 0) {
      severityGroups.push({
        label: `Warnings (${warningIssues.length})`,
        iconPath: new vscode.ThemeIcon("warning"),
        collapsibleState: vscode.TreeItemCollapsibleState.Collapsed,
        contextValue: "severityGroup",
        severity: vscode.DiagnosticSeverity.Warning,
      });
    }

    if (infoIssues.length > 0) {
      severityGroups.push({
        label: `Information (${infoIssues.length})`,
        iconPath: new vscode.ThemeIcon("info"),
        collapsibleState: vscode.TreeItemCollapsibleState.Collapsed,
        contextValue: "severityGroup",
        severity: vscode.DiagnosticSeverity.Information,
      });
    }

    return {
      label: "Issues by Severity",
      iconPath: new vscode.ThemeIcon("list-tree"),
      collapsibleState: vscode.TreeItemCollapsibleState.Collapsed,
      contextValue: "severitySection",
      children: severityGroups,
    };
  }

  private getIssuesByFileSection(): SecurityTreeItem {
    const fileItems: SecurityTreeItem[] = [];

    for (const [fileUri, issues] of this.securityIssues.entries()) {
      if (issues.length > 0) {
        const uri = vscode.Uri.parse(fileUri);
        const fileName = uri.path.split("/").pop() || "Unknown";
        const criticalCount = issues.filter(
          (i) => i.severity === vscode.DiagnosticSeverity.Error
        ).length;

        fileItems.push({
          label: fileName,
          description: `${issues.length} issue${
            issues.length === 1 ? "" : "s"
          }`,
          tooltip: `${uri.path}\n${issues.length} security issues found`,
          iconPath:
            criticalCount > 0
              ? new vscode.ThemeIcon("error")
              : new vscode.ThemeIcon("warning"),
          collapsibleState: vscode.TreeItemCollapsibleState.Collapsed,
          contextValue: "file",
          resourceUri: uri,
        });
      }
    }

    return {
      label: "Issues by File",
      iconPath: new vscode.ThemeIcon("file-directory"),
      collapsibleState: vscode.TreeItemCollapsibleState.Collapsed,
      contextValue: "fileSection",
      children: fileItems,
    };
  }

  private getRecentScansSection(): SecurityTreeItem {
    const recentItems: SecurityTreeItem[] = [];

    // First, add currently loading files
    for (const fileUri of this.loadingFiles) {
      const uri = vscode.Uri.parse(fileUri);
      const fileName = uri.path.split("/").pop() || "Unknown";

      recentItems.push({
        label: fileName,
        description: "Scanning...",
        tooltip: "Security scan in progress",
        iconPath: new vscode.ThemeIcon("loading~spin"),
        contextValue: "loadingScan",
        resourceUri: uri,
        command: {
          command: "vscode.open",
          title: "Open File",
          arguments: [uri],
        },
      });
    }

    // Then, add recent completed scans (exclude currently loading files)
    const sortedScans = Array.from(this.scanResults.entries())
      .filter(([fileUri]) => !this.loadingFiles.has(fileUri)) // Exclude loading files
      .sort(([, a], [, b]) => b.timestamp.getTime() - a.timestamp.getTime())
      .slice(0, 5 - recentItems.length); // Adjust slice to account for loading items

    for (const [fileUri, result] of sortedScans) {
      const uri = vscode.Uri.parse(fileUri);
      const fileName = uri.path.split("/").pop() || "Unknown";
      const timeAgo = this.getTimeAgo(result.timestamp);

      recentItems.push({
        label: fileName,
        description: `${result.issueCount} issues • ${timeAgo}`,
        tooltip: `Scanned ${result.timestamp.toLocaleString()}\nFound ${
          result.issueCount
        } issues`,
        iconPath:
          result.issueCount > 0
            ? new vscode.ThemeIcon("warning")
            : new vscode.ThemeIcon("check"),
        contextValue: "recentScan",
        resourceUri: uri,
        command: {
          command: "vscode.open",
          title: "Open File",
          arguments: [uri],
        },
      });
    }

    if (recentItems.length === 0) {
      recentItems.push({
        label: "No recent scans",
        iconPath: new vscode.ThemeIcon("info"),
        contextValue: "noScans",
      });
    }

    return {
      label: "Recent Scans",
      iconPath: new vscode.ThemeIcon("history"),
      collapsibleState:
        this.loadingFiles.size > 0
          ? vscode.TreeItemCollapsibleState.Expanded // Auto-expand when files are loading
          : vscode.TreeItemCollapsibleState.Collapsed,
      contextValue: "recentSection",
      children: recentItems,
    };
  }

  private getIssueItems(
    issues: SecurityIssue[],
    fileUri: vscode.Uri
  ): SecurityTreeItem[] {
    return issues.map((issue) => ({
      label: issue.message,
      description: `Line ${issue.line + 1}`,
      tooltip: `${issue.message}\n\nLine: ${
        issue.line + 1
      }\nSeverity: ${this.getSeverityLabel(issue.severity)}\nConfidence: ${
        issue.confidence || "N/A"
      }%${issue.suggestion ? "\n\nSuggestion: " + issue.suggestion : ""}`,
      iconPath: this.getSeverityIcon(issue.severity),
      contextValue: "issue",
      issue: issue,
      command: {
        command: "vscode.open",
        title: "Go to Issue",
        arguments: [
          fileUri,
          {
            selection: new vscode.Range(
              new vscode.Position(issue.line, issue.column),
              new vscode.Position(issue.endLine, issue.endColumn)
            ),
          },
        ],
      },
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
      const fileName = uri.path.split("/").pop() || "Unknown";

      fileItems.push({
        label: fileName,
        description: `${fileIssues.length} issue${
          fileIssues.length === 1 ? "" : "s"
        }`,
        iconPath: new vscode.ThemeIcon("file"),
        collapsibleState: vscode.TreeItemCollapsibleState.Collapsed,
        contextValue: "file",
        resourceUri: uri,
        children: this.getIssueItems(fileIssues, uri),
      });
    }

    return fileItems;
  }

  private getSeverityIcon(
    severity: vscode.DiagnosticSeverity
  ): vscode.ThemeIcon {
    switch (severity) {
      case vscode.DiagnosticSeverity.Error:
        return new vscode.ThemeIcon("error");
      case vscode.DiagnosticSeverity.Warning:
        return new vscode.ThemeIcon("warning");
      case vscode.DiagnosticSeverity.Information:
        return new vscode.ThemeIcon("info");
      default:
        return new vscode.ThemeIcon("circle-outline");
    }
  }

  private getSeverityLabel(severity: vscode.DiagnosticSeverity): string {
    switch (severity) {
      case vscode.DiagnosticSeverity.Error:
        return "Critical";
      case vscode.DiagnosticSeverity.Warning:
        return "Warning";
      case vscode.DiagnosticSeverity.Information:
        return "Information";
      default:
        return "Unknown";
    }
  }

  private hasAnyIssues(): boolean {
    return Array.from(this.securityIssues.values()).some(
      (issues) => issues.length > 0
    );
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
      return "Just now";
    }
  }

  // Public methods to update the tree view
  updateSecurityIssues(
    document: vscode.TextDocument,
    issues: SecurityIssue[]
  ): void {
    const fileUri = document.uri.toString();
    this.securityIssues.set(fileUri, issues);
    this.scanResults.set(fileUri, {
      timestamp: new Date(),
      issueCount: issues.length,
      isEnabled: vscode.workspace
        .getConfiguration("vulnzap")
        .get("enabled", true),
    });
    // Automatically stop loading state when scan results are updated
    this.loadingFiles.delete(fileUri);
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

  // Dependency vulnerability methods
  private hasDependencyVulnerabilities(): boolean {
    return this.dependencyVulnerabilities.size > 0;
  }

  private getDependencyVulnerabilitiesSection(): SecurityTreeItem {
    const allVulns = Array.from(this.dependencyVulnerabilities.values());
    const totalVulns = allVulns.reduce(
      (sum, result) => sum + result.vulnerabilities.length,
      0
    );
    const criticalCount = allVulns.reduce(
      (sum, result) =>
        sum +
        result.vulnerabilities.filter((v) => v.severity === "critical").length,
      0
    );
    const highCount = allVulns.reduce(
      (sum, result) =>
        sum +
        result.vulnerabilities.filter((v) => v.severity === "high").length,
      0
    );

    const children: SecurityTreeItem[] = [];

    // Summary item
    children.push({
      label: `Total Vulnerabilities: ${totalVulns}`,
      description: `${criticalCount} critical, ${highCount} high`,
      iconPath: new vscode.ThemeIcon("package"),
      contextValue: "dependencySummary",
    });

    // Fix All button
    if (totalVulns > 0) {
      children.push({
        label: "Fix All Dependencies",
        description: "Update all to latest versions",
        iconPath: new vscode.ThemeIcon("tools"),
        contextValue: "fixAllDependencies",
        command: {
          command: "vulnzap.fixAllDependencies",
          title: "Fix All Dependencies",
        },
      });
    }

    // List vulnerabilities by severity
    const vulnsBySeverity = new Map<string, VulnerabilityInfo[]>();
    for (const result of allVulns) {
      for (const vuln of result.vulnerabilities) {
        if (!vulnsBySeverity.has(vuln.severity)) {
          vulnsBySeverity.set(vuln.severity, []);
        }
        vulnsBySeverity.get(vuln.severity)!.push(vuln);
      }
    }

    // Add severity groups (only critical and high for inline display)
    for (const [severity, vulns] of vulnsBySeverity) {
      if (severity === "critical" || severity === "high") {
        children.push({
          label: `${severity.charAt(0).toUpperCase() + severity.slice(1)} (${
            vulns.length
          })`,
          iconPath:
            severity === "critical"
              ? new vscode.ThemeIcon("error")
              : new vscode.ThemeIcon("warning"),
          collapsibleState: vscode.TreeItemCollapsibleState.Collapsed,
          contextValue: "dependencySeverityGroup",
          children: vulns.map((vuln) => ({
            label: `${vuln.packageName}@${vuln.packageVersion}`,
            description: vuln.fixedIn
              ? `Fix: ${vuln.fixedIn}`
              : "Update needed",
            tooltip: `${vuln.description}\n\nRecommendation: ${
              vuln.recommendation
            }${vuln.cveId ? `\nCVE: ${vuln.cveId}` : ""}`,
            iconPath: new vscode.ThemeIcon("bug"),
            contextValue: "dependencyVulnerability",
            vulnerability: vuln,
            command: vuln.fixedIn
              ? {
                  command: "vulnzap.updateDependencyToVersion",
                  title: `Update to ${vuln.fixedIn}`,
                  arguments: [vuln.packageName, vuln.fixedIn],
                }
              : {
                  command: "vulnzap.showUpdateCommand",
                  title: `Show update command for ${vuln.packageName}`,
                  arguments: [vuln.packageName],
                },
          })),
        });
      }
    }

    return {
      label: "Dependency Vulnerabilities",
      description: totalVulns > 0 ? `${totalVulns} found` : undefined,
      iconPath: new vscode.ThemeIcon("package"),
      collapsibleState: vscode.TreeItemCollapsibleState.Expanded,
      contextValue: "dependencySection",
      children: children,
    };
  }

  updateDependencyVulnerabilities(scanResult: DependencyScanResult): void {
    this.dependencyVulnerabilities.set(scanResult.projectHash, scanResult);
    this.refresh();
  }

  clearDependencyVulnerabilities(): void {
    this.dependencyVulnerabilities.clear();
    this.refresh();
  }

  // Loading state management methods
  startScanLoading(document: vscode.TextDocument): void {
    this.loadingFiles.add(document.uri.toString());
    this.refresh();
  }

  stopScanLoading(document: vscode.TextDocument): void {
    this.loadingFiles.delete(document.uri.toString());
    this.refresh();
  }

  clearAllLoadingStates(): void {
    this.loadingFiles.clear();
    this.refresh();
  }
}
