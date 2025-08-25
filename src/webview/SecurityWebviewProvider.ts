import * as vscode from "vscode";
import { APIProviderManager } from "../providers/apiProviders";
import {
  VulnerabilityInfo,
  DependencyScanResult,
} from "../dependencies/dependencyCache";

interface SecurityIssue {
  id: string;
  message: string;
  severity: vscode.DiagnosticSeverity;
  line: number;
  column: number;
  endLine?: number;
  endColumn?: number;
  source: string;
  code?: string | number;
  file: string;
  relatedInformation?: vscode.DiagnosticRelatedInformation[];
  tags?: vscode.DiagnosticTag[];
  data?: any;
  similarVulnerabilities?: any[];
}

export class SecurityWebviewProvider implements vscode.WebviewViewProvider {
  public static readonly viewType = "vulnzap.securityView";

  private _view?: vscode.WebviewView;
  private _issues: SecurityIssue[] = [];
  private _dependencyVulnerabilities: Map<string, VulnerabilityInfo[]> =
    new Map();
  private _dependencyScanResults: DependencyScanResult[] = [];

  constructor(
    private readonly _extensionUri: vscode.Uri,
    private readonly context: vscode.ExtensionContext
  ) {}

  public resolveWebviewView(
    webviewView: vscode.WebviewView,
    context: vscode.WebviewViewResolveContext,
    _token: vscode.CancellationToken
  ) {
    this._view = webviewView;

    webviewView.webview.options = {
      enableScripts: true,
      localResourceRoots: [this._extensionUri],
    };

    webviewView.webview.html = this._getHtmlForWebview(webviewView.webview);

    // Handle messages from the webview
    webviewView.webview.onDidReceiveMessage(
      (message) => {
        switch (message.type) {
          case "refresh":
            this.refresh();
            break;
          case "scanDependencies":
            vscode.commands.executeCommand("vulnzap.scanDependencies");
            break;
          case "scanCurrentFile":
            vscode.commands.executeCommand("vulnzap.scanFile");
            break;
          case "openFile":
            this.openFile(message.file, message.line);
            break;
          case "fixVulnerability":
            this.fixVulnerability(message.vulnerability);
            break;
          case "updateDependency":
            vscode.commands.executeCommand(
              "vulnzap.updateDependencyToVersion",
              message.dependency
            );
            break;
          case "showOutputLogs":
            vscode.commands.executeCommand("vulnzap.showOutputChannel");
            break;
          case "fixAllDependencies":
            vscode.commands.executeCommand("vulnzap.fixAllDependencies");
            break;
        }
      },
      undefined,
      this.context.subscriptions
    );

    // Send initial data
    this.updateWebviewData();
  }

  public refresh() {
    if (this._view) {
      this._view.webview.html = this._getHtmlForWebview(this._view.webview);
      this.updateWebviewData();
    }
  }

  public updateIssues(issues: SecurityIssue[]) {
    this._issues = issues;
    this.updateWebviewData();
  }

  public updateDependencyVulnerabilities(
    scanResult: DependencyScanResult | Map<string, VulnerabilityInfo[]>
  ) {
    if (scanResult instanceof Map) {
      this._dependencyVulnerabilities = scanResult;
    } else {
      // Convert DependencyScanResult to Map format
      this._dependencyVulnerabilities.clear();
      scanResult.vulnerabilities.forEach((vuln) => {
        const existing =
          this._dependencyVulnerabilities.get(vuln.packageName) || [];
        existing.push(vuln);
        this._dependencyVulnerabilities.set(vuln.packageName, existing);
      });

      // Also update scan results
      this._dependencyScanResults = [scanResult];
    }
    this.updateWebviewData();
  }

  public updateDependencyScanResults(results: DependencyScanResult[]) {
    this._dependencyScanResults = results;
    this.updateWebviewData();
  }

  // Method called by diagnostic providers to update issues
  public updateIssuesFromDiagnostics(
    uri: vscode.Uri,
    diagnostics: vscode.Diagnostic[]
  ) {
    const file = uri.fsPath;

    // Convert diagnostics to SecurityIssue format
    const issues: SecurityIssue[] = diagnostics.map((diagnostic) => ({
      id: `${file}:${diagnostic.range.start.line}:${diagnostic.range.start.character}`,
      message: diagnostic.message,
      severity: diagnostic.severity || vscode.DiagnosticSeverity.Information,
      line: diagnostic.range.start.line + 1, // Convert to 1-based
      column: diagnostic.range.start.character + 1, // Convert to 1-based
      endLine: diagnostic.range.end.line + 1,
      endColumn: diagnostic.range.end.character + 1,
      source: diagnostic.source || "VulnZap",
      code: diagnostic.code?.toString(),
      file: file,
      relatedInformation: diagnostic.relatedInformation,
      tags: diagnostic.tags,
    }));

    // Update or replace issues for this file
    this._issues = this._issues.filter((issue) => issue.file !== file);
    this._issues.push(...issues);

    this.updateWebviewData();
  }

  // Methods for compatibility with the old tree view interface
  public clearAllSecurityIssues() {
    this._issues = [];
    this.updateWebviewData();
  }

  public clearDependencyVulnerabilities() {
    this._dependencyVulnerabilities.clear();
    this.updateWebviewData();
  }

  public updateSecurityIssues(
    document: vscode.TextDocument,
    issues: SecurityIssue[]
  ) {
    // Filter out old issues for this document and add new ones
    const file = document.uri.fsPath;
    this._issues = this._issues.filter((issue) => issue.file !== file);
    this._issues.push(...issues);
    this.updateWebviewData();
  }

  public startScanLoading(document?: vscode.TextDocument) {
    // Send loading state to webview
    if (this._view) {
      this._view.webview.postMessage({
        type: "scanStarted",
        document: document?.uri.fsPath,
      });
    }
  }

  public stopScanLoading(
    document?: vscode.TextDocument,
    cancelled: boolean = false
  ) {
    // Send scan completed/cancelled state to webview
    if (this._view) {
      this._view.webview.postMessage({
        type: cancelled ? "scanCancelled" : "scanCompleted",
        document: document?.uri.fsPath,
      });
    }
  }

  public startDependencyScanLoading() {
    // Send dependency scan started state to webview
    if (this._view) {
      this._view.webview.postMessage({
        type: "dependencyScanStarted",
      });
    }
  }

  public stopDependencyScanLoading() {
    // Send dependency scan completed state to webview
    if (this._view) {
      this._view.webview.postMessage({
        type: "dependencyScanCompleted",
      });
    }
  }

  private updateWebviewData() {
    if (!this._view) return;

    const data = {
      issues: this._issues,
      dependencyVulnerabilities: Array.from(
        this._dependencyVulnerabilities.entries()
      ),
      dependencyScanResults: this._dependencyScanResults,
      isLoggedIn: !!this.context.globalState.get("vulnzapSession"),
    };

    this._view.webview.postMessage({
      type: "updateData",
      data: data,
    });
  }

  private async openFile(file: string, line?: number) {
    try {
      const document = await vscode.workspace.openTextDocument(file);
      const editor = await vscode.window.showTextDocument(document);

      if (line !== undefined && line > 0) {
        const position = new vscode.Position(line - 1, 0);
        editor.selection = new vscode.Selection(position, position);
        editor.revealRange(new vscode.Range(position, position));
      }
    } catch (error) {
      vscode.window.showErrorMessage(`Could not open file: ${file}`);
    }
  }

  private async fixVulnerability(vulnerability: any) {
    // Implement vulnerability fixing logic
    vscode.window.showInformationMessage(
      `Fixing vulnerability: ${vulnerability.id}`
    );
  }

  private _getHtmlForWebview(webview: vscode.Webview) {
    const scriptUri = webview.asWebviewUri(
      vscode.Uri.joinPath(this._extensionUri, "media", "security.js")
    );
    const styleUri = webview.asWebviewUri(
      vscode.Uri.joinPath(this._extensionUri, "media", "security.css")
    );

    const nonce = getNonce();

    return `<!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${
          webview.cspSource
        } 'unsafe-inline'; script-src 'nonce-${nonce}';">
        <link href="${styleUri}" rel="stylesheet">
        <title>VulnZap Security Analysis</title>
      </head>
      <body>
        <div id="security-container">
          <div class="header">
            <div class="logo-section">
              <svg viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg" class="logo-svg">
                <path d="M13 9L19 1L27 11L22 18Z" fill="currentColor" />
                <path d="M13 9L1 19L13 27L22 18Z" fill="currentColor" />
                <path d="M22 18L13 27L19 37L27 25Z" fill="currentColor" />
                <path d="M22 18L27 11L39 19L31 27Z" fill="currentColor" />
                <path d="M20 15L25 20M20 15L15 20M20 15L20 10M20 25L15 20M20 25L25 20M20 25L20 30" stroke="currentColor" stroke-width="1.5" />
              </svg>
              <h1>Security Analysis</h1>
            </div>
            <div class="action-buttons">
              <button id="refresh-btn" class="action-btn">
                <span class="icon" data-icon="refresh"></span>
                Refresh
              </button>
              <button id="scan-deps-btn" class="action-btn">
                <span class="icon" data-icon="package"></span>
                Scan Dependencies
              </button>
              <button id="scan-file-btn" class="action-btn">
                <span class="icon" data-icon="file"></span>
                Scan Current File
              </button>
            </div>
          </div>

          <div class="content">
            <!-- Statistics Section -->
            <div class="section" id="stats-section">
              <div class="section-header">
                <h2><span class="icon" data-icon="stats"></span> Statistics</h2>
              </div>
              <div class="stats-grid">
                <div class="stat-card">
                  <div class="stat-value" id="total-issues">0</div>
                  <div class="stat-label">Total Issues</div>
                </div>
                <div class="stat-card critical">
                  <div class="stat-value" id="critical-issues">0</div>
                  <div class="stat-label">Critical</div>
                </div>
                <div class="stat-card high">
                  <div class="stat-value" id="high-issues">0</div>
                  <div class="stat-label">High</div>
                </div>
                <div class="stat-card medium">
                  <div class="stat-value" id="medium-issues">0</div>
                  <div class="stat-label">Medium</div>
                </div>
                <div class="stat-card low">
                  <div class="stat-value" id="low-issues">0</div>
                  <div class="stat-label">Low</div>
                </div>
              </div>
            </div>

            <!-- Dependency Vulnerabilities Section -->
            <div class="section" id="dependencies-section">
              <div class="section-header">
                <h2><span class="icon" data-icon="package"></span> Dependency Vulnerabilities</h2>
                <div class="section-actions">
                  <button id="fix-all-deps" class="fix-btn">Fix All</button>
                </div>
              </div>
              <div id="dependencies-list" class="vulnerabilities-list">
                <!-- Dependencies will be populated here -->
              </div>
            </div>

            <!-- Code Issues Section -->
            <div class="section" id="issues-section">
              <div class="section-header">
                <h2><span class="icon" data-icon="search"></span> Code Security Issues</h2>
                <div class="filter-controls">
                  <select id="severity-filter">
                    <option value="all">All Severities</option>
                    <option value="1">Critical</option>
                    <option value="2">High</option>
                    <option value="3">Medium</option>
                    <option value="4">Low</option>
                  </select>
                  <select id="file-filter">
                    <option value="all">All Files</option>
                  </select>
                </div>
              </div>
              <div id="issues-list" class="issues-list">
                <!-- Issues will be populated here -->
              </div>
            </div>

            <!-- Recent Scans Section -->
            <div class="section" id="scans-section">
              <div class="section-header">
                <h2><span class="icon" data-icon="clipboard"></span> Recent Scans</h2>
                <button id="show-logs-btn" class="action-btn">View Logs</button>
              </div>
              <div id="scans-list" class="scans-list">
                <!-- Recent scans will be populated here -->
              </div>
            </div>
          </div>
        </div>

        <script nonce="${nonce}" src="${webview.asWebviewUri(
      vscode.Uri.joinPath(this._extensionUri, "media", "icons.js")
    )}"></script>
        <script nonce="${nonce}" src="${scriptUri}"></script>
      </body>
      </html>`;
  }
}

function getNonce() {
  let text = "";
  const possible =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  for (let i = 0; i < 32; i++) {
    text += possible.charAt(Math.floor(Math.random() * possible.length));
  }
  return text;
}
