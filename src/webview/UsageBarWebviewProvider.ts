import * as vscode from "vscode";
import { UsageService, UsageData } from "../utils/usageService";
import { Logger } from "../utils/logger";

export class UsageBarWebviewProvider implements vscode.WebviewViewProvider {
  public static readonly viewType = "vulnzap.usageBar";

  private _view?: vscode.WebviewView;
  private _usageService: UsageService;
  private _disposables: vscode.Disposable[] = [];

  constructor(
    private readonly _extensionUri: vscode.Uri,
    private readonly _context: vscode.ExtensionContext
  ) {
    this._usageService = UsageService.getInstance(_context);

    // Listen for usage updates
    this._disposables.push(
      this._usageService.onUsageUpdated((usage) => {
        this.updateUsageDisplay(usage);
      })
    );
  }

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
            this.refreshUsage();
            break;
          case "logout":
            vscode.commands.executeCommand("vulnzap.logout");
            break;
        }
      },
      undefined,
      this._context.subscriptions
    );

    // Handle webview visibility changes - refresh data when tab becomes visible
    webviewView.onDidChangeVisibility(
      () => {
        if (webviewView.visible) {
          // Webview became visible (user switched back to this tab)
          // Refresh usage data to ensure it's up to date
          this.loadInitialUsage();
        }
      },
      undefined,
      this._context.subscriptions
    );

    // Initial data load
    this.loadInitialUsage();
  }

  private async loadInitialUsage() {
    const lastUsage = this._usageService.getLastUsageData();
    if (lastUsage) {
      this.updateUsageDisplay(lastUsage);
    } else {
      // Fetch fresh data
      await this._usageService.fetchUsageData();
    }
  }

  private async refreshUsage() {
    try {
      this.updateLoadingState(true);
      await this._usageService.refreshAll(); // Refresh both profile and usage data
    } catch (error) {
      Logger.error("Error refreshing usage:", error as Error);
    } finally {
      this.updateLoadingState(false);
    }
  }

  private updateLoadingState(loading: boolean) {
    if (this._view) {
      this._view.webview.postMessage({
        type: "loading",
        loading: loading,
      });
    }
  }

  private updateUsageDisplay(usage: UsageData) {
    if (this._view) {
      Logger.debug("Sending usage data to webview:", usage);
      this._view.webview.postMessage({
        type: "updateUsage",
        usage: usage,
      });
    }
  }

  public refresh() {
    if (this._view) {
      this._view.webview.html = this._getHtmlForWebview(this._view.webview);
      this.loadInitialUsage();
    }
  }

  public dispose() {
    this._disposables.forEach((d) => d.dispose());
  }

  private _getHtmlForWebview(webview: vscode.Webview) {
    const scriptUri = webview.asWebviewUri(
      vscode.Uri.joinPath(this._extensionUri, "media", "usageBar.js")
    );
    const styleUri = webview.asWebviewUri(
      vscode.Uri.joinPath(this._extensionUri, "media", "usageBar.css")
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
        <title>VulnZap Usage</title>
      </head>
      <body>
        <div id="usage-container">
          <div class="usage-header">
            <div class="usage-title">
              <span class="usage-icon" data-icon="stats"></span>
              <span class="title-text">Usage</span>
            </div>
            <div class="usage-actions">
              <button id="refresh-btn" class="action-btn" title="Refresh Usage Data">
                <span class="icon" data-icon="refresh"></span>
              </button>
              <button id="logout-btn" class="action-btn" title="Logout">
                <span class="icon" data-icon="sign-out"></span>
              </button>
            </div>
          </div>

          <div class="usage-content">
            <!-- Line Scan Usage Progress -->
            <div class="usage-progress-section">
              <div class="progress-header">
                <div class="progress-title">
                  <span class="progress-icon" data-icon="stats"></span>
                  <span class="progress-label">Line Scan Usage</span>
                  <span class="tier-badge" id="tier-badge">Free</span>
                </div>
                <div class="progress-numbers">
                  <span id="line-scans-used">--</span> / <span id="line-scans-limit">--</span>
                </div>
              </div>
              <div class="progress-bar-container">
                <div class="progress-bar">
                  <div class="progress-fill" id="progress-fill"></div>
                </div>
                <div class="progress-percentage" id="progress-percentage">0%</div>
              </div>
              <div class="progress-details">
                <span class="remaining-text" id="remaining-text">-- lines remaining</span>
              </div>
            </div>

            <!-- Compact Stats -->
            <div class="compact-stats">
              <div class="stat-item secondary">
                <div class="stat-value" id="total-scans">--</div>
                <div class="stat-label">Total Scans</div>
              </div>

              <div class="stat-divider"></div>

              <div class="stat-item tertiary">
                <div class="stat-value" id="vulnerabilities">--</div>
                <div class="stat-label">Issues Found</div>
              </div>
            </div>
          </div>

          <div class="loading-overlay" id="loading-overlay" style="display: none;">
            <div class="loading-spinner"><span class="icon" data-icon="spinner"></span></div>
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
