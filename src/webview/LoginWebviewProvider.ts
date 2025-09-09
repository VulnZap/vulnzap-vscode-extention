import * as vscode from "vscode";

export class LoginWebviewProvider implements vscode.WebviewViewProvider {
  public static readonly viewType = "vulnzap.loginView";

  private _view?: vscode.WebviewView;

  constructor(
    private readonly _extensionUri: vscode.Uri,
    private readonly _context: vscode.ExtensionContext
  ) {}

  public resolveWebviewView(
    webviewView: vscode.WebviewView,
    context: vscode.WebviewViewResolveContext,
    _token: vscode.CancellationToken
  ) {
    this._view = webviewView;

    webviewView.webview.options = {
      // Allow scripts in the webview
      enableScripts: true,
      localResourceRoots: [this._extensionUri],
    };

    webviewView.webview.html = this._getHtmlForWebview(webviewView.webview);

    // Handle messages from the webview
    webviewView.webview.onDidReceiveMessage(
      (message) => {
        switch (message.type) {
          case "login":
            vscode.commands.executeCommand("vulnzap.login");
            break;
          case "createAccount":
            vscode.env.openExternal(vscode.Uri.parse("https://vulnzap.com"));
            break;
        }
      },
      undefined,
      this._context.subscriptions
    );

    // Handle webview visibility changes - refresh view when tab becomes visible
    webviewView.onDidChangeVisibility(
      () => {
        if (webviewView.visible) {
          // Webview became visible (user switched back to this tab)
          // Refresh the view to ensure it reflects current login state
          this.refresh();
        }
      },
      undefined,
      this._context.subscriptions
    );
  }

  public refresh() {
    if (this._view) {
      this._view.webview.html = this._getHtmlForWebview(this._view.webview);
    }
  }

  private _getHtmlForWebview(webview: vscode.Webview) {
    // Get the local path to main script run in the webview, then convert it to a uri we can use in the webview.
    const scriptUri = webview.asWebviewUri(
      vscode.Uri.joinPath(this._extensionUri, "media", "login.js")
    );
    const styleUri = webview.asWebviewUri(
      vscode.Uri.joinPath(this._extensionUri, "media", "login.css")
    );

    // Use a nonce to only allow specific scripts to be run
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
        <title>VulnZap Login</title>
      </head>
      <body>
        <div id="login-container">
          <div class="login-header">
             <div class="logo-icon">
               <svg viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg" class="logo-svg">
                 <path d="M13 9L19 1L27 11L22 18Z" fill="currentColor" />
                 <path d="M13 9L1 19L13 27L22 18Z" fill="currentColor" />
                 <path d="M22 18L13 27L19 37L27 25Z" fill="currentColor" />
                 <path d="M22 18L27 11L39 19L31 27Z" fill="currentColor" />
                 <path d="M20 15L25 20M20 15L15 20M20 15L20 10M20 25L15 20M20 25L25 20M20 25L20 30" stroke="currentColor" stroke-width="1.5" />
               </svg>
             </div>
             <h1>Welcome to VulnZap!</h1>
             <p>Please sign in below to continue.</p>
          </div>

          <div class="login-form">
            <button id="signin-btn" class="signin-button">
              <span class="button-icon" data-icon="key"></span>
              Sign In
            </button>
          </div>

          

          <div class="signup-section">
            <p>Need an account? <a href="#" id="create-account">Create one at vulnzap.com</a></p>
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
