import * as vscode from "vscode";

import { DiagnosticProvider } from "../providers/diagnosticProvider";
import { DependencyDiagnosticProvider } from "../providers/dependencyDiagnosticProvider";
import { APIProviderManager } from "../providers/apiProviders";
import { SecurityViewProvider } from "../providers/securityViewProvider";
import { LoginWebviewProvider } from "../webview/LoginWebviewProvider";

import { CodebaseSecurityAnalyzer } from "../security/codebaseSecurityAnalyzer";
import { DependencyScanner } from "../dependencies/dependencyScanner";
import { Logger } from "../utils/logger";

/**
 * Main extension activation function
 * Initializes all components and registers commands, listeners, and providers
 */
export async function activate(context: vscode.ExtensionContext) {
  try {
    // Initialize logger first for proper output channel logging
    Logger.initialize();
    Logger.info("VulnZap extension is activating...");

    // Initialize core security analysis components
    const codebaseSecurityAnalyzer = new CodebaseSecurityAnalyzer();

    const diagnosticProvider = new DiagnosticProvider(context);
    const dependencyDiagnosticProvider = new DependencyDiagnosticProvider(
      context
    );
    const securityViewProvider = new SecurityViewProvider(context);
    const loginWebviewProvider = new LoginWebviewProvider(
      context.extensionUri,
      context
    );
    const dependencyScanner = new DependencyScanner(context);

    // Register the security issues tree view in the sidebar
    vscode.window.registerTreeDataProvider(
      "vulnzap.securityView",
      securityViewProvider
    );

    // Register the login webview provider
    vscode.window.registerWebviewViewProvider(
      LoginWebviewProvider.viewType,
      loginWebviewProvider
    );

    // Set initial context based on login status
    updateLoginContext();

    // Connect diagnostic providers with security view for synchronized updates
    diagnosticProvider.setSecurityViewProvider(securityViewProvider);
    dependencyDiagnosticProvider.setSecurityViewProvider(securityViewProvider);

    // Connect dependency scanner with dependency diagnostic provider
    dependencyScanner.setDependencyDiagnosticProvider(
      dependencyDiagnosticProvider
    );

    // Get user configuration preferences
    let isEnabled = vscode.workspace
      .getConfiguration("vulnzap")
      .get("enabled", true);
    let scanTimeout: NodeJS.Timeout | undefined;

    // Create status bar indicator showing extension state
    const statusBarItem = vscode.window.createStatusBarItem(
      vscode.StatusBarAlignment.Right,
      100
    );
    statusBarItem.command = "vulnzap.toggle";
    updateStatusBar();
    statusBarItem.show();

    // Listen for file save events to trigger security analysis and dependency scanning
    const documentSaveListener = vscode.workspace.onDidSaveTextDocument(
      async (document) => {
        if (!isEnabled) return;

        // Check if this is a dependency file and trigger dependency scan
        await dependencyScanner.onFileSaved(document);

        if (!isSupportedLanguage(document.languageId)) return;

        // Clear any pending timeouts since we're processing immediately
        if (scanTimeout) {
          clearTimeout(scanTimeout);
        }

        // Execute comprehensive AI-powered analysis
        await scanDocument(document);
      }
    );

    // Listen for editor changes to scan newly opened files
    const activeEditorChangeListener =
      vscode.window.onDidChangeActiveTextEditor(async (editor) => {
        if (!isEnabled || !editor) return;

        const document = editor.document;
        if (!isSupportedLanguage(document.languageId)) return;

        await scanDocument(document);
      });

    // Register all extension commands
    Logger.info("Registering commands...");

    // Command: Enable security scanning
    const enableCommand = vscode.commands.registerCommand(
      "vulnzap.enable",
      () => {
        Logger.info("Enable command called");
        isEnabled = true;
        vscode.workspace
          .getConfiguration("vulnzap")
          .update("enabled", true, true);
        updateStatusBar();
        vscode.window.showInformationMessage("Security review enabled");

        // Immediately scan the current file if one is open
        const activeEditor = vscode.window.activeTextEditor;
        if (activeEditor) {
          scanDocument(activeEditor.document);
        }
      }
    );

    // Command: Disable security scanning
    const disableCommand = vscode.commands.registerCommand(
      "vulnzap.disable",
      () => {
        Logger.info("Disable command called");
        isEnabled = false;
        vscode.workspace
          .getConfiguration("vulnzap")
          .update("enabled", false, true);
        updateStatusBar();
        diagnosticProvider.clearAll();
        dependencyDiagnosticProvider.clearAll();
        securityViewProvider.clearAllSecurityIssues();
        securityViewProvider.clearDependencyVulnerabilities();
        vscode.window.showInformationMessage("Security review disabled");
      }
    );

    // Command: Toggle security scanning on/off
    const toggleCommand = vscode.commands.registerCommand(
      "vulnzap.toggle",
      () => {
        console.log("VulnZap: Toggle command called");
        if (isEnabled) {
          vscode.commands.executeCommand("vulnzap.disable");
        } else {
          vscode.commands.executeCommand("vulnzap.enable");
        }
      }
    );

    // Command: Manually scan the current file
    const scanFileCommand = vscode.commands.registerCommand(
      "vulnzap.scanFile",
      async () => {
        console.log("VulnZap: Scan file command called");
        const activeEditor = vscode.window.activeTextEditor;
        if (!activeEditor) {
          vscode.window.showWarningMessage("No active file to scan");
          return;
        }

        await scanDocument(activeEditor.document, true);
        vscode.window.showInformationMessage("Security scan completed");
      }
    );

    // Command: Configure API provider selection
    const selectApiProviderCommand = vscode.commands.registerCommand(
      "vulnzap.selectApiProvider",
      async () => {
        console.log("VulnZap: Configure VulnZap API command called");
        await configureVulnZap(vscode.workspace.getConfiguration("vulnzap"));
      }
    );

    // Command: Set up API keys for AI providers
    const configureApiKeysCommand = vscode.commands.registerCommand(
      "vulnzap.configureApiKeys",
      async () => {
        console.log("VulnZap: Configure API keys command called");
        try {
          const config = vscode.workspace.getConfiguration("vulnzap");
          await configureVulnZap(config);
          vscode.window.showInformationMessage(
            "✅ VulnZap API configured successfully!"
          );
        } catch (error) {
          console.error("VulnZap: Error in configureApiKeys:", error);
          vscode.window.showErrorMessage(
            "Error configuring API keys: " + (error as Error).message
          );
        }
      }
    );

    // Command: Toggle AST-guided precision analysis
    const toggleASTCommand = vscode.commands.registerCommand(
      "vulnzap.toggleASTPrecision",
      async () => {
        console.log("VulnZap: Toggle AST precision command called");
        const config = vscode.workspace.getConfiguration("vulnzap");
        const currentValue = config.get("enableASTPrecision", true);
        const newValue = !currentValue;

        await config.update("enableASTPrecision", newValue, true);

        const message = newValue
          ? "✅ AST-guided precision analysis enabled"
          : "❌ AST-guided precision analysis disabled";
        vscode.window.showInformationMessage(message);

        // Rescan current file if one is open
        const activeEditor = vscode.window.activeTextEditor;
        if (activeEditor && isEnabled) {
          await scanDocument(activeEditor.document, true);
        }
      }
    );

    // Security View Commands - manage the security issues panel

    // Command: Refresh the security view panel
    const refreshSecurityViewCommand = vscode.commands.registerCommand(
      "vulnzap.refreshSecurityView",
      () => {
        console.log("VulnZap: Refresh security view command called");
        securityViewProvider.refresh();
        vscode.window.showInformationMessage("Security view refreshed");
      }
    );

    // Command: Clear all detected security issues
    const clearAllIssuesCommand = vscode.commands.registerCommand(
      "vulnzap.clearAllIssues",
      () => {
        console.log("VulnZap: Clear all issues command called");
        diagnosticProvider.clearAll();
        dependencyDiagnosticProvider.clearAll();
        securityViewProvider.clearAllSecurityIssues();
        securityViewProvider.clearDependencyVulnerabilities();
        vscode.window.showInformationMessage("All security issues cleared");
      }
    );

    // Command: Scan the entire workspace
    const scanWorkspaceCommand = vscode.commands.registerCommand(
      "vulnzap.scanWorkspace",
      async () => {
        console.log("VulnZap: Scan workspace command called");

        if (!isEnabled) {
          vscode.window.showWarningMessage(
            "Security scanning is disabled. Enable it first."
          );
          return;
        }

        const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
        if (!workspaceFolder) {
          vscode.window.showWarningMessage("No workspace folder open");
          return;
        }

        await vscode.window.withProgress(
          {
            location: vscode.ProgressLocation.Notification,
            title: "Scanning workspace for security issues...",
            cancellable: true,
          },
          async (progress, token) => {
            const supportedExtensions = [".js", ".ts", ".py", ".java"];

            // Comprehensive exclude pattern for build/output directories
            const excludePatterns = [
              // Package managers & dependencies
              "**/node_modules/**",
              "**/bower_components/**",

              // JavaScript/TypeScript build outputs
              "**/dist/**",
              "**/build/**",
              "**/out/**",
              "**/.next/**",
              "**/.nuxt/**",
              "**/coverage/**",
              "**/.nyc_output/**",

              // Python build/cache directories
              "**/__pycache__/**",
              "**/build/**",
              "**/dist/**",
              "**/.pytest_cache/**",
              "**/venv/**",
              "**/env/**",
              "**/.venv/**",
              "**/site-packages/**",

              // Java build outputs
              "**/target/**",
              "**/bin/**",
              "**/.gradle/**",
              "**/gradle/**",
              "**/classes/**",

              // IDE and editor directories
              "**/.vscode/**",
              "**/.idea/**",
              "**/*.swp",
              "**/*.swo",

              // Version control and temp directories
              "**/.git/**",
              "**/tmp/**",
              "**/temp/**",
              "**/logs/**",
              "**/.cache/**",
              "**/.DS_Store",
            ].join(",");

            const files = await vscode.workspace.findFiles(
              `**/*{${supportedExtensions.join(",")}}`,
              `{${excludePatterns}}`
            );

            let scannedCount = 0;
            for (const file of files) {
              if (token.isCancellationRequested) {
                break;
              }

              try {
                const document = await vscode.workspace.openTextDocument(file);
                if (isSupportedLanguage(document.languageId)) {
                  await scanDocument(document);
                  scannedCount++;
                }
              } catch (error) {
                console.error(`Error scanning ${file.fsPath}:`, error);
              }

              progress.report({
                increment: 100 / files.length,
                message: `Scanned ${scannedCount}/${files.length} files`,
              });
            }

            vscode.window.showInformationMessage(
              `Workspace scan complete. Scanned ${scannedCount} files.`
            );
          }
        );
      }
    );

    // Register the login command
    const loginCommand = vscode.commands.registerCommand(
      "vulnzap.login",
      async () => {
        const config = vscode.workspace.getConfiguration("vulnzap");
        const port = 54322; // Use a port unlikely to conflict with CLI
        const state = Math.random().toString(36).substring(2);
        const callbackUrl = `http://localhost:${port}/callback`;
        const apiBaseUrl = "https://vulnzap.com";
        let server: any;
        let timeoutId: NodeJS.Timeout | undefined;
        try {
          // 1. Request login URL from VulnZap web app
          const response = await fetch(
            `${apiBaseUrl}/auth/cli?` +
              new URLSearchParams({
                state,
                redirect_uri: callbackUrl,
                usecase: "login",
              })
          );
          const { url } = await response.json();
          if (!url) throw new Error("Failed to get authentication URL");

          // 2. Start local server to receive callback
          const http = await import("http");
          const serverPromise = new Promise((resolve, reject) => {
            let serverClosed = false;
            server = http.createServer(async (req: any, res: any) => {
              if (serverClosed) return;
              const reqUrl = new URL(req.url!, `http://localhost:${port}`);
              const urlState = reqUrl.searchParams.get("state");
              const access_token = reqUrl.searchParams.get("access_token");
              const refresh_token = reqUrl.searchParams.get("refresh_token");
              const expires_at = reqUrl.searchParams.get("expires_at");
              const apiKey = reqUrl.searchParams.get("api_key");
              if (urlState === state && access_token && apiKey) {
                // Save session in global state
                const session = {
                  access_token,
                  refresh_token,
                  expires_at: expires_at ? parseInt(expires_at) : 0,
                  apiKey,
                };
                await context.globalState.update("vulnzapSession", session);
                await config.update(
                  "vulnzapApiKey",
                  apiKey,
                  vscode.ConfigurationTarget.Global
                );
                await config.update(
                  "vulnzapApiProvider",
                  "vulnzap",
                  vscode.ConfigurationTarget.Global
                );
                res.writeHead(200, { "Content-Type": "text/html" });
                res.end(
                  "<html><body><h2>VulnZap: Login successful!</h2><p>You may now close this tab and return to VS Code.</p></body></html>"
                );
                setTimeout(() => {
                  serverClosed = true;
                  server.close();
                  clearTimeout(timeoutId);
                  resolve(session);
                }, 2000);
              } else {
                res.writeHead(400, { "Content-Type": "text/html" });
                res.end(
                  "<html><body><h2>VulnZap: Login failed.</h2><p>Invalid state or missing tokens.</p></body></html>"
                );
                setTimeout(() => {
                  serverClosed = true;
                  server.close();
                  clearTimeout(timeoutId);
                  reject(new Error("Invalid state or missing tokens"));
                }, 2000);
              }
            });
            server.listen(port);
            timeoutId = setTimeout(() => {
              if (!serverClosed) {
                serverClosed = true;
                server.close();
                reject(
                  new Error(
                    "Authentication timeout - no response received within 2 minutes"
                  )
                );
              }
            }, 120000);
          });

          // 3. Open browser for login
          vscode.env.openExternal(vscode.Uri.parse(url));
          vscode.window.showInformationMessage(
            "Please complete login in your browser."
          );
          // 4. Wait for callback
          await serverPromise;
          vscode.window.showInformationMessage("VulnZap: Login successful!");
          // 5. Update context and refresh views
          updateLoginContext();
          securityViewProvider.refresh();
          updateStatusBar(); // Update status bar to show logged in state
        } catch (err: any) {
          vscode.window.showErrorMessage(
            "VulnZap: Login failed: " + err.message
          );
        } finally {
          if (server) {
            try {
              server.close();
            } catch {}
          }
          if (timeoutId) {
            clearTimeout(timeoutId);
          }
        }
      }
    );

    // Register the logout command
    const logoutCommand = vscode.commands.registerCommand(
      "vulnzap.logout",
      async () => {
        const confirm = await vscode.window.showWarningMessage(
          "Are you sure you want to sign out of VulnZap?",
          "Sign Out",
          "Cancel"
        );

        if (confirm === "Sign Out") {
          // Clear session from global state
          await context.globalState.update("vulnzapSession", undefined);

          // Clear API configuration
          const config = vscode.workspace.getConfiguration("vulnzap");
          await config.update(
            "vulnzapApiKey",
            "",
            vscode.ConfigurationTarget.Global
          );
          await config.update(
            "vulnzapApiProvider",
            "",
            vscode.ConfigurationTarget.Global
          );

          // Clear all issues and refresh views
          diagnosticProvider.clearAll();
          dependencyDiagnosticProvider.clearAll();
          securityViewProvider.clearAllSecurityIssues();
          securityViewProvider.clearDependencyVulnerabilities();
          updateLoginContext();
          securityViewProvider.refresh();
          updateStatusBar(); // Update status bar to show login required

          vscode.window.showInformationMessage(
            "Successfully signed out of VulnZap"
          );
        }
      }
    );

    // Dependency Scanning Commands
    const scanDependenciesCommand = vscode.commands.registerCommand(
      "vulnzap.scanDependencies",
      async () => {
        console.log("VulnZap: Scan dependencies command called");

        try {
          await vscode.window.withProgress(
            {
              location: vscode.ProgressLocation.Notification,
              title: "Scanning dependencies for vulnerabilities...",
              cancellable: false,
            },
            async () => {
              const results =
                await dependencyScanner.scanWorkspaceDependencies();

              if (results.length === 0) {
                vscode.window.showInformationMessage(
                  "No dependencies found or no dependency files detected in workspace."
                );
              } else {
                const totalVulns = results.reduce(
                  (sum, result) => sum + result.vulnerabilities.length,
                  0
                );
                const totalPackages = results.reduce(
                  (sum, result) => sum + result.totalPackages,
                  0
                );

                if (totalVulns === 0) {
                  vscode.window.showInformationMessage(
                    `✅ No vulnerabilities found in ${totalPackages} dependencies across ${results.length} project(s).`
                  );
                } else {
                  vscode.window.showWarningMessage(
                    `🔍 Found ${totalVulns} vulnerabilities in ${totalPackages} dependencies. Check notifications for details.`
                  );
                }
              }
            }
          );
        } catch (error) {
          console.error("Error scanning dependencies:", error);
          vscode.window.showErrorMessage(
            "Error scanning dependencies: " + (error as Error).message
          );
        }
      }
    );

    const forceDependencyScanCommand = vscode.commands.registerCommand(
      "vulnzap.forceDependencyScan",
      async () => {
        console.log("VulnZap: Force dependency scan command called");

        try {
          await vscode.window.withProgress(
            {
              location: vscode.ProgressLocation.Notification,
              title: "Force scanning dependencies (ignoring cache)...",
              cancellable: false,
            },
            async () => {
              const results = await dependencyScanner.forceScan();

              if (results.length === 0) {
                vscode.window.showInformationMessage(
                  "No dependencies found or no dependency files detected in workspace."
                );
              } else {
                const totalVulns = results.reduce(
                  (sum, result) => sum + result.vulnerabilities.length,
                  0
                );
                const totalPackages = results.reduce(
                  (sum, result) => sum + result.totalPackages,
                  0
                );

                if (totalVulns === 0) {
                  vscode.window.showInformationMessage(
                    `✅ Fresh scan complete: No vulnerabilities found in ${totalPackages} dependencies.`
                  );
                } else {
                  vscode.window.showWarningMessage(
                    `🔍 Fresh scan complete: Found ${totalVulns} vulnerabilities in ${totalPackages} dependencies.`
                  );
                }
              }
            }
          );
        } catch (error) {
          console.error("Error force scanning dependencies:", error);
          vscode.window.showErrorMessage(
            "Error force scanning dependencies: " + (error as Error).message
          );
        }
      }
    );

    const dependencyCacheStatsCommand = vscode.commands.registerCommand(
      "vulnzap.dependencyCacheStats",
      async () => {
        console.log("VulnZap: Dependency cache stats command called");

        try {
          const stats = await dependencyScanner.getCacheInfo();
          const oldestDate = stats.oldestEntry
            ? new Date(stats.oldestEntry).toLocaleString()
            : "N/A";
          const newestDate = stats.newestEntry
            ? new Date(stats.newestEntry).toLocaleString()
            : "N/A";
          const sizeInMB = (stats.totalSize / (1024 * 1024)).toFixed(2);

          const message =
            `📊 Dependency Cache Statistics\n\n` +
            `Total Entries: ${stats.totalEntries}\n` +
            `Total Size: ${sizeInMB} MB\n` +
            `Expired Entries: ${stats.expiredEntries}\n` +
            `Oldest Entry: ${oldestDate}\n` +
            `Newest Entry: ${newestDate}`;

          vscode.window
            .showInformationMessage(message, "Clean Cache")
            .then((selection) => {
              if (selection === "Clean Cache") {
                vscode.commands.executeCommand("vulnzap.cleanDependencyCache");
              }
            });
        } catch (error) {
          console.error("Error getting cache stats:", error);
          vscode.window.showErrorMessage(
            "Error getting cache statistics: " + (error as Error).message
          );
        }
      }
    );

    const cleanDependencyCacheCommand = vscode.commands.registerCommand(
      "vulnzap.cleanDependencyCache",
      async () => {
        console.log("VulnZap: Clean dependency cache command called");

        try {
          const cleanedCount = await dependencyScanner.cleanupCache();
          vscode.window.showInformationMessage(
            `🧹 Cleaned up ${cleanedCount} expired cache entries.`
          );
        } catch (error) {
          console.error("Error cleaning cache:", error);
          vscode.window.showErrorMessage(
            "Error cleaning cache: " + (error as Error).message
          );
        }
      }
    );

    // Dependency Fix Commands
    const updateDependencyToVersionCommand = vscode.commands.registerCommand(
      "vulnzap.updateDependencyToVersion",
      async (
        packageNameOrUri?: string | vscode.Uri,
        packageName?: string,
        version?: string
      ) => {
        console.log("VulnZap: Update dependency to version command called");

        try {
          let targetPackageName: string;
          let targetVersion: string;
          let packageJsonUri: vscode.Uri;

          if (packageNameOrUri instanceof vscode.Uri) {
            // Called from code action with document URI
            packageJsonUri = packageNameOrUri;
            targetPackageName = packageName!;
            targetVersion = version!;
          } else {
            // Called from sidebar with package name directly
            targetPackageName = packageNameOrUri!;
            targetVersion = packageName!;

            // Find package.json in workspace
            const workspaceFolders = vscode.workspace.workspaceFolders;
            if (!workspaceFolders) {
              vscode.window.showErrorMessage("No workspace folder found");
              return;
            }
            packageJsonUri = vscode.Uri.file(
              `${workspaceFolders[0].uri.fsPath}/package.json`
            );
          }

          const document = await vscode.workspace.openTextDocument(
            packageJsonUri
          );
          const edit = new vscode.WorkspaceEdit();

          const text = document.getText();
          const packageRegex = new RegExp(
            `("${targetPackageName}"\\s*:\\s*"[^"]*")`,
            "g"
          );
          const match = packageRegex.exec(text);

          if (match) {
            const startPos = document.positionAt(text.indexOf(match[1]));
            const endPos = document.positionAt(
              text.indexOf(match[1]) + match[1].length
            );
            const newText = `"${targetPackageName}": "${targetVersion}"`;

            edit.replace(
              packageJsonUri,
              new vscode.Range(startPos, endPos),
              newText
            );

            const success = await vscode.workspace.applyEdit(edit);
            if (success) {
              await document.save();
              vscode.window.showInformationMessage(
                `✅ Updated ${targetPackageName} to version ${targetVersion}`
              );
            } else {
              vscode.window.showErrorMessage(
                `Failed to update ${targetPackageName}`
              );
            }
          } else {
            vscode.window.showErrorMessage(
              `Package ${targetPackageName} not found in package.json`
            );
          }
        } catch (error) {
          console.error("Error updating dependency:", error);
          vscode.window.showErrorMessage(
            "Error updating dependency: " + (error as Error).message
          );
        }
      }
    );

    const showUpdateCommandCmd = vscode.commands.registerCommand(
      "vulnzap.showUpdateCommand",
      async (packageName: string) => {
        console.log("VulnZap: Show update command called for:", packageName);

        const command = `npm install ${packageName}@latest`;

        const action = await vscode.window.showInformationMessage(
          `To update ${packageName}, run this command in your terminal:`,
          "Copy Command",
          "Open Terminal"
        );

        if (action === "Copy Command") {
          await vscode.env.clipboard.writeText(command);
          vscode.window.showInformationMessage("Command copied to clipboard!");
        } else if (action === "Open Terminal") {
          const terminal = vscode.window.createTerminal(
            "VulnZap Dependency Update"
          );
          terminal.show();
          terminal.sendText(command);
        }
      }
    );

    const fixAllDependenciesCommand = vscode.commands.registerCommand(
      "vulnzap.fixAllDependencies",
      async () => {
        console.log("VulnZap: Fix all dependencies command called");

        try {
          const workspaceFolders = vscode.workspace.workspaceFolders;
          if (!workspaceFolders) {
            vscode.window.showErrorMessage("No workspace folder found");
            return;
          }

          const action = await vscode.window.showWarningMessage(
            "This will update all dependencies to their latest versions. This may introduce breaking changes. Are you sure?",
            "Update All",
            "Cancel"
          );

          if (action === "Update All") {
            const terminal = vscode.window.createTerminal(
              "VulnZap Fix All Dependencies"
            );
            terminal.show();

            // Use npm update to update all dependencies
            terminal.sendText("npm update");

            vscode.window.showInformationMessage(
              "🔄 Running npm update to fix all dependencies. Check the terminal for progress."
            );
          }
        } catch (error) {
          console.error("Error fixing all dependencies:", error);
          vscode.window.showErrorMessage(
            "Error fixing all dependencies: " + (error as Error).message
          );
        }
      }
    );

    // Command: Show output channel
    const showOutputChannelCommand = vscode.commands.registerCommand(
      "vulnzap.showOutputChannel",
      () => {
        Logger.info("Show output channel command called");
        Logger.show();
      }
    );

    console.log("VulnZap: All commands registered successfully");

    // Configuration change listener
    const configChangeListener = vscode.workspace.onDidChangeConfiguration(
      (event) => {
        if (event.affectsConfiguration("vulnzap.enabled")) {
          isEnabled = vscode.workspace
            .getConfiguration("vulnzap")
            .get("enabled", true);
          updateStatusBar();

          if (!isEnabled) {
            diagnosticProvider.clearAll();
          }
        }

        if (event.affectsConfiguration("vulnzap.enableDebugLogging")) {
          const config = vscode.workspace.getConfiguration("vulnzap");
          const debugEnabled = config.get("enableDebugLogging", false);
          Logger.setDebugMode(debugEnabled);
        }
      }
    );

    async function scanDocument(
      document: vscode.TextDocument,
      forceShow: boolean = false
    ) {
      try {
        const config = vscode.workspace.getConfiguration("vulnzap");
        const maxFileSize = config.get<number>("maxFileSizeBytes", 1000000);
        const maxFileLines = config.get<number>("maxFileLines", 2000);
        const maxIssues = config.get<number>("maxIssuesPerFile", 100);
        const fileSize = Buffer.byteLength(document.getText(), "utf8");
        const lineCount = document.lineCount;

        if (fileSize > maxFileSize || lineCount > maxFileLines) {
          vscode.window.showWarningMessage(
            `VulnZap: File too large to scan (>${maxFileSize} bytes or >${maxFileLines} lines). Skipping scan.`
          );
          Logger.warn(
            `Skipping scan for large file: ${document.uri.fsPath} (${fileSize} bytes, ${lineCount} lines)`
          );
          updateStatusBar();
          return;
        }

        Logger.info("=== VULNZAP SCAN STARTING ===");
        Logger.info("Document:", document.uri.fsPath);
        if (fileSize > 0.5 * maxFileSize || lineCount > 0.5 * maxFileLines) {
          updateStatusBar("scanning");
          vscode.window.setStatusBarMessage(
            "$(loading~spin) VulnZap: Scanning large file...",
            3000
          );
        } else {
          updateStatusBar("scanning");
        }

        let issues = await codebaseSecurityAnalyzer.analyzeDocument(document);
        Logger.info(`Full issues: ${JSON.stringify(issues)}`);
        if (issues.length > maxIssues) {
          issues = issues.slice(0, maxIssues);
          vscode.window.showInformationMessage(
            `VulnZap: Too many issues found in this file. Only the first ${maxIssues} are shown.`
          );
        }

        Logger.info("=== SCAN COMPLETED ===");
        Logger.info("Found issues:", issues.length);
        diagnosticProvider.updateDiagnostics(document, issues);
        securityViewProvider.updateSecurityIssues(document, issues);
        updateStatusBar(); // Reset to normal status

        // Add notification for debugging
        if (issues.length > 0) {
          const issueDetails = issues
            .map(
              (issue) =>
                `Line ${issue.line + 1}: ${issue.message.substring(0, 50)}...`
            )
            .join("; ");
        } else {
          vscode.window.showInformationMessage(
            "✅ VulnZap: No security issues found"
          );
        }

        if (forceShow && issues.length > 0) {
          vscode.window.showInformationMessage(
            `Found ${issues.length} security issue${
              issues.length === 1 ? "" : "s"
            }`
          );
        }
      } catch (error) {
        Logger.error("=== SCAN ERROR ===", error as Error);
        updateStatusBar(); // Reset to normal status
        if (forceShow) {
          vscode.window.showErrorMessage("Error during security scan");
        }
      }
    }

    function isSupportedLanguage(languageId: string): boolean {
      const supportedLanguages = [
        "javascript",
        "typescript",
        "python",
        "java",
        "php",
        "csharp",
      ];
      return supportedLanguages.includes(languageId);
    }

    function updateLoginContext() {
      const session = context.globalState.get("vulnzapSession");
      vscode.commands.executeCommand(
        "setContext",
        "vulnzap.loggedIn",
        !!session
      );
      vscode.commands.executeCommand(
        "setContext",
        "vulnzap.notLoggedIn",
        !session
      );
    }

    function updateStatusBar(status: string = "") {
      // Check if user is logged in
      const session = context.globalState.get("vulnzapSession");

      if (!session) {
        // User not logged in
        statusBarItem.text = "$(shield) VulnZap: Sign In Required";
        statusBarItem.tooltip =
          "Click to sign in to VulnZap and start security analysis.";
        statusBarItem.backgroundColor = new vscode.ThemeColor(
          "statusBarItem.warningBackground"
        );
        statusBarItem.command = "vulnzap.login";
      } else if (isEnabled) {
        // User logged in and enabled
        if (status === "quick-scan") {
          statusBarItem.text = "$(shield) Security: Quick Scan";
          statusBarItem.tooltip =
            "Quick security scan completed. Full analysis in progress...";
          statusBarItem.backgroundColor = undefined;
        } else if (status === "scanning") {
          statusBarItem.text = "$(loading~spin) Security: Scanning...";
          statusBarItem.tooltip = "Text-based security analysis in progress...";
          statusBarItem.backgroundColor = undefined;
        } else {
          statusBarItem.text = "$(shield) Security: ON";
          statusBarItem.tooltip =
            "Security review is enabled with text-based analysis. Click to disable.";
          statusBarItem.backgroundColor = undefined;
        }
        statusBarItem.command = "vulnzap.toggle";
      } else {
        // User logged in but disabled
        statusBarItem.text = "$(shield) Security: OFF";
        statusBarItem.tooltip = "Security review is disabled. Click to enable.";
        statusBarItem.backgroundColor = new vscode.ThemeColor(
          "statusBarItem.warningBackground"
        );
        statusBarItem.command = "vulnzap.toggle";
      }
    }

    // Register disposables
    context.subscriptions.push(
      statusBarItem,
      documentSaveListener,
      activeEditorChangeListener,
      enableCommand,
      disableCommand,
      toggleCommand,
      scanFileCommand,
      selectApiProviderCommand,
      configureApiKeysCommand,
      toggleASTCommand,
      refreshSecurityViewCommand,
      clearAllIssuesCommand,
      scanWorkspaceCommand,
      loginCommand,
      logoutCommand,

      scanDependenciesCommand,
      forceDependencyScanCommand,
      dependencyCacheStatsCommand,
      cleanDependencyCacheCommand,
      updateDependencyToVersionCommand,
      showUpdateCommandCmd,
      fixAllDependenciesCommand,
      showOutputChannelCommand,
      configChangeListener,
      diagnosticProvider
    );

    // Initial scan if there's an active editor
    const activeEditor = vscode.window.activeTextEditor;
    if (
      isEnabled &&
      activeEditor &&
      isSupportedLanguage(activeEditor.document.languageId)
    ) {
      Logger.debug("Active editor found, performing initial scan");
      scanDocument(activeEditor.document);
    } else {
      Logger.debug(
        "No active editor or unsupported language, skipping initial scan"
      );
    }

    // Initial dependency scan on startup (if enabled)
    const dependencyScanOnStartup = vscode.workspace
      .getConfiguration("vulnzap")
      .get<boolean>("dependencyScanOnStartup", true);
    if (dependencyScanOnStartup) {
      setTimeout(async () => {
        try {
          Logger.info("Performing initial dependency scan...");
          await dependencyScanner.scanWorkspaceDependencies();
        } catch (error) {
          Logger.error("Error during initial dependency scan:", error as Error);
        }
      }, 2000); // Wait 2 seconds after activation to avoid blocking startup
    }

    // After activation, call providerManager.setContext(context) if needed
    const providerManager = new APIProviderManager(context);
    providerManager.setContext(context);
  } catch (error) {
    Logger.error("Error in activate:", error as Error);
    vscode.window.showErrorMessage(
      "Error activating the extension: " + (error as Error).message
    );
  }
}

export function deactivate() {
  Logger.info("VulnZap deactivated");
  Logger.dispose();
}

async function configureVulnZap(config: vscode.WorkspaceConfiguration) {
  const apiKey = await vscode.window.showInputBox({
    prompt: "Enter your VulnZap API key",
    password: true,
    value: config.get("vulnzapApiKey", ""),
    placeHolder: "Your VulnZap API key",
  });

  if (apiKey !== undefined) {
    await config.update(
      "vulnzapApiKey",
      apiKey,
      vscode.ConfigurationTarget.Global
    );
  }

  const apiUrl = await vscode.window.showInputBox({
    prompt: "Enter VulnZap API URL",
    value: config.get("vulnzapApiUrl", "https://api.vulnzap.com"),
    placeHolder: "https://api.vulnzap.com",
  });

  if (apiUrl !== undefined) {
    await config.update(
      "vulnzapApiUrl",
      apiUrl,
      vscode.ConfigurationTarget.Global
    );
  }
}

// async function configureGoogleSearch(config: vscode.WorkspaceConfiguration) {
//     const searchApiKey = await vscode.window.showInputBox({
//         prompt: 'Enter your Google Search API key (optional)',
//         password: true,
//         value: config.get('googleSearchApiKey', ''),
//         placeHolder: 'Your Google Custom Search API key'
//     });

//     if (searchApiKey !== undefined) {
//         await config.update('googleSearchApiKey', searchApiKey, vscode.ConfigurationTarget.Global);
//     }

//     const searchEngineId = await vscode.window.showInputBox({
//         prompt: 'Enter your Google Custom Search Engine ID (optional)',
//         value: config.get('googleSearchEngineId', ''),
//         placeHolder: 'Your Custom Search Engine ID'
//     });

//     if (searchEngineId !== undefined) {
//         await config.update('googleSearchEngineId', searchEngineId, vscode.ConfigurationTarget.Global);
//     }
// }
