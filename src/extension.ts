import * as vscode from "vscode";
import { SecurityAnalyzer } from "./securityAnalyzer";
import { DiagnosticProvider } from "./diagnosticProvider";
import { APIProviderManager } from "./apiProviders";
import { SecurityViewProvider } from "./securityViewProvider";

export function activate(context: vscode.ExtensionContext) {
  try {
    const securityAnalyzer = new SecurityAnalyzer();
    const diagnosticProvider = new DiagnosticProvider(context);
    const securityViewProvider = new SecurityViewProvider(context);

    // Register the tree data provider
    vscode.window.registerTreeDataProvider(
      "vulnzap.securityView",
      securityViewProvider
    );

    // Link diagnostic provider with security view provider
    diagnosticProvider.setSecurityViewProvider(securityViewProvider);

    let isEnabled = vscode.workspace
      .getConfiguration("vulnzap")
      .get("enabled", true);
    let scanTimeout: NodeJS.Timeout | undefined;

    // Status bar item
    const statusBarItem = vscode.window.createStatusBarItem(
      vscode.StatusBarAlignment.Right,
      100
    );
    statusBarItem.command = "vulnzap.toggle";
    updateStatusBar();
    statusBarItem.show();

    // Document change listener
    const documentChangeListener = vscode.workspace.onDidChangeTextDocument(
      async (event) => {
        if (!isEnabled) return;

        const document = event.document;
        if (!isSupportedLanguage(document.languageId)) return;

        // Debounce the scanning
        if (scanTimeout) {
          clearTimeout(scanTimeout);
        }

        const delay = vscode.workspace
          .getConfiguration("vulnzap")
          .get("scanDelay", 1000);
        const enableFastScan = vscode.workspace
          .getConfiguration("vulnzap")
          .get("enableFastScan", true);

        // Show immediate basic feedback if fast scan is enabled
        if (enableFastScan) {
          // Quick pattern-based scan (immediate feedback)
          setTimeout(async () => {
            const basicIssues = await securityAnalyzer.fallbackToBasicAnalysis(
              document
            );
            if (basicIssues.length > 0) {
              diagnosticProvider.updateDiagnostics(document, basicIssues);
              updateStatusBar("quick-scan");
            }
          }, 100); // Near-instant feedback
        }

        scanTimeout = setTimeout(async () => {
          await scanDocument(document);
        }, delay);
      }
    );

    // Active editor change listener
    const activeEditorChangeListener =
      vscode.window.onDidChangeActiveTextEditor(async (editor) => {
        if (!isEnabled || !editor) return;

        const document = editor.document;
        if (!isSupportedLanguage(document.languageId)) return;

        await scanDocument(document);
      });

    // Commands
    console.log("VulnZap: Registering commands...");

    const enableCommand = vscode.commands.registerCommand(
      "vulnzap.enable",
      () => {
        console.log("VulnZap: Enable command called");
        isEnabled = true;
        vscode.workspace
          .getConfiguration("vulnzap")
          .update("enabled", true, true);
        updateStatusBar();
        vscode.window.showInformationMessage("Security review enabled");

        // Scan current file if available
        const activeEditor = vscode.window.activeTextEditor;
        if (activeEditor) {
          scanDocument(activeEditor.document);
        }
      }
    );

    const disableCommand = vscode.commands.registerCommand(
      "vulnzap.disable",
      () => {
        console.log("VulnZap: Disable command called");
        isEnabled = false;
        vscode.workspace
          .getConfiguration("vulnzap")
          .update("enabled", false, true);
        updateStatusBar();
        diagnosticProvider.clearAll();
        securityViewProvider.clearAllSecurityIssues();
        vscode.window.showInformationMessage("Security review disabled");
      }
    );

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

    const selectApiProviderCommand = vscode.commands.registerCommand(
      "vulnzap.selectApiProvider",
      async () => {
        console.log("VulnZap: Select API provider command called");
        try {
          const providerManager = new APIProviderManager(context);

          const providers = providerManager.getAllProviders();
          const options = providers.map((provider) => ({
            label: provider.displayName,
            description: provider.isConfigured()
              ? "✓ Configured"
              : "⚠ Not configured",
            detail: provider.name,
            provider: provider,
          }));

          const selection = await vscode.window.showQuickPick(options, {
            placeHolder:
              "Select your preferred AI provider for security analysis",
            matchOnDescription: true,
            matchOnDetail: true,
          });

          if (selection) {
            const config = vscode.workspace.getConfiguration("vulnzap");
            await config.update(
              "apiProvider",
              selection.provider.name,
              vscode.ConfigurationTarget.Global
            );

            if (selection.provider.isConfigured()) {
              vscode.window.showInformationMessage(
                `✅ ${selection.provider.displayName} selected and ready to use!`
              );
            } else {
              const configNow = await vscode.window.showQuickPick(
                ["Yes", "No"],
                {
                  placeHolder: `${selection.provider.displayName} is not configured. Configure it now?`,
                }
              );
              if (configNow === "Yes") {
                vscode.commands.executeCommand("vulnzap.configureApiKeys");
              }
            }
          }
        } catch (error) {
          console.error("VulnZap: Error in selectApiProvider:", error);
          vscode.window.showErrorMessage(
            "Error selecting API provider: " + (error as Error).message
          );
        }
      }
    );

    const configureApiKeysCommand = vscode.commands.registerCommand(
      "vulnzap.configureApiKeys",
      async () => {
        console.log("VulnZap: Configure API keys command called");
        try {
          const config = vscode.workspace.getConfiguration("vulnzap");
          const selectedProvider = config.get<string>("apiProvider", "gemini");

          const providerManager = new APIProviderManager(context);
          const provider = providerManager.getProvider(selectedProvider);

          if (!provider) {
            vscode.window.showErrorMessage(
              "Invalid API provider selected. Please select a provider first."
            );
            return;
          }

          // Configure based on selected provider
          switch (provider.name) {
            case "openai":
              await configureOpenAI(config);
              break;
            case "gemini":
              await configureGemini(config);
              break;
            case "openrouter":
              await configureOpenRouter(config);
              break;
            case "vulnzap":
              await configureVulnZap(config);
              break;
            default:
              vscode.window.showErrorMessage("Unknown provider selected");
              return;
          }

          vscode.window.showInformationMessage(
            `✅ ${provider.displayName} configured successfully!`
          );
        } catch (error) {
          console.error("VulnZap: Error in configureApiKeys:", error);
          vscode.window.showErrorMessage(
            "Error configuring API keys: " + (error as Error).message
          );
        }
      }
    );

    // Security View Commands
    const refreshSecurityViewCommand = vscode.commands.registerCommand(
      "vulnzap.refreshSecurityView",
      () => {
        console.log("VulnZap: Refresh security view command called");
        securityViewProvider.refresh();
        vscode.window.showInformationMessage("Security view refreshed");
      }
    );

    const clearAllIssuesCommand = vscode.commands.registerCommand(
      "vulnzap.clearAllIssues",
      () => {
        console.log("VulnZap: Clear all issues command called");
        diagnosticProvider.clearAll();
        securityViewProvider.clearAllSecurityIssues();
        vscode.window.showInformationMessage("All security issues cleared");
      }
    );

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
            const files = await vscode.workspace.findFiles(
              `**/*{${supportedExtensions.join(",")}}`,
              "**/node_modules/**"
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
              if (urlState === state && access_token) {
                // Save session in global state
                const session = {
                  access_token,
                  refresh_token,
                  expires_at: expires_at ? parseInt(expires_at) : 0,
                  apiKey,
                };
                await context.globalState.update("vulnzapSession", session);
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
          // 5. Refresh the security view
          vscode.commands.executeCommand("vulnzap.refreshSecurityView");
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
      }
    );

    async function scanDocument(
      document: vscode.TextDocument,
      forceShow: boolean = false
    ) {
      try {
        updateStatusBar("scanning");
        const issues = await securityAnalyzer.analyzeDocument(document);
        diagnosticProvider.updateDiagnostics(document, issues);
        securityViewProvider.updateSecurityIssues(document, issues);
        updateStatusBar(); // Reset to normal status

        if (forceShow && issues.length > 0) {
          vscode.window.showInformationMessage(
            `Found ${issues.length} security issue${
              issues.length === 1 ? "" : "s"
            }`
          );
        }
      } catch (error) {
        console.error("Error scanning document:", error);
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

    function updateStatusBar(status: string = "") {
      if (isEnabled) {
        if (status === "quick-scan") {
          statusBarItem.text = "$(shield) Security: Quick Scan";
          statusBarItem.tooltip =
            "Quick security scan completed. Full AI analysis in progress...";
          statusBarItem.backgroundColor = undefined;
        } else if (status === "scanning") {
          statusBarItem.text = "$(loading~spin) Security: Scanning...";
          statusBarItem.tooltip = "AI security analysis in progress...";
          statusBarItem.backgroundColor = undefined;
        } else {
          statusBarItem.text = "$(shield) Security: ON";
          statusBarItem.tooltip =
            "Security review is enabled. Click to disable.";
          statusBarItem.backgroundColor = undefined;
        }
      } else {
        statusBarItem.text = "$(shield) Security: OFF";
        statusBarItem.tooltip = "Security review is disabled. Click to enable.";
        statusBarItem.backgroundColor = new vscode.ThemeColor(
          "statusBarItem.warningBackground"
        );
      }
    }

    // Register disposables
    context.subscriptions.push(
      statusBarItem,
      documentChangeListener,
      activeEditorChangeListener,
      enableCommand,
      disableCommand,
      toggleCommand,
      scanFileCommand,
      selectApiProviderCommand,
      configureApiKeysCommand,
      refreshSecurityViewCommand,
      clearAllIssuesCommand,
      scanWorkspaceCommand,
      configChangeListener,
      diagnosticProvider,
      loginCommand
    );

    // Initial scan if there's an active editor
    const activeEditor = vscode.window.activeTextEditor;
    if (
      isEnabled &&
      activeEditor &&
      isSupportedLanguage(activeEditor.document.languageId)
    ) {
      scanDocument(activeEditor.document);
    }

    // After activation, call providerManager.setContext(context) if needed
    const providerManager = new APIProviderManager(context);
    providerManager.setContext(context);
  } catch (error) {
    console.error("VulnZap: Error in activate:", error);
    vscode.window.showErrorMessage(
      "Error activating the extension: " + (error as Error).message
    );
  }
}

export function deactivate() {
  console.log("VulnZap deactivated");
}

async function configureOpenAI(config: vscode.WorkspaceConfiguration) {
  const apiKey = await vscode.window.showInputBox({
    prompt: "Enter your OpenAI API key",
    password: true,
    value: config.get("openaiApiKey", ""),
    placeHolder: "sk-...",
  });

  if (apiKey !== undefined) {
    await config.update(
      "openaiApiKey",
      apiKey,
      vscode.ConfigurationTarget.Global
    );
  }

  const model = await vscode.window.showQuickPick(
    [
      { label: "GPT-4", value: "gpt-4" },
      { label: "GPT-4 Turbo", value: "gpt-4-turbo" },
      { label: "GPT-3.5 Turbo", value: "gpt-3.5-turbo" },
    ],
    {
      placeHolder: "Select OpenAI model",
    }
  );

  if (model) {
    await config.update(
      "openaiModel",
      model.value,
      vscode.ConfigurationTarget.Global
    );
  }
}

async function configureGemini(config: vscode.WorkspaceConfiguration) {
  const apiKey = await vscode.window.showInputBox({
    prompt: "Enter your Google Gemini API key",
    password: true,
    value: config.get("geminiApiKey", ""),
    placeHolder: "Your Gemini API key",
  });

  if (apiKey !== undefined) {
    await config.update(
      "geminiApiKey",
      apiKey,
      vscode.ConfigurationTarget.Global
    );
  }
}

async function configureOpenRouter(config: vscode.WorkspaceConfiguration) {
  const apiKey = await vscode.window.showInputBox({
    prompt: "Enter your OpenRouter API key",
    password: true,
    value: config.get("openrouterApiKey", ""),
    placeHolder: "sk-or-...",
  });

  if (apiKey !== undefined) {
    await config.update(
      "openrouterApiKey",
      apiKey,
      vscode.ConfigurationTarget.Global
    );
  }

  const model = await vscode.window.showQuickPick(
    [
      {
        label: "Claude 3 Haiku (Fast & Cheap)",
        value: "anthropic/claude-3-haiku",
      },
      {
        label: "Claude 3 Sonnet (Balanced)",
        value: "anthropic/claude-3-sonnet",
      },
      {
        label: "Claude 3 Opus (Most Capable)",
        value: "anthropic/claude-3-opus",
      },
      { label: "GPT-4", value: "openai/gpt-4" },
      { label: "GPT-3.5 Turbo", value: "openai/gpt-3.5-turbo" },
      { label: "Llama 2 70B", value: "meta-llama/llama-2-70b-chat" },
      { label: "Mixtral 8x7B", value: "mistralai/mixtral-8x7b-instruct" },
    ],
    {
      placeHolder: "Select model to use",
    }
  );

  if (model) {
    await config.update(
      "openrouterModel",
      model.value,
      vscode.ConfigurationTarget.Global
    );
  }
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
