import * as vscode from 'vscode';
import { SecurityAnalyzer } from './securityAnalyzer';
import { DiagnosticProvider } from './diagnosticProvider';

export function activate(context: vscode.ExtensionContext) {
    console.log('Inline Security Reviewer is now active!');

    const securityAnalyzer = new SecurityAnalyzer();
    const diagnosticProvider = new DiagnosticProvider(context);
    
    let isEnabled = vscode.workspace.getConfiguration('inlineSecurityReviewer').get('enabled', true);
    let scanTimeout: NodeJS.Timeout | undefined;

    // Status bar item
    const statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    statusBarItem.command = 'inlineSecurityReviewer.toggle';
    updateStatusBar();
    statusBarItem.show();

    // Document change listener
    const documentChangeListener = vscode.workspace.onDidChangeTextDocument(async (event) => {
        if (!isEnabled) return;
        
        const document = event.document;
        if (!isSupportedLanguage(document.languageId)) return;

        // Debounce the scanning
        if (scanTimeout) {
            clearTimeout(scanTimeout);
        }

        const delay = vscode.workspace.getConfiguration('inlineSecurityReviewer').get('scanDelay', 1000);
        scanTimeout = setTimeout(async () => {
            await scanDocument(document);
        }, delay);
    });

    // Active editor change listener
    const activeEditorChangeListener = vscode.window.onDidChangeActiveTextEditor(async (editor) => {
        if (!isEnabled || !editor) return;
        
        const document = editor.document;
        if (!isSupportedLanguage(document.languageId)) return;
        
        await scanDocument(document);
    });

    // Commands
    const enableCommand = vscode.commands.registerCommand('inlineSecurityReviewer.enable', () => {
        isEnabled = true;
        vscode.workspace.getConfiguration('inlineSecurityReviewer').update('enabled', true, true);
        updateStatusBar();
        vscode.window.showInformationMessage('Security review enabled');
        
        // Scan current file if available
        const activeEditor = vscode.window.activeTextEditor;
        if (activeEditor) {
            scanDocument(activeEditor.document);
        }
    });

    const disableCommand = vscode.commands.registerCommand('inlineSecurityReviewer.disable', () => {
        isEnabled = false;
        vscode.workspace.getConfiguration('inlineSecurityReviewer').update('enabled', false, true);
        updateStatusBar();
        diagnosticProvider.clearAll();
        vscode.window.showInformationMessage('Security review disabled');
    });

    const toggleCommand = vscode.commands.registerCommand('inlineSecurityReviewer.toggle', () => {
        if (isEnabled) {
            vscode.commands.executeCommand('inlineSecurityReviewer.disable');
        } else {
            vscode.commands.executeCommand('inlineSecurityReviewer.enable');
        }
    });

    const scanFileCommand = vscode.commands.registerCommand('inlineSecurityReviewer.scanFile', async () => {
        const activeEditor = vscode.window.activeTextEditor;
        if (!activeEditor) {
            vscode.window.showWarningMessage('No active file to scan');
            return;
        }
        
        await scanDocument(activeEditor.document, true);
        vscode.window.showInformationMessage('Security scan completed');
    });

    const selectApiProviderCommand = vscode.commands.registerCommand('inlineSecurityReviewer.selectApiProvider', async () => {
        const { APIProviderManager } = await import('./apiProviders');
        const providerManager = new APIProviderManager();
        
        const providers = providerManager.getAllProviders();
        const options = providers.map(provider => ({
            label: provider.displayName,
            description: provider.isConfigured() ? '✓ Configured' : '⚠ Not configured',
            detail: provider.name,
            provider: provider
        }));

        const selection = await vscode.window.showQuickPick(options, {
            placeHolder: 'Select your preferred AI provider for security analysis',
            matchOnDescription: true,
            matchOnDetail: true
        });

        if (selection) {
            const config = vscode.workspace.getConfiguration('inlineSecurityReviewer');
            await config.update('apiProvider', selection.provider.name, vscode.ConfigurationTarget.Global);
            
            if (selection.provider.isConfigured()) {
                vscode.window.showInformationMessage(`✅ ${selection.provider.displayName} selected and ready to use!`);
            } else {
                const configNow = await vscode.window.showQuickPick(['Yes', 'No'], {
                    placeHolder: `${selection.provider.displayName} is not configured. Configure it now?`
                });
                if (configNow === 'Yes') {
                    vscode.commands.executeCommand('inlineSecurityReviewer.configureApiKeys');
                }
            }
        }
    });

    const configureApiKeysCommand = vscode.commands.registerCommand('inlineSecurityReviewer.configureApiKeys', async () => {
        const config = vscode.workspace.getConfiguration('inlineSecurityReviewer');
        const selectedProvider = config.get<string>('apiProvider', 'gemini');
        
        const { APIProviderManager } = await import('./apiProviders');
        const providerManager = new APIProviderManager();
        const provider = providerManager.getProvider(selectedProvider);
        
        if (!provider) {
            vscode.window.showErrorMessage('Invalid API provider selected. Please select a provider first.');
            return;
        }

        // Configure based on selected provider
        switch (provider.name) {
            case 'openai':
                await configureOpenAI(config);
                break;
            case 'gemini':
                await configureGemini(config);
                break;
            case 'openrouter':
                await configureOpenRouter(config);
                break;
            case 'vulnzap':
                await configureVulnZap(config);
                break;
            default:
                vscode.window.showErrorMessage('Unknown provider selected');
                return;
        }
        
        // Optional: Configure search enhancement
        const enableSearch = await vscode.window.showQuickPick(['Yes', 'No'], {
            placeHolder: 'Enable Google Search enhancement for vulnerability research? (Optional)'
        });
        
        if (enableSearch === 'Yes') {
            await configureGoogleSearch(config);
        }
        
        vscode.window.showInformationMessage(`✅ ${provider.displayName} configured successfully!`);
    });
    
    async function configureOpenAI(config: vscode.WorkspaceConfiguration) {
        const apiKey = await vscode.window.showInputBox({
            prompt: 'Enter your OpenAI API key',
            password: true,
            value: config.get('openaiApiKey', ''),
            placeHolder: 'sk-...'
        });
        
        if (apiKey !== undefined) {
            await config.update('openaiApiKey', apiKey, vscode.ConfigurationTarget.Global);
        }
        
        const model = await vscode.window.showQuickPick([
            { label: 'GPT-4', value: 'gpt-4' },
            { label: 'GPT-4 Turbo', value: 'gpt-4-turbo' },
            { label: 'GPT-3.5 Turbo', value: 'gpt-3.5-turbo' }
        ], {
            placeHolder: 'Select OpenAI model'
        });
        
        if (model) {
            await config.update('openaiModel', model.value, vscode.ConfigurationTarget.Global);
        }
    }
    
    async function configureGemini(config: vscode.WorkspaceConfiguration) {
        const apiKey = await vscode.window.showInputBox({
            prompt: 'Enter your Google Gemini API key',
            password: true,
            value: config.get('geminiApiKey', ''),
            placeHolder: 'Your Gemini API key'
        });
        
        if (apiKey !== undefined) {
            await config.update('geminiApiKey', apiKey, vscode.ConfigurationTarget.Global);
        }
    }
    
    async function configureOpenRouter(config: vscode.WorkspaceConfiguration) {
        const apiKey = await vscode.window.showInputBox({
            prompt: 'Enter your OpenRouter API key',
            password: true,
            value: config.get('openrouterApiKey', ''),
            placeHolder: 'sk-or-...'
        });
        
        if (apiKey !== undefined) {
            await config.update('openrouterApiKey', apiKey, vscode.ConfigurationTarget.Global);
        }
        
        const model = await vscode.window.showQuickPick([
            { label: 'Claude 3 Haiku (Fast & Cheap)', value: 'anthropic/claude-3-haiku' },
            { label: 'Claude 3 Sonnet (Balanced)', value: 'anthropic/claude-3-sonnet' },
            { label: 'Claude 3 Opus (Most Capable)', value: 'anthropic/claude-3-opus' },
            { label: 'GPT-4', value: 'openai/gpt-4' },
            { label: 'GPT-3.5 Turbo', value: 'openai/gpt-3.5-turbo' },
            { label: 'Llama 2 70B', value: 'meta-llama/llama-2-70b-chat' },
            { label: 'Mixtral 8x7B', value: 'mistralai/mixtral-8x7b-instruct' }
        ], {
            placeHolder: 'Select model to use'
        });
        
        if (model) {
            await config.update('openrouterModel', model.value, vscode.ConfigurationTarget.Global);
        }
    }
    
    async function configureVulnZap(config: vscode.WorkspaceConfiguration) {
        const apiKey = await vscode.window.showInputBox({
            prompt: 'Enter your VulnZap API key',
            password: true,
            value: config.get('vulnzapApiKey', ''),
            placeHolder: 'Your VulnZap API key'
        });
        
        if (apiKey !== undefined) {
            await config.update('vulnzapApiKey', apiKey, vscode.ConfigurationTarget.Global);
        }
        
        const apiUrl = await vscode.window.showInputBox({
            prompt: 'Enter VulnZap API URL',
            value: config.get('vulnzapApiUrl', 'https://api.vulnzap.com'),
            placeHolder: 'https://api.vulnzap.com'
        });
        
        if (apiUrl !== undefined) {
            await config.update('vulnzapApiUrl', apiUrl, vscode.ConfigurationTarget.Global);
        }
    }
    
    async function configureGoogleSearch(config: vscode.WorkspaceConfiguration) {
        const searchApiKey = await vscode.window.showInputBox({
            prompt: 'Enter your Google Search API key (optional)',
            password: true,
            value: config.get('googleSearchApiKey', ''),
            placeHolder: 'Your Google Custom Search API key'
        });
        
        if (searchApiKey !== undefined) {
            await config.update('googleSearchApiKey', searchApiKey, vscode.ConfigurationTarget.Global);
        }
        
        const searchEngineId = await vscode.window.showInputBox({
            prompt: 'Enter your Google Custom Search Engine ID (optional)',
            value: config.get('googleSearchEngineId', ''),
            placeHolder: 'Your Custom Search Engine ID'
        });
        
        if (searchEngineId !== undefined) {
            await config.update('googleSearchEngineId', searchEngineId, vscode.ConfigurationTarget.Global);
        }
    }

    // Configuration change listener
    const configChangeListener = vscode.workspace.onDidChangeConfiguration((event) => {
        if (event.affectsConfiguration('inlineSecurityReviewer.enabled')) {
            isEnabled = vscode.workspace.getConfiguration('inlineSecurityReviewer').get('enabled', true);
            updateStatusBar();
            
            if (!isEnabled) {
                diagnosticProvider.clearAll();
            }
        }
    });

    async function scanDocument(document: vscode.TextDocument, forceShow: boolean = false) {
        try {
            const issues = await securityAnalyzer.analyzeDocument(document);
            diagnosticProvider.updateDiagnostics(document, issues);
            
            if (forceShow && issues.length > 0) {
                vscode.window.showInformationMessage(
                    `Found ${issues.length} security issue${issues.length === 1 ? '' : 's'}`
                );
            }
        } catch (error) {
            console.error('Error scanning document:', error);
            if (forceShow) {
                vscode.window.showErrorMessage('Error during security scan');
            }
        }
    }

    function isSupportedLanguage(languageId: string): boolean {
        const supportedLanguages = ['javascript', 'typescript', 'python', 'java', 'php', 'csharp'];
        return supportedLanguages.includes(languageId);
    }

    function updateStatusBar() {
        if (isEnabled) {
            statusBarItem.text = "$(shield) Security: ON";
            statusBarItem.tooltip = "Security review is enabled. Click to disable.";
            statusBarItem.backgroundColor = undefined;
        } else {
            statusBarItem.text = "$(shield) Security: OFF";
            statusBarItem.tooltip = "Security review is disabled. Click to enable.";
            statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
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
        configChangeListener,
        diagnosticProvider
    );

    // Initial scan if there's an active editor
    const activeEditor = vscode.window.activeTextEditor;
    if (isEnabled && activeEditor && isSupportedLanguage(activeEditor.document.languageId)) {
        scanDocument(activeEditor.document);
    }
}

export function deactivate() {
    console.log('Inline Security Reviewer deactivated');
}