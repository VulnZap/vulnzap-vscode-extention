import * as vscode from 'vscode';

/**
 * Centralized logging utility for VulnZap extension
 * Ensures logs are visible in the Extension Host output channel
 */
export class Logger {
    private static outputChannel: vscode.OutputChannel;
    private static isDebugMode: boolean = false;

    /**
     * Initialize the logger with VS Code output channel
     * Call this during extension activation
     */
    public static initialize(): void {
        this.outputChannel = vscode.window.createOutputChannel('VulnZap');
        
        // Check if debug mode is enabled in configuration
        const config = vscode.workspace.getConfiguration('vulnzap');
        this.isDebugMode = config.get('enableDebugLogging', false);
        
        this.info('VulnZap Logger initialized');
    }

    /**
     * Log an info message
     */
    public static info(message: string, ...args: any[]): void {
        const formattedMessage = this.formatMessage('INFO', message, args);
        this.outputChannel.appendLine(formattedMessage);
        
        // Also log to console for VS Code extension development
        console.log(`[VulnZap] ${message}`, ...args);
    }

    /**
     * Log a warning message
     */
    public static warn(message: string, ...args: any[]): void {
        const formattedMessage = this.formatMessage('WARN', message, args);
        this.outputChannel.appendLine(formattedMessage);
        
        // Also log to console
        console.warn(`[VulnZap] ${message}`, ...args);
    }

    /**
     * Log an error message
     */
    public static error(message: string, error?: Error, ...args: any[]): void {
        const errorDetails = error ? ` - ${error.message}\n${error.stack}` : '';
        const formattedMessage = this.formatMessage('ERROR', message + errorDetails, args);
        this.outputChannel.appendLine(formattedMessage);
        
        // Also log to console
        console.error(`[VulnZap] ${message}`, error, ...args);
    }

    /**
     * Log a debug message (only shown if debug mode is enabled)
     */
    public static debug(message: string, ...args: any[]): void {
        if (!this.isDebugMode) {
            return;
        }
        
        const formattedMessage = this.formatMessage('DEBUG', message, args);
        this.outputChannel.appendLine(formattedMessage);
        
        // Also log to console in debug mode
        console.log(`[VulnZap DEBUG] ${message}`, ...args);
    }

    /**
     * Show the output channel (useful for debugging)
     */
    public static show(): void {
        if (this.outputChannel) {
            this.outputChannel.show();
        }
    }

    /**
     * Clear the output channel
     */
    public static clear(): void {
        if (this.outputChannel) {
            this.outputChannel.clear();
        }
    }

    /**
     * Update debug mode setting
     */
    public static setDebugMode(enabled: boolean): void {
        this.isDebugMode = enabled;
        this.info(`Debug logging ${enabled ? 'enabled' : 'disabled'}`);
    }

    /**
     * Dispose of the output channel
     */
    public static dispose(): void {
        if (this.outputChannel) {
            this.outputChannel.dispose();
        }
    }

    /**
     * Format log message with timestamp and level
     */
    private static formatMessage(level: string, message: string, args: any[]): string {
        const timestamp = new Date().toISOString();
        const argsString = args.length > 0 ? ` | Args: ${JSON.stringify(args)}` : '';
        return `[${timestamp}] [${level}] ${message}${argsString}`;
    }
} 