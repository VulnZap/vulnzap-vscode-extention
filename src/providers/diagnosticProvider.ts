import * as vscode from "vscode";
import { Logger } from "../utils/logger";

// Simple security issue interface for compatibility
interface SecurityIssue {
  line: number;
  column: number;
  endLine: number;
  endColumn: number;
  message: string;
  severity: vscode.DiagnosticSeverity;
  code: string;
  suggestion?: string;
  confidence?: number;
  cve?: string[];
  searchResults?: string[];
  relatedCode?: any[];
  similarVulnerabilities?: any[];
}

/**
 * Manages diagnostic information for security vulnerabilities in VS Code
 * Provides real-time feedback through squiggly underlines and Problems panel
 */
export class DiagnosticProvider {
  private diagnosticCollection: vscode.DiagnosticCollection;
  private context: vscode.ExtensionContext;
  private securityWebviewProvider?: any;
  private documentChangeListener?: vscode.Disposable;
  private documentsWithDiagnostics: Set<string> = new Set();

  constructor(context: vscode.ExtensionContext) {
    this.context = context;
    this.diagnosticCollection =
      vscode.languages.createDiagnosticCollection("vulnzap-security");

    // Set up document change listener
    this.setupDocumentChangeListener();
  }

  /**
   * Sets up the document change listener to automatically clear diagnostics
   * when lines containing those diagnostics are deleted
   */
  private setupDocumentChangeListener(): void {
    this.documentChangeListener = vscode.workspace.onDidChangeTextDocument(
      (event) => {
        const documentUri = event.document.uri.toString();

        // Only process documents that have diagnostics
        if (!this.documentsWithDiagnostics.has(documentUri)) {
          return;
        }

        // Check each content change for deletions
        for (const change of event.contentChanges) {
          if (this.isDeletion(change)) {
            this.handleLineDeletion(event.document, change);
          }
        }
      }
    );
  }

  /**
   * Checks if a content change represents a deletion
   */
  private isDeletion(change: vscode.TextDocumentContentChangeEvent): boolean {
    return change.text === "" && change.rangeLength > 0;
  }

  /**
   * Handles line deletions by clearing diagnostics that fall within the deleted range
   */
  private handleLineDeletion(
    document: vscode.TextDocument,
    change: vscode.TextDocumentContentChangeEvent
  ): void {
    const deletionRange = change.range;
    const currentDiagnostics = this.getDiagnostics(document);

    if (currentDiagnostics.length === 0) {
      return;
    }

    Logger.debug(
      `Processing deletion in ${document.uri.fsPath} at lines ${deletionRange.start.line}-${deletionRange.end.line}`
    );

    // Find diagnostics that should be cleared and those that should be adjusted
    const { diagnosticsToKeep, diagnosticsToAdjust } =
      this.categorizeDiagnostics(currentDiagnostics, deletionRange);

    // Adjust line numbers for remaining diagnostics
    const adjustedDiagnostics = this.adjustDiagnosticLineNumbers(
      diagnosticsToAdjust,
      deletionRange
    );

    // Combine diagnostics to keep with adjusted diagnostics
    const finalDiagnostics = [...diagnosticsToKeep, ...adjustedDiagnostics];

    // Update the diagnostic collection
    this.diagnosticCollection.set(document.uri, finalDiagnostics);

    Logger.debug(
      `Updated diagnostics: ${currentDiagnostics.length} -> ${
        finalDiagnostics.length
      } (${currentDiagnostics.length - finalDiagnostics.length} cleared)`
    );

    // Update security webview if available
    if (
      this.securityWebviewProvider &&
      currentDiagnostics.length !== finalDiagnostics.length
    ) {
      this.securityWebviewProvider.refresh();
    }
  }

  /**
   * Categorizes diagnostics based on their relationship to the deletion range
   */
  private categorizeDiagnostics(
    diagnostics: readonly vscode.Diagnostic[],
    deletionRange: vscode.Range
  ): {
    diagnosticsToKeep: vscode.Diagnostic[];
    diagnosticsToAdjust: vscode.Diagnostic[];
  } {
    const diagnosticsToKeep: vscode.Diagnostic[] = [];
    const diagnosticsToAdjust: vscode.Diagnostic[] = [];

    for (const diagnostic of diagnostics) {
      if (this.isDiagnosticInDeletedRange(diagnostic, deletionRange)) {
        // This diagnostic was deleted, don't keep it
        Logger.debug(
          `Clearing diagnostic: ${diagnostic.message} at line ${diagnostic.range.start.line}`
        );
      } else if (diagnostic.range.start.line > deletionRange.end.line) {
        // This diagnostic is after the deletion, needs line number adjustment
        diagnosticsToAdjust.push(diagnostic);
      } else {
        // This diagnostic is before the deletion, keep as-is
        diagnosticsToKeep.push(diagnostic);
      }
    }

    return { diagnosticsToKeep, diagnosticsToAdjust };
  }

  /**
   * Checks if a diagnostic falls within the deleted range
   */
  private isDiagnosticInDeletedRange(
    diagnostic: vscode.Diagnostic,
    deletionRange: vscode.Range
  ): boolean {
    const diagStart = diagnostic.range.start.line;
    const diagEnd = diagnostic.range.end.line;
    const deleteStart = deletionRange.start.line;
    const deleteEnd = deletionRange.end.line;

    // Check if diagnostic is completely within the deleted range
    return diagStart >= deleteStart && diagEnd <= deleteEnd;
  }

  /**
   * Adjusts line numbers for diagnostics that come after the deletion
   */
  private adjustDiagnosticLineNumbers(
    diagnostics: vscode.Diagnostic[],
    deletionRange: vscode.Range
  ): vscode.Diagnostic[] {
    const linesDeleted = deletionRange.end.line - deletionRange.start.line;

    if (linesDeleted === 0) {
      return diagnostics; // No line adjustment needed for same-line deletions
    }

    return diagnostics.map((diagnostic) => {
      const newStartLine = Math.max(
        0,
        diagnostic.range.start.line - linesDeleted
      );
      const newEndLine = Math.max(0, diagnostic.range.end.line - linesDeleted);

      const newRange = new vscode.Range(
        new vscode.Position(newStartLine, diagnostic.range.start.character),
        new vscode.Position(newEndLine, diagnostic.range.end.character)
      );

      const newDiagnostic = new vscode.Diagnostic(
        newRange,
        diagnostic.message,
        diagnostic.severity
      );

      // Copy other properties
      newDiagnostic.code = diagnostic.code;
      newDiagnostic.source = diagnostic.source;
      newDiagnostic.relatedInformation = diagnostic.relatedInformation;

      return newDiagnostic;
    });
  }

  /**
   * Links this provider with the security view for synchronized updates
   */
  setSecurityWebviewProvider(provider: any): void {
    this.securityWebviewProvider = provider;
  }

  /**
   * Updates diagnostics for a specific document
   */
  updateDiagnostics(
    document: vscode.TextDocument,
    issues: SecurityIssue[]
  ): void {
    Logger.debug(
      `Updating diagnostics for ${document.uri.fsPath} with ${issues.length} issues`
    );

    const diagnostics: vscode.Diagnostic[] = issues.map((issue) => {
      const range = new vscode.Range(
        new vscode.Position(Math.max(0, issue.line), Math.max(0, issue.column)),
        new vscode.Position(
          Math.max(0, issue.endLine),
          Math.max(0, issue.endColumn)
        )
      );

      const diagnostic = new vscode.Diagnostic(
        range,
        issue.message,
        issue.severity
      );
      diagnostic.code = issue.code;
      diagnostic.source = "VulnZap";

      // Add additional information for hover tooltips
      if (issue.suggestion) {
        diagnostic.relatedInformation = [
          new vscode.DiagnosticRelatedInformation(
            new vscode.Location(document.uri, range),
            `Suggestion: ${issue.suggestion}`
          ),
        ];
      }

      return diagnostic;
    });

    this.diagnosticCollection.set(document.uri, diagnostics);

    // Track documents with diagnostics for the change listener
    const documentUri = document.uri.toString();
    if (diagnostics.length > 0) {
      this.documentsWithDiagnostics.add(documentUri);
    } else {
      this.documentsWithDiagnostics.delete(documentUri);
    }

    // Update security webview with the new issues
    if (this.securityWebviewProvider) {
      this.securityWebviewProvider.updateIssuesFromDiagnostics(
        document.uri,
        diagnostics
      );
    }

    Logger.debug(
      `Set ${diagnostics.length} diagnostics for ${document.uri.fsPath}`
    );
  }

  /**
   * Clears diagnostics for a specific document
   */
  clearDiagnostics(document: vscode.TextDocument): void {
    this.diagnosticCollection.set(document.uri, []);
    // Remove from tracking set
    this.documentsWithDiagnostics.delete(document.uri.toString());
  }

  /**
   * Clears all diagnostics
   */
  clearAll(): void {
    this.diagnosticCollection.clear();
    // Clear tracking set
    this.documentsWithDiagnostics.clear();
  }

  /**
   * Gets current diagnostics for a document
   */
  getDiagnostics(document: vscode.TextDocument): readonly vscode.Diagnostic[] {
    return this.diagnosticCollection.get(document.uri) || [];
  }

  /**
   * Disposes of the diagnostic provider
   */
  dispose(): void {
    this.diagnosticCollection.dispose();
    // Dispose of document change listener
    if (this.documentChangeListener) {
      this.documentChangeListener.dispose();
    }
  }
}
