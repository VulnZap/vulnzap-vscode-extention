import * as vscode from "vscode";
import { Logger } from "../utils/logger";

/**
 * Provides code actions (quick fixes) for VulnZap security vulnerabilities
 * This enables the light bulb functionality when hovering over diagnostic issues
 */
export class VulnZapCodeActionProvider implements vscode.CodeActionProvider {
  public static readonly providedCodeActionKinds = [
    vscode.CodeActionKind.QuickFix,
  ];

  /**
   * Provides code actions for the given document and range
   */
  public provideCodeActions(
    document: vscode.TextDocument,
    range: vscode.Range | vscode.Selection,
    context: vscode.CodeActionContext,
    token: vscode.CancellationToken
  ): vscode.ProviderResult<(vscode.CodeAction | vscode.Command)[]> {
    const actions: vscode.CodeAction[] = [];

    // Only provide actions for VulnZap diagnostics
    const vulnZapDiagnostics = context.diagnostics.filter(
      (diagnostic) => diagnostic.source === "VulnZap"
    );

    for (const diagnostic of vulnZapDiagnostics) {
      const codeAction = this.createFixAction(document, diagnostic);
      if (codeAction) {
        actions.push(codeAction);
      }
    }

    return actions;
  }

  /**
   * Creates a code action for fixing a VulnZap diagnostic
   */
  private createFixAction(
    document: vscode.TextDocument,
    diagnostic: vscode.Diagnostic
  ): vscode.CodeAction | undefined {
    try {
      // Extract the suggested fix from the diagnostic
      const suggestion = this.extractSuggestionFromDiagnostic(diagnostic);
      if (!suggestion) {
        Logger.debug(`No suggestion found for diagnostic: ${diagnostic.message}`);
        return undefined;
      }

      // Parse the suggested code from the markdown
      const suggestedCode = this.extractCodeFromSuggestion(suggestion);
      if (!suggestedCode) {
        Logger.debug(`No code found in suggestion: ${suggestion}`);
        return undefined;
      }

      // Create the code action
      const action = new vscode.CodeAction(
`Fix: ${diagnostic.message}`,
        vscode.CodeActionKind.QuickFix
      );

      action.diagnostics = [diagnostic];
      action.isPreferred = true; // Make this the preferred quick fix

      // Create the edit that will replace the problematic code
      const edit = new vscode.WorkspaceEdit();
      
      // For now, replace the entire line with the suggested fix
      // In the future, we could be more precise about what to replace
      const lineRange = document.lineAt(diagnostic.range.start.line).range;
      const currentLine = document.lineAt(diagnostic.range.start.line).text;
      
      // Try to preserve indentation
      const indentation = this.extractIndentation(currentLine);
      const indentedSuggestedCode = this.applyIndentation(suggestedCode, indentation);
      
      edit.replace(document.uri, lineRange, indentedSuggestedCode);
      action.edit = edit;

      Logger.debug(`Created code action for: ${diagnostic.message}`);
      return action;

    } catch (error) {
      Logger.error("Error creating code action:", error as Error);
      return undefined;
    }
  }

  /**
   * Extracts the suggestion text from a diagnostic
   */
  private extractSuggestionFromDiagnostic(diagnostic: vscode.Diagnostic): string | undefined {
    // Check if there's suggestion data stored in the diagnostic
    if ((diagnostic as any).suggestion) {
      return (diagnostic as any).suggestion;
    }

    // Fallback: Look for suggestion in the diagnostic message
    if (typeof diagnostic.message === 'string') {
const suggestionMatch = diagnostic.message.match(/\*\*Recommended Fix:\*\*([\s\S]*?)(?:\n\n|$)/);
      if (suggestionMatch) {
        return suggestionMatch[1].trim();
      }
    }

    // Check related information for suggestions
    if (diagnostic.relatedInformation) {
      for (const info of diagnostic.relatedInformation) {
        if (info.message.startsWith('Suggestion:')) {
          return info.message.substring('Suggestion:'.length).trim();
        }
      }
    }

    return undefined;
  }

  /**
   * Extracts code from a markdown-formatted suggestion
   */
  private extractCodeFromSuggestion(suggestion: string): string | undefined {
    // Look for code blocks in the suggestion
    const codeBlockMatch = suggestion.match(/```[\s\S]*?\n([\s\S]*?)```/);
    if (codeBlockMatch) {
      return codeBlockMatch[1].trim();
    }

    // If no code block found, treat the entire suggestion as code
    return suggestion.trim();
  }

  /**
   * Extracts indentation from the current line
   */
  private extractIndentation(line: string): string {
    const match = line.match(/^(\s*)/);
    return match ? match[1] : '';
  }

  /**
   * Applies indentation to suggested code
   */
  private applyIndentation(code: string, indentation: string): string {
    if (!indentation) {
      return code;
    }

    // Split code into lines and apply indentation to each line
    const lines = code.split('\n');
    return lines
      .map((line, index) => {
        // Don't add indentation to empty lines
        if (line.trim() === '') {
          return line;
        }
        // For the first line, preserve any existing indentation in the suggested code
        // For subsequent lines, add the base indentation
        return index === 0 ? indentation + line : indentation + line;
      })
      .join('\n');
  }
}
