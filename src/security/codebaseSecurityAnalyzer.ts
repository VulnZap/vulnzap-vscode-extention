import * as vscode from "vscode";
import { APIProviderManager } from "../providers/apiProviders";
import { Logger } from "../utils/logger";

/**
 * Security issue found by the analyzer
 */
export interface SecurityIssue {
  id: string;
  type: string;
  severity: "low" | "medium" | "high" | "critical";
  message: string;
  description: string;
  filePath: string;
  startLine: number;
  endLine: number;
  startColumn: number;
  endColumn: number;
  confidence: number;
  suggestion?: string;
}

/**
 * Analysis response from the AI
 */
export interface SecurityAnalysisResponse {
  issues: SecurityIssue[];
  summary: string;
  overallRisk: "low" | "medium" | "high" | "critical";
  recommendations: string[];
  analysisStats: {
    chunksAnalyzed: number;
    securityPatternsFound: number;
    contextualMatches: number;
  };
}

/**
 * Codebase security analyzer using API-based analysis only
 * All scanning is now performed through the VulnZap API
 */
export class CodebaseSecurityAnalyzer {
  private apiProvider: APIProviderManager;

  constructor() {
    this.apiProvider = new APIProviderManager();
  }

  /**
   * Analyze a VS Code document for security vulnerabilities
   * This method provides compatibility with the diagnostic provider interface
   */
  async analyzeDocument(document: vscode.TextDocument): Promise<any[]> {
    const response = await this.analyzeCode(
      document.getText(),
      document.uri.fsPath,
      document.languageId.toString()
    );

    // Convert SecurityIssue[] to the format expected by the diagnostic provider
    return response.issues.map((issue) => ({
      line: issue.startLine, // Already 0-based from conversion
      column: issue.startColumn,
      endLine: issue.endLine, // Already 0-based from conversion
      endColumn: issue.endColumn,
      message: issue.message,
      severity: this.convertToVSCodeSeverity(issue.severity),
      code: issue.type,
      suggestion: issue.suggestion,
      confidence: issue.confidence,
      cve: [],
      searchResults: [],
      relatedCode: [],
      similarVulnerabilities: [],
    }));
  }

  /**
   * Convert our severity enum to VS Code DiagnosticSeverity
   */
  public convertToVSCodeSeverity(
    severity: "low" | "medium" | "high" | "critical"
  ): vscode.DiagnosticSeverity {
    switch (severity) {
      case "critical":
      case "high":
        return vscode.DiagnosticSeverity.Error;
      case "medium":
        return vscode.DiagnosticSeverity.Warning;
      case "low":
      default:
        return vscode.DiagnosticSeverity.Information;
    }
  }

  /**
   * Analyze code for security vulnerabilities using API-based approach only
   */
  async analyzeCode(
    code: string,
    filePath: string,
    language: string
  ): Promise<SecurityAnalysisResponse> {
    Logger.debug(`Analyzing code security for: ${filePath}`);

    try {
      // Perform API-based analysis only
      const apiIssues = await this.performAPIAnalysis(code, filePath, language);

      return {
        issues: apiIssues,
        summary: this.generateSummary(apiIssues),
        overallRisk: this.calculateOverallRisk(apiIssues),
        recommendations: this.generateRecommendations(apiIssues),
        analysisStats: {
          chunksAnalyzed: 0,
          securityPatternsFound: 0,
          contextualMatches: apiIssues.length,
        },
      };
    } catch (error) {
      Logger.error("Security analysis failed:", error as Error);
      return this.createFallbackResponse(filePath);
    }
  }

  /**
   * Perform API-based analysis
   */
  private async performAPIAnalysis(
    code: string,
    filePath: string,
    language: string
  ): Promise<SecurityIssue[]> {
    try {
      Logger.debug("API Analysis starting, calling API with raw code...");
      const aiResponse = await this.getAIAnalysis(code, filePath, language);

      // log the aiResponse
      Logger.debug("AI Response:", JSON.stringify(aiResponse, null, 2));

      // Convert AISecurityResponse issues to SecurityIssue format
      const parsedIssues = this.convertAIResponseToSecurityIssues(
        aiResponse,
        filePath
      );
      return parsedIssues;
    } catch (error) {
      Logger.warn("API analysis failed:", error as Error);
      return [];
    }
  }

  /**
   * Get AI analysis response
   */
  private async getAIAnalysis(
    code: string,
    filePath: string,
    language: string
  ): Promise<any> {
    const provider = this.apiProvider.getCurrentProvider();
    if (!provider) {
      throw new Error("No AI provider configured");
    }

    const response = await provider.analyzeCode(code, filePath, language);

    // The response is already an AISecurityResponse object, not a string
    if (response && response.issues) {
      return response;
    }

    // Fallback to empty response
    return { issues: [] };
  }

  /**
   * Convert AISecurityResponse issues to SecurityIssue format
   */
  private convertAIResponseToSecurityIssues(
    aiResponse: any,
    filePath: string
  ): SecurityIssue[] {
    const issues: SecurityIssue[] = [];

    if (aiResponse && aiResponse.issues && Array.isArray(aiResponse.issues)) {
      for (const issue of aiResponse.issues) {
        const securityIssue: SecurityIssue = {
          id: `api_${issue.code || "unknown"}_${Date.now()}_${Math.random()}`,
          type: issue.code || "unknown",
          severity:
            issue.severity === "error"
              ? "high"
              : issue.severity === "warning"
              ? "medium"
              : "low",
          message: issue.message || "Security issue detected",
          description: issue.message || "",
          filePath,
          startLine: issue.line || 0, // Already 0-based from API provider
          endLine: issue.endLine || issue.line || 0, // Already 0-based from API provider
          startColumn: issue.column || 0, // Already 0-based from API provider
          endColumn: issue.endColumn || (issue.column || 0) + 10, // Already 0-based from API provider
          confidence: issue.confidence || 80,
          suggestion: issue.suggestion,
        };

        Logger.debug(
          `SecurityIssue: ${securityIssue.type} at ${securityIssue.startLine}:${securityIssue.startColumn}-${securityIssue.endLine}:${securityIssue.endColumn}`
        );
        issues.push(securityIssue);
      }
    }

    Logger.debug(
      `Converted ${issues.length} API issues to SecurityIssue format`
    );
    return issues;
  }

  private generateSummary(issues: SecurityIssue[]): string {
    if (issues.length === 0) {
      return "No security issues detected in the analyzed code.";
    }

    const severityCounts = issues.reduce((acc, issue) => {
      acc[issue.severity] = (acc[issue.severity] || 0) + 1;
      return acc;
    }, {} as { [key: string]: number });

    const severityList = Object.entries(severityCounts)
      .map(([severity, count]) => `${count} ${severity}`)
      .join(", ");

    return `Found ${issues.length} security issue(s): ${severityList}`;
  }

  private calculateOverallRisk(
    issues: SecurityIssue[]
  ): "low" | "medium" | "high" | "critical" {
    if (issues.length === 0) return "low";

    const criticalCount = issues.filter(
      (i) => i.severity === "critical"
    ).length;
    const highCount = issues.filter((i) => i.severity === "high").length;
    const mediumCount = issues.filter((i) => i.severity === "medium").length;

    if (criticalCount > 0) return "critical";
    if (highCount >= 3) return "critical";
    if (highCount >= 1) return "high";
    if (mediumCount >= 3) return "high";
    if (mediumCount >= 1) return "medium";

    return "low";
  }

  private generateRecommendations(issues: SecurityIssue[]): string[] {
    const recommendations: string[] = [];

    const issueTypes = new Set(issues.map((i) => i.type));

    if (issueTypes.has("sql_injection")) {
      recommendations.push(
        "Implement parameterized queries to prevent SQL injection"
      );
    }

    if (issueTypes.has("xss")) {
      recommendations.push(
        "Implement proper input validation and output encoding"
      );
    }

    if (issueTypes.has("hardcoded_secrets")) {
      recommendations.push(
        "Move secrets to environment variables or secure vaults"
      );
    }

    if (issueTypes.has("weak_crypto")) {
      recommendations.push("Upgrade to stronger cryptographic algorithms");
    }

    if (issueTypes.has("unsafe_functions")) {
      recommendations.push("Review and secure all command execution functions");
    }

    if (recommendations.length === 0) {
      recommendations.push("Continue following secure coding practices");
    }

    return recommendations;
  }

  private createFallbackResponse(filePath: string): SecurityAnalysisResponse {
    return {
      issues: [],
      summary: "Security analysis failed, manual review recommended",
      overallRisk: "low",
      recommendations: ["Manually review this code for security issues"],
      analysisStats: {
        chunksAnalyzed: 0,
        securityPatternsFound: 0,
        contextualMatches: 0,
      },
    };
  }
}
