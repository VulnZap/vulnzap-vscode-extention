import * as vscode from "vscode";
import axios from "axios";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
// AST analysis removed - using text-based approach now
import { Logger } from "../utils/logger";

/**
 * Standard response format for AI security analysis results
 */
export interface AISecurityResponse {
  issues: Array<{
    line: number;
    column: number;
    endLine: number;
    endColumn: number;
    message: string;
    severity: "error" | "warning" | "info";
    code: string;
    suggestion?: string;
    confidence: number;
    cve?: string[];
    searchQuery?: string;
    // New fields for enhanced vulnerability analysis
    taintFlowPath?: Array<{
      nodeId: string;
      filePath: string;
      flowType: string;
      operation: string;
      lineNumber: number;
      stepNumber: number;
      codeSnippet: string;
      description: string;
      columnNumber: number;
      contextLines: {
        after: string[];
        before: string[];
        current: string;
      };
    }>;
    owasp?: string;
    framework?: string;
    metadata?: any;
  }>;
  summary: string;
  overallRisk: "low" | "medium" | "high" | "critical";
  isPartial?: boolean;
  analysisTime?: number;
}

export interface Vulnerability {
  uniqueId: string;
  type: string;
  severity: "low" | "medium" | "high" | "critical";
  title: string;
  description: string;
  file: string;
  line: number;
  column: number;
  endLine?: number;
  endColumn?: number;
  snippet: string;
  confidence: number;
  cwe?: string;
  remediation?: string;
}

export interface ScanSummary {
  totalFiles: number;
  totalVulnerabilities: number;
  uniqueVulnerabilities: number;
  severityBreakdown: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  scanTime: number;
  llmDeduplicationApplied: boolean;
}

export interface ScanResult {
  jobId: string;
  status: "pending" | "running" | "completed" | "failed";
  vulnerabilities: Vulnerability[];
  summary: ScanSummary;
  createdAt: string;
  standaloneVulnerabilities?: ClientVulnerability[]; // Added for new API format
  results?: {
    vulnerabilities: Array<{
      file: string;
      language: string;
      metadata: {
        performance: {
          totalTime: number;
          cfgBuildTime: number;
          cpgBuildTime: number;
          dfgBuildTime: number;
          taintAnalysisTime: number;
          contextResolveTime: number;
        };
      };
      scanTime: number;
      linesOfCode: number;
      taintVulnerabilities: TaintVulnerability[];
      standaloneVulnerabilities: StandaloneVulnerability[];
    }>;
  };
}

export interface TaintVulnerability {
  id: string;
  cwe: string;
  name: string;
  sink: {
    type: string;
    nodeId: string;
    category: string;
    filePath: string;
    lineNumber: number;
    codeSnippet: string;
    columnNumber: number;
  };
  type: string;
  owasp: string;
  title: string;
  source: {
    type: string;
    nodeId: string;
    category: string;
    filePath: string;
    lineNumber: number;
    codeSnippet: string;
    columnNumber: number;
  };
  category: string;
  language: string;
  metadata: {
    requestId: string;
    pathLength: number;
    isInterFile: boolean;
    analysisType: string;
    sinkCategory: string;
    sourceCategory: string;
  };
  severity: string;
  framework: string;
  confidence: number;
  sanitizers: any[];
  description: string;
  taintFlowPath: Array<{
    nodeId: string;
    filePath: string;
    flowType: string;
    operation: string;
    lineNumber: number;
    stepNumber: number;
    codeSnippet: string;
    description: string;
    columnNumber: number;
    contextLines: {
      after: string[];
      before: string[];
      current: string;
    };
  }>;
  vulnerabilityId: string;
}

export interface StandaloneVulnerability {
  id: string;
  cwe: string;
  name: string;
  type: string;
  owasp: string;
  nodeId: string;
  category: string;
  filePath: string;
  location: {
    end: {
      row: number;
      column: number;
    };
    start: {
      row: number;
      column: number;
    };
    snippet: string;
  };
  metadata: {
    standalone: boolean;
    credentialType: string;
    detectionMethod: string;
  };
  severity: string;
  confidence: number;
  codeSnippet: string;
  description: string;
  vulnerabilityId: string;
}

export interface VulnZapResponse {
  success: boolean;
  data:
    | ScanResult
    | {
        results: {
          vulnerabilities: Array<{
            file: string;
            language: string;
            metadata: {
              performance: {
                totalTime: number;
                cfgBuildTime: number;
                cpgBuildTime: number;
                dfgBuildTime: number;
                taintAnalysisTime: number;
                contextResolveTime: number;
              };
            };
            scanTime: number;
            linesOfCode: number;
            taintVulnerabilities: TaintVulnerability[];
            standaloneVulnerabilities: StandaloneVulnerability[];
          }>;
        };
        createdAt: string;
      };
  error?: string;
}

export interface ClientVulnerability {
  uniqueId: string;
  type: string;
  severity: "low" | "medium" | "high" | "critical";
  title: string;
  description: string;
  file: string;
  line: number;
  column: number;
  endLine?: number;
  endColumn?: number;
  snippet: string;
  confidence: number;
  cwe?: string;
  remediation?: string;
  flowMilestones?: Array<{
    type: "data_source" | "data_flow" | "vulnerability_source";
    description: string;
    location: {
      file: string;
      line: number;
      column: number;
      snippet: string;
    };
    riskLevel: string;
  }>;
  interFileFlow?: {
    id: string;
    description: string;
    files: string[];
    steps: number;
  };
}

/**
 * Interface that all AI providers must implement for security analysis
 */
export interface APIProvider {
  name: string;
  displayName: string;
  analyzeCode(
    code: string,
    filePath: string,
    language: string
  ): Promise<AISecurityResponse>;
  isConfigured(): boolean;
  getConfigurationErrors(): string[];
}

/**
 * Utility class for logging LLM interactions for debugging and analysis
 */
class LLMLogger {
  private static logDir: string = path.join(os.homedir(), ".vulnzap");

  /**
   * Creates the log directory if it doesn't exist
   */
  static async ensureLogDirectory(): Promise<void> {
    try {
      if (!fs.existsSync(this.logDir)) {
        fs.mkdirSync(this.logDir, { recursive: true });
      }
    } catch (error) {
      Logger.error("Failed to create log directory:", error as Error);
    }
  }

  /**
   * Logs an LLM interaction with input, output, and metadata
   */
  static async logLLMInteraction(
    provider: string,
    input: string,
    output: string,
    metadata: any = {}
  ): Promise<void> {
    try {
      await this.ensureLogDirectory();

      const timestamp = new Date().toISOString();
      const logEntry = {
        timestamp,
        provider,
        metadata,
        input: {
          content: input,
          length: input.length,
        },
        output: {
          content: output,
          length: output.length,
        },
      };

      const logFileName = `llm-${provider}-${
        new Date().toISOString().split("T")[0]
      }.log`;
      const logFilePath = path.join(this.logDir, logFileName);

      const logLine = JSON.stringify(logEntry) + "\n";
      fs.appendFileSync(logFilePath, logLine);
    } catch (error) {
      Logger.error("Failed to log LLM interaction:", error as Error);
    }
  }
}

/**
 * VulnZap API provider implementation for specialized security analysis
 * Connects to the VulnZap backend service for enhanced vulnerability detection
 */
export class VulnZapProvider implements APIProvider {
  name = "vulnzap";
  displayName = "VulnZap API";
  private context: vscode.ExtensionContext | undefined;

  constructor(context?: vscode.ExtensionContext) {
    this.context = context;
  }

  /**
   * Sets the VS Code extension context for accessing configuration
   */
  setContext(context: vscode.ExtensionContext) {
    this.context = context;
  }

  /**
   * Checks if the provider has all required configuration (API key and URL)
   */
  isConfigured(): boolean {
    const config = vscode.workspace.getConfiguration("vulnzap");
    const apiKey = config.get("vulnzapApiKey", "").trim();
    const apiUrl = config.get("vulnzapApiUrl", "").trim();

    return apiKey.length > 0 && apiUrl.length > 0;
  }

  /**
   * Returns a list of configuration issues that prevent the provider from working
   */
  getConfigurationErrors(): string[] {
    const errors: string[] = [];
    const config = vscode.workspace.getConfiguration("vulnzap");

    const apiKey = config.get("vulnzapApiKey", "").trim();
    const apiUrl = config.get("vulnzapApiUrl", "").trim();

    if (!apiKey) {
      errors.push("VulnZap API key is required");
    }

    if (!apiUrl) {
      errors.push("VulnZap API URL is required");
    } else {
      try {
        new URL(apiUrl);
      } catch {
        errors.push("VulnZap API URL must be a valid URL");
      }
    }

    return errors;
  }

  /**
   * Analyzes code for security vulnerabilities using text-based approach
   */
  async analyzeCode(
    code: string,
    filePath: string,
    language: string
  ): Promise<AISecurityResponse> {
    const config = vscode.workspace.getConfiguration("vulnzap");
    const apiKey = config.get("vulnzapApiKey", "").trim();
    const apiUrl = config.get("vulnzapApiUrl", "").trim();

    if (!apiKey || !apiUrl) {
      throw new Error("VulnZap API key and URL are required");
    }

    const startTime = Date.now();
    const fastScan = config.get("enableFastScan", true);

    try {
      // Use text-based analysis (AST removed for simplicity and speed)
      Logger.debug(`Using text-based analysis for ${language}`);
      const analysisResult = await this.performTextBasedAnalysis(
        filePath,
        code,
        language,
        apiKey,
        apiUrl,
        fastScan
      );

      const analysisTime = Date.now() - startTime;
      analysisResult.analysisTime = analysisTime;

      return analysisResult;
    } catch (error: any) {
      Logger.error("VulnZap API error:", error as Error);

      // Provide specific error messages based on the type of failure
      if (error.response) {
        const status = error.response.status;
        const message =
          error.response.data?.message || error.response.statusText;

        if (status === 401) {
          throw new Error("Invalid VulnZap API key");
        } else if (status === 429) {
          throw new Error("VulnZap API rate limit exceeded");
        } else if (status >= 500) {
          throw new Error("VulnZap API server error");
        } else {
          throw new Error(`VulnZap API error: ${message}`);
        }
      } else if (error.code === "ENOTFOUND" || error.code === "ECONNREFUSED") {
        throw new Error("Cannot connect to VulnZap API - check URL");
      } else {
        throw new Error(`VulnZap API error: ${error.message}`);
      }
    }
  }

  /**
   * Perform text-based analysis (fast and simple)
   */
  private async performTextBasedAnalysis(
    filePath: string,
    code: string,
    language: string,
    apiKey: string,
    apiUrl: string,
    fastScan: boolean
  ): Promise<AISecurityResponse> {
    // Step 1: Start the scan job
    const scanResponse = await axios.post(
      `${apiUrl}/api/scan/content`,
      {
        files: [
          {
            name: filePath,
            content: code,
            language: language,
          },
        ],
      },
      {
        headers: {
          "x-api-key": `${apiKey}`,
          "Content-Type": "application/json",
          "User-Agent": "VulnZap-VSCode-Extension",
        },
      }
    );

    // Extract job ID from the scan response
    const jobId = scanResponse.data?.data?.jobId;
    if (!jobId) {
      throw new Error("No job ID returned from scan request");
    }

    // Step 2: Poll for results (no timeout limit)
    const pollingInterval = 2000; // 2 seconds

    for (let attempt = 0; ; attempt++) {
      try {
        const jobResponse = await axios.get(
          `${apiUrl}/api/scan/jobs/${jobId}`,
          {
            headers: {
              "x-api-key": `${apiKey}`,
              "Content-Type": "application/json",
              "User-Agent": "VulnZap-VSCode-Extension",
            },
          }
        );

        const jobData = jobResponse.data?.data;
        if (jobData?.status.toLowerCase() === "completed") {
          // Step 3: Get the result ID and fetch detailed results
          const resultsData: VulnZapResponse = jobResponse.data;
          if (!resultsData) {
            throw new Error("No results data returned from results endpoint");
          }

          Logger.debug(
            `Results data structure:`,
            JSON.stringify(resultsData, null, 2)
          );

          // Log the interaction for debugging and analytics
          await LLMLogger.logLLMInteraction(
            this.name,
            code,
            JSON.stringify(resultsData),
            {
              language,
              codeLength: code.length,
              fastScan,
              approach: "text-based",
              jobId,
              pollingAttempts: attempt + 1,
            }
          );

          return this.normalizeResponse(resultsData);
        } else if (jobData?.status.toLowerCase() === "failed") {
          throw new Error(
            `Scan job failed: ${jobData.error || "Unknown error"}`
          );
        }

        // Job is still in progress, wait before next poll
        await new Promise((resolve) => setTimeout(resolve, pollingInterval));
      } catch (error: any) {
        if (error.response?.status === 404) {
          throw new Error("Scan job not found");
        }
        throw error;
      }
    }
  }

  /**
   * Normalizes the response from the VulnZap API
   * @param data - The response from the VulnZap API
   * @returns The normalized response
   */
  private normalizeResponse(data: VulnZapResponse): AISecurityResponse {
    try {
      let allVulnerabilities: any[] = [];
      let totalScanTime = 0;
      let totalLinesOfCode = 0;

      // Handle new nested response format
      if ("results" in data.data && data.data.results) {
        // New API response format
        const results = data.data.results;

        for (const fileResult of results.vulnerabilities) {
          totalScanTime += fileResult.scanTime || 0;
          totalLinesOfCode += fileResult.linesOfCode || 0;

          // Process taint vulnerabilities
          if (fileResult.taintVulnerabilities) {
            const taintVulns = fileResult.taintVulnerabilities.map(
              (vuln: TaintVulnerability) => ({
                ...vuln,
                file: fileResult.file,
                language: fileResult.language,
                vulnerabilityType: "taint",
                // Map sink location to standard format
                line: vuln.sink.lineNumber,
                column: vuln.sink.columnNumber,
                snippet: vuln.sink.codeSnippet,
                // Include taint flow information
                taintFlowPath: vuln.taintFlowPath,
              })
            );
            allVulnerabilities.push(...taintVulns);
          }

          // Process standalone vulnerabilities
          if (fileResult.standaloneVulnerabilities) {
            const standaloneVulns = fileResult.standaloneVulnerabilities.map(
              (vuln: StandaloneVulnerability) => ({
                ...vuln,
                file: fileResult.file,
                language: fileResult.language,
                vulnerabilityType: "standalone",
                // Map location to standard format
                line: vuln.location.start.row,
                column: vuln.location.start.column,
                endLine: vuln.location.end.row,
                endColumn: vuln.location.end.column,
                snippet: vuln.location.snippet,
              })
            );
            allVulnerabilities.push(...standaloneVulns);
          }
        }
      } else {
        // Legacy format - combine both vulnerabilities and standaloneVulnerabilities
        const legacyData = data.data as ScanResult;
        allVulnerabilities = [
          ...(legacyData.vulnerabilities || []),
          ...(legacyData.standaloneVulnerabilities || []),
        ];
      }

      if (allVulnerabilities.length === 0) {
        Logger.warn("No results found in VulnZap scan response.");
        return {
          issues: [],
          summary: "No security vulnerabilities detected",
          overallRisk: "low",
        };
      }

      // Determine overall risk based on severity
      let overallRisk: "low" | "medium" | "high" | "critical" = "low";
      const severityCount = { critical: 0, high: 0, medium: 0, low: 0 };

      allVulnerabilities.forEach((vuln) => {
        const severity = vuln.severity?.toLowerCase();
        if (severity === "critical") {
          severityCount.critical++;
          overallRisk = "critical";
        } else if (severity === "high") {
          severityCount.high++;
          if (overallRisk !== "critical") overallRisk = "high";
        } else if (severity === "medium") {
          severityCount.medium++;
          if (overallRisk !== "critical" && overallRisk !== "high")
            overallRisk = "medium";
        } else {
          severityCount.low++;
        }
      });

      const issues = allVulnerabilities.map((vuln: any) => {
        // Handle different location formats
        let line = 1,
          column = 1,
          endLine = 1,
          endColumn = 1,
          snippet = "";

        if (vuln.vulnerabilityType === "taint") {
          // Taint vulnerability uses sink location
          line = vuln.line || vuln.sink?.lineNumber || 1;
          column = vuln.column || vuln.sink?.columnNumber || 1;
          endLine = line; // Taint vulns typically don't have end positions
          endColumn = column + (vuln.snippet?.length || 10);
          snippet = vuln.snippet || vuln.sink?.codeSnippet || "";
        } else if (vuln.vulnerabilityType === "standalone" || vuln.location) {
          // Standalone vulnerability uses location object
          line = vuln.line || vuln.location?.start?.row || 1;
          column = vuln.column || vuln.location?.start?.column || 1;
          endLine = vuln.endLine || vuln.location?.end?.row || line;
          endColumn = vuln.endColumn || vuln.location?.end?.column || column;
          snippet =
            vuln.snippet || vuln.location?.snippet || vuln.codeSnippet || "";
        } else {
          // Legacy format
          line = vuln.line || 1;
          column = vuln.column || 1;
          endLine = vuln.endLine || line;
          endColumn = vuln.endColumn || column;
          snippet = vuln.snippet || vuln.codeSnippet || "";
        }

        return {
          line: Math.max(0, line - 1), // Convert to 0-based indexing
          column: Math.max(0, column - 1),
          endLine: Math.max(0, endLine - 1),
          endColumn: Math.max(0, endColumn - 1),
          message:
            vuln.description ||
            vuln.title ||
            vuln.name ||
            "Security issue detected",
          severity: this.mapSeverityToVSCode(vuln.severity),
          code: vuln.type || vuln.vulnerabilityId || "SECURITY_ISSUE",
          suggestion: vuln.remediation || this.generateSuggestion(vuln),
          confidence: Math.min(
            100,
            Math.max(0, Math.round((vuln.confidence ?? 0.5) * 100))
          ),
          cve: vuln.cwe ? [vuln.cwe] : [],
          searchQuery: vuln.type || vuln.category,
          // Additional data for enhanced analysis
          taintFlowPath: vuln.taintFlowPath,
          owasp: vuln.owasp,
          framework: vuln.framework,
          metadata: vuln.metadata,
        };
      });

      const summaryText = this.generateSummary(
        allVulnerabilities.length,
        severityCount,
        totalScanTime,
        totalLinesOfCode
      );

      return {
        issues,
        summary: summaryText,
        overallRisk,
        isPartial: false,
        analysisTime: totalScanTime || undefined,
      };
    } catch (error) {
      Logger.error("Error validating API response:", error as Error);
      return {
        issues: [],
        summary: "Failed to process security analysis response",
        overallRisk: "low",
      };
    }
  }

  /**
   * Generates a suggestion for remediation based on vulnerability type
   */
  private generateSuggestion(vuln: any): string | undefined {
    if (
      vuln.type === "hardcoded_credentials" ||
      vuln.category === "hardcoded_credentials"
    ) {
      return "Remove hardcoded credentials and use environment variables or secure credential storage instead.";
    }
    if (vuln.type === "injection" || vuln.category === "injection") {
      return "Use parameterized queries or input validation to prevent injection attacks.";
    }
    if (vuln.owasp?.includes("Authentication")) {
      return "Implement proper authentication mechanisms and avoid predictable tokens.";
    }
    return undefined;
  }

  /**
   * Generates a comprehensive summary of the scan results
   */
  private generateSummary(
    totalVulns: number,
    severityCount: {
      critical: number;
      high: number;
      medium: number;
      low: number;
    },
    scanTime: number,
    linesOfCode: number
  ): string {
    if (totalVulns === 0) {
      return "No security vulnerabilities detected";
    }

    let summary = `Found ${totalVulns} security issue${
      totalVulns > 1 ? "s" : ""
    }`;

    const severityParts: string[] = [];
    if (severityCount.critical > 0)
      severityParts.push(`${severityCount.critical} critical`);
    if (severityCount.high > 0)
      severityParts.push(`${severityCount.high} high`);
    if (severityCount.medium > 0)
      severityParts.push(`${severityCount.medium} medium`);
    if (severityCount.low > 0) severityParts.push(`${severityCount.low} low`);

    if (severityParts.length > 0) {
      summary += ` (${severityParts.join(", ")})`;
    }

    if (scanTime > 0) {
      summary += `. Scan completed in ${(scanTime / 1000).toFixed(2)}s`;
    }

    if (linesOfCode > 0) {
      summary += ` for ${linesOfCode} lines of code`;
    }

    return summary;
  }

  /**
   * Maps API severity levels to VS Code severity levels
   */
  private mapSeverityToVSCode(severity: string): "error" | "warning" | "info" {
    switch (severity?.toLowerCase()) {
      case "critical":
      case "high":
        return "error";
      case "medium":
        return "warning";
      case "low":
      default:
        return "info";
    }
  }
}

/**
 * Manages API providers for security analysis
 * Currently supports VulnZap API but designed to be extensible for future providers
 */
export class APIProviderManager {
  private provider: VulnZapProvider;
  private context: vscode.ExtensionContext | undefined;

  constructor(context?: vscode.ExtensionContext) {
    this.context = context;
    this.provider = new VulnZapProvider(context);
  }

  /**
   * Updates the extension context for all managed providers
   */
  setContext(context: vscode.ExtensionContext) {
    this.context = context;
    this.provider.setContext(context);
  }

  /**
   * Updates the current provider based on configuration
   * Currently a no-op since we only have one provider
   */
  updateCurrentProvider() {
    // No-op since we only have one provider
  }

  /**
   * Returns the currently active API provider
   */
  getCurrentProvider(): APIProvider {
    return this.provider;
  }

  /**
   * Gets a specific provider by name
   */
  getProvider(name: string): APIProvider | undefined {
    return name === "vulnzap" ? this.provider : undefined;
  }

  /**
   * Returns all available providers
   */
  getAllProviders(): APIProvider[] {
    return [this.provider];
  }

  /**
   * Returns only providers that are properly configured
   */
  getAvailableProviders(): APIProvider[] {
    return this.provider.isConfigured() ? [this.provider] : [];
  }

  /**
   * Analyzes code using the current provider
   * Throws an error if no provider is configured
   */
  async analyzeCode(
    code: string,
    filePath: string,
    language: string
  ): Promise<AISecurityResponse> {
    if (!this.provider.isConfigured()) {
      throw new Error("VulnZap API is not configured");
    }

    return this.provider.analyzeCode(code, filePath, language);
  }
}
