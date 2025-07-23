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
  }>;
  summary: string;
  overallRisk: "low" | "medium" | "high" | "critical";
  isPartial?: boolean;
  analysisTime?: number;
}

/**
 * Interface that all AI providers must implement for security analysis
 */
export interface APIProvider {
  name: string;
  displayName: string;
  analyzeCode(code: string, language: string): Promise<AISecurityResponse>;
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
      } else if (error.code === "ECONNABORTED") {
        throw new Error("VulnZap API request timeout");
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
            name: "code_to_analyze",
            content: code,
            language: language
          }
        ]
      },
      {
        headers: {
          "x-api-key": `${apiKey}`,
          "Content-Type": "application/json",
          "User-Agent": "VulnZap-VSCode-Extension",
        },
        timeout: 30000,
      }
    );

    // Extract job ID from the scan response
    const jobId = scanResponse.data?.data?.jobId;
    if (!jobId) {
      throw new Error("No job ID returned from scan request");
    }

    // Step 2: Poll for results
    const maxPollingAttempts = 30; // 30 attempts with 2-second intervals = 1 minute max
    const pollingInterval = 2000; // 2 seconds

    for (let attempt = 0; attempt < maxPollingAttempts; attempt++) {
      try {
        const jobResponse = await axios.get(
          `${apiUrl}/api/scan/jobs/${jobId}`,
          {
            headers: {
              "x-api-key": `${apiKey}`,
              "Content-Type": "application/json",
              "User-Agent": "VulnZap-VSCode-Extension",
            },
            timeout: 10000,
          }
        );

        const jobData = jobResponse.data?.data;
        if (jobData?.status === "COMPLETED") {
          // Step 3: Get the result ID and fetch detailed results
          const resultId = jobData?.scanResults[0]?.id;
          if (!resultId) {
            Logger.error("Job completed but no result ID found", undefined, "Job data:", JSON.stringify(jobData, null, 2));
            throw new Error("No result ID returned from completed job");
          }

          Logger.debug(`Job completed successfully. ResultId: ${resultId}`);

          // Fetch the detailed scan results
          const resultsResponse = await axios.get(
            `${apiUrl}/api/scan/results/${resultId}`,
            {
              headers: {
                "x-api-key": `${apiKey}`,
                "Content-Type": "application/json",
                "User-Agent": "VulnZap-VSCode-Extension",
              },
              timeout: 10000,
            }
          );

          const resultsData = resultsResponse.data?.data;
          if (!resultsData) {
            throw new Error("No results data returned from results endpoint");
          }

          Logger.debug(`Successfully fetched scan results for resultId: ${resultId}`);
          Logger.debug(`Results data structure:`, JSON.stringify(resultsData, null, 2));

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
              resultId,
              pollingAttempts: attempt + 1,
            }
          );

          return this.validateAndNormalizeResponse(resultsData);
        } else if (jobData?.status === "FAILED") {
          throw new Error(`Scan job failed: ${jobData.error || "Unknown error"}`);
        }

        // Job is still in progress, wait before next poll
        await new Promise(resolve => setTimeout(resolve, pollingInterval));
      } catch (error: any) {
        if (error.response?.status === 404) {
          throw new Error("Scan job not found");
        }
        throw error;
      }
    }

    throw new Error("Scan job timed out - results not available within expected time");
  }

  /**
   * Validates and normalizes the API response
   */
  private validateAndNormalizeResponse(data: any): AISecurityResponse {
    try {
      // Handle different response formats from the API
      let parsedData = data;

      // Process the new results endpoint response format
      if (parsedData.results && Array.isArray(parsedData.results) && parsedData.results.length > 0) {
        const fileResult = parsedData.results[0];
        const vulnerabilities = fileResult.vulnerabilities || [];

        // Get summary information
        const summary = parsedData.summary || {};
        const totalVulnerabilities = summary.totalVulnerabilities || vulnerabilities.length;
        const severityBreakdown = summary.severityBreakdown || {};

        let summaryText = "Security analysis completed";
        let overallRisk: "low" | "medium" | "high" | "critical" = "low";

        if (totalVulnerabilities > 0) {
          summaryText = `Found ${totalVulnerabilities} security issues`;

          // Determine overall risk based on severity breakdown
          if (severityBreakdown.critical > 0) {
            overallRisk = "critical";
          } else if (severityBreakdown.high > 0) {
            overallRisk = "high";
          } else if (severityBreakdown.medium > 0) {
            overallRisk = "medium";
          }
        } else {
          summaryText = "No security vulnerabilities detected";
        }

        // Convert vulnerabilities to the expected format
        // API returns 1-based line/column numbers, convert to 0-based for VS Code
        const issues = vulnerabilities.map((vuln: any) => {
          const startRow = Number(vuln.location?.start?.row) || 1;
          const startCol = Number(vuln.location?.start?.column) || 1;
          const endRow = Number(vuln.location?.end?.row) || startRow;
          const endCol = Number(vuln.location?.end?.column) || startCol;

          const issue = {
            line: Math.max(0, startRow - 1), // Convert to 0-based
            column: Math.max(0, startCol - 1), // Convert to 0-based
            endLine: Math.max(0, endRow - 1), // Convert to 0-based
            endColumn: Math.max(0, endCol - 1), // Convert to 0-based
            message: String(vuln.description || vuln.title || "Security issue detected"),
            severity: this.mapSeverityToVSCode(vuln.severity),
            code: String(vuln.type || "SECURITY_ISSUE"),
            suggestion: vuln.remediation ? String(vuln.remediation) : undefined,
            confidence: Math.min(100, Math.max(0, Math.round((Number(vuln.confidence) || 0.5) * 100))),
            cve: vuln.cwe ? [vuln.cwe] : [],
            searchQuery: vuln.type ? String(vuln.type) : undefined,
          };

          Logger.debug(`Converted vulnerability: ${vuln.type} at line ${startRow}:${startCol}-${endRow}:${endCol} -> ${issue.line}:${issue.column}-${issue.endLine}:${issue.endColumn}`);

          return issue;
        });

        return {
          issues,
          summary: summaryText,
          overallRisk,
          isPartial: false,
          analysisTime: parsedData.job?.completedAt && parsedData.job?.startedAt ?
            new Date(parsedData.job.completedAt).getTime() - new Date(parsedData.job.startedAt).getTime() :
            undefined,
        };
      }

      // Fallback to empty response if the expected format is not found
      Logger.warn("Unexpected API response format:", JSON.stringify(parsedData, null, 2));
      return {
        issues: [],
        summary: "No security analysis results available",
        overallRisk: "low",
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
    language: string
  ): Promise<AISecurityResponse> {
    if (!this.provider.isConfigured()) {
      throw new Error("VulnZap API is not configured");
    }

    return this.provider.analyzeCode(code, language);
  }
}
