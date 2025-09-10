import * as vscode from "vscode";
import axios from "axios";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
// AST analysis removed - using text-based approach now
import { Logger } from "../utils/logger";
import { VulnZapConfig, getApiUrl, getJobApiUrl } from "../utils/config";

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
      lineNumber: number;
      stepNumber: number;
      codeSnippet: string;
      description: string;
      originalFilePath: string;
    }>;
    patchedCode?: Array<{
      lineNumber: number;
      stepNumber: number;
      codeSnippet: string;
      description: string;
      originalFilePath: string;
    }>;
    keywords?: string[];
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


export interface StandaloneVulnerability {
  id: string;
  description: string;
  type: string;
  keywords: string[];
  confidence: number;
  originalFilePath: string;
  codeSnippet: string;
  patchedCode: string;
  lineNumber: number;
}

export interface SimplifiedTaintFlowStep {
  stepNumber: number;
  filePath: string;
  originalFilePath: string;
  lineNumber: number;
  codeSnippet: string;
  description: string;
}

export interface TaintVulnerability {
  id: string;
  description: string;
  type: string;
  keywords: string[];
  confidence: number;
  source: {
    originalFilePath: string;
    filePath: string;
    lineNumber: number;
    codeSnippet: string;
    description: string;
  }
  sink: {
    originalFilePath: string;
    filePath: string;
    lineNumber: number;
    codeSnippet: string;
    description: string;
  }
  taintFlowPath: Array<SimplifiedTaintFlowStep>;
  patchedCode: Array<{
    stepNumber: number;
    description: string;
    originalFilePath: string;
    lineNumber: number;
    codeSnippet: string;
  }>;
}

export interface VulnZapResponse {
  success: boolean;
  data: {
    jobId: string;
    status: string;
    progress: number;
    metadata: {
      fileCount: number;
      languages: string[];
    };
    startedAt: string;
    completedAt: string;
    error: string | null;
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
 * VulnZap API provider implementation for specialized security analysis
 * Connects to the VulnZap backend service for enhanced vulnerability detection
 */
export class VulnZapProvider implements APIProvider {
  name = "vulnzap";
  displayName = "VulnZap API";
  private context: vscode.ExtensionContext | undefined;
  private requestQueue: Promise<any> = Promise.resolve();
  private runningJobs: Map<string, string> = new Map(); // filePath -> jobId
  private scanLocks: Map<string, Promise<any>> = new Map(); // filePath -> ongoing scan promise

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
   * Checks if the provider has all required configuration (API key only)
   */
  isConfigured(): boolean {
    const config = vscode.workspace.getConfiguration("vulnzap");
    const apiKey = config.get("vulnzapApiKey", "").trim();

    return apiKey.length > 0;
  }

  /**
   * Returns a list of configuration issues that prevent the provider from working
   */
  getConfigurationErrors(): string[] {
    const errors: string[] = [];
    const config = vscode.workspace.getConfiguration("vulnzap");

    const apiKey = config.get("vulnzapApiKey", "").trim();

    if (!apiKey) {
      errors.push("VulnZap API key is required");
    }

    return errors;
  }

  /**
   * Analyzes code for security vulnerabilities using text-based approach with request queuing
   */
  async analyzeCode(
    code: string,
    filePath: string,
    language: string
  ): Promise<AISecurityResponse> {
    // Check if there's already a scan running for this file
    const existingScan = this.scanLocks.get(filePath);
    if (existingScan) {
      Logger.info(`Cancelling existing scan for ${filePath} and starting new one`);
      // Cancel the existing scan by not awaiting it and letting it be garbage collected
      // The actual job cancellation will happen in performTextBasedAnalysis
    }

    // Create a new scan promise and store it
    const scanPromise = this.performScan(code, filePath, language);
    this.scanLocks.set(filePath, scanPromise);

    try {
      const result = await scanPromise;
      return result;
    } finally {
      // Clean up the scan lock
      this.scanLocks.delete(filePath);
    }
  }

  /**
   * Performs the actual scan with proper error handling
   */
  private async performScan(
    code: string,
    filePath: string,
    language: string
  ): Promise<AISecurityResponse> {
    // Queue requests to prevent overwhelming the API
    return this.queueRequest(async () => {
      const config = vscode.workspace.getConfiguration("vulnzap");
      const apiKey = config.get("vulnzapApiKey", "").trim();

      if (!apiKey) {
        throw new Error("VulnZap API key is required");
      }

      const startTime = Date.now();

      try {
        // Use text-based analysis (AST removed for simplicity and speed)
        Logger.debug(`Using text-based analysis for ${language}`);
        const analysisResult = await this.performTextBasedAnalysis(
          filePath,
          code,
          language,
          apiKey
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
            // This should rarely happen now due to our retry logic, but provide helpful message
            throw new Error(
              "VulnZap API rate limit exceeded. The extension has automatic retry logic, but the API is currently overloaded. Please try again in a few minutes."
            );
          } else if (status >= 500) {
            throw new Error("VulnZap API server error");
          } else {
            throw new Error(`VulnZap API error: ${message}`);
          }
        } else if (
          error.code === "ENOTFOUND" ||
          error.code === "ECONNREFUSED"
        ) {
          throw new Error("Cannot connect to VulnZap API - check URL");
        } else if (error.message.includes("rate limit exceeded")) {
          // This is our custom rate limit error from makeApiCallWithRetry
          throw error;
        } else {
          throw new Error(`VulnZap API error: ${error.message}`);
        }
      }
    });
  }

  /**
   * Queues API requests to prevent overwhelming the server
   */
  private async queueRequest<T>(request: () => Promise<T>): Promise<T> {
    const queueDelay = VulnZapConfig.api.retry.queueDelay;

    const currentRequest = this.requestQueue.then(async () => {
      // Add a configurable delay between requests to be respectful to the API
      if (queueDelay > 0) {
        await this.sleep(queueDelay);
      }
      return request();
    });

    this.requestQueue = currentRequest.catch(() => {
      // Ignore errors in the queue chain to prevent blocking future requests
    });

    return currentRequest;
  }

  /**
   * Perform text-based analysis with rate limiting and retry logic
   */
  private async performTextBasedAnalysis(
    filePath: string,
    code: string,
    language: string,
    apiKey: string
  ): Promise<AISecurityResponse> {
    let jobId: string | undefined;
    
    try {
      // Step 0: Cancel any existing job for this file path
      await this.cancelPreviousJobForFile(filePath, apiKey);

      // Step 1: Start the scan job with retry logic
      const scanResponse = await this.makeApiCallWithRetry(async () => {
        return axios.post(
          getApiUrl("scanContent"),
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
              "User-Agent": VulnZapConfig.userAgent,
            },
          }
      );
    });

    Logger.debug("Scan response:", JSON.stringify(scanResponse.data, null, 2));

      // Extract job ID from the scan response
      jobId = scanResponse.data?.data?.jobId;
      if (!jobId) {
        throw new Error("No job ID returned from scan request");
      }

      // Step 1.5: Register the new job for this file path
      this.runningJobs.set(filePath, jobId);
Logger.info(`Started new scan job ${jobId} for file ${filePath}`);

      // Step 2: Poll for results with exponential backoff (no timeout)
      const initialPollingInterval = VulnZapConfig.api.timeouts.scanPolling.initial;
      const maxPollingInterval = VulnZapConfig.api.timeouts.scanPolling.maximum;

      // Get file info for logging
      const fileSizeKB = Buffer.byteLength(code, "utf8") / 1024;
      const lineCount = code.split("\n").length;

      Logger.info(
        `Starting scan polling for ${filePath} (${fileSizeKB.toFixed(
          1
        )}KB, ${lineCount} lines). No timeout - will poll until completion.`
      );

      // Inform user about potentially long scans for large files
      if (fileSizeKB > 500 || lineCount > 5000) {
        vscode.window.showInformationMessage(
          `VulnZap: Large file detected (${fileSizeKB.toFixed(
            1
          )}KB, ${lineCount} lines). This scan may take several minutes to complete.`,
          { modal: false }
        );
      }

      const startTime = Date.now();
      let pollingInterval = initialPollingInterval;
      let attempt = 0;
      const maxPollingAttempts = VulnZapConfig.api.timeouts.scanPolling.maxAttempts;

      // Poll until job completes, fails, or we hit the failsafe limit
      while (attempt < maxPollingAttempts) {
        try {
          const jobResponse = await this.makeApiCallWithRetry(async () => {
            return axios.get(getJobApiUrl(jobId!), {
              headers: {
                "x-api-key": `${apiKey}`,
                "Content-Type": "application/json",
                "User-Agent": VulnZapConfig.userAgent,
              },
            });
          });

          const jobData = jobResponse.data?.data;
          Logger.debug(
            `Job polling response (attempt ${attempt + 1}):`,
            JSON.stringify(jobResponse.data, null, 2)
          );

          if (!jobData) {
            Logger.warn("No job data received from API response");
            await this.sleep(pollingInterval);
            continue;
          }

          Logger.debug(`Job status: ${jobData.status}`);

          // Provide progress feedback for long-running scans
          const elapsedTime = Date.now() - startTime;
          if (elapsedTime > 60000 && attempt % 3 === 0) {
            // Every 3rd attempt after 1 minute
            const elapsedMinutes = Math.round(elapsedTime / 60000);
            Logger.info(
              `Scan still in progress (${elapsedMinutes} minute${
                elapsedMinutes !== 1 ? "s" : ""
              } elapsed). Job status: ${jobData.status || "unknown"}`
            );
          }

          if (jobData.status?.toLowerCase() === "completed") {
Logger.info(`Job ${jobId} completed for file ${filePath}`);
            // Clean up job tracking
            this.runningJobs.delete(filePath);
            // Step 3: Get the result ID and fetch detailed results
            const resultsData = jobResponse.data;
            if (!resultsData) {
              throw new Error("No results data returned from results endpoint");
            }

            Logger.info(
              `Results data structure:`,
              JSON.stringify(resultsData, null, 2)
            );

            // Additional detailed logging for debugging
            Logger.debug("Response analysis:");
            Logger.debug("- resultsData.success:", resultsData.success);
            Logger.debug("- resultsData.data type:", typeof resultsData.data);
            if (resultsData.data) {
              Logger.debug(
                "- resultsData.data keys:",
                Object.keys(resultsData.data)
              );
            }
            return this.normalizeResponse(resultsData);
          } else if (jobData.status?.toLowerCase() === "failed") {
Logger.error(`Job ${jobId} failed for file ${filePath}: ${jobData.error || "Unknown error"}`);
            // Clean up job tracking
            this.runningJobs.delete(filePath);
            throw new Error(
              `Scan job failed: ${jobData.error || "Unknown error"}`
            );
          }

          // Job is still in progress, wait before next poll with exponential backoff
          await this.sleep(pollingInterval);

          // Increase polling interval exponentially, but cap at maximum
          pollingInterval = Math.min(pollingInterval * 1.5, maxPollingInterval);
          attempt++;
        } catch (error: any) {
          if (error.response?.status === 404) {
            throw new Error("Scan job not found");
          }
          // If it's a rate limit error during polling, it will be handled by makeApiCallWithRetry
          throw error;
        }
      }

      // Failsafe: if we somehow exit the loop without completing
      // Clean up job tracking
      this.runningJobs.delete(filePath);
      const elapsedHours = Math.round((Date.now() - startTime) / 3600000);
      throw new Error(
        `Scan job exceeded maximum polling attempts (${maxPollingAttempts}) after ${elapsedHours} hours. ` +
          `The job may be stuck or the server may be unresponsive. Please try again or contact support.`
      );
    } catch (error) {
      // Ensure job cleanup on any error
      if (jobId) {
        this.runningJobs.delete(filePath);
        Logger.info(`Cleaned up job tracking for ${filePath} due to error`);
      }
      throw error;
    }
  }

  /**
   * Makes an API call with retry logic and exponential backoff for rate limiting
   */
  private async makeApiCallWithRetry<T>(
    apiCall: () => Promise<T>,
    maxRetries?: number
  ): Promise<T> {
    const actualMaxRetries = maxRetries ?? VulnZapConfig.api.retry.defaultAttempts;
    let lastError: any;

    for (let attempt = 0; attempt <= actualMaxRetries; attempt++) {
      try {
        return await apiCall();
      } catch (error: any) {
        lastError = error;

        // Check if it's a rate limit error
        if (error.response?.status === 429) {
          if (attempt < actualMaxRetries) {
            // Extract retry-after header if available
            const retryAfter = error.response.headers["retry-after"];
            let waitTime = retryAfter
              ? parseInt(retryAfter) * 1000
              : this.calculateBackoffDelay(attempt);

            // Cap the wait time to a reasonable maximum (2 minutes)
            waitTime = Math.min(waitTime, 120000);

            Logger.warn(
              `Rate limit exceeded (attempt ${attempt + 1}/${
                actualMaxRetries + 1
              }). ` + `Waiting ${waitTime / 1000} seconds before retry...`
            );

            await this.sleep(waitTime);
            continue;
          } else {
            Logger.error(
              `Rate limit exceeded after ${actualMaxRetries} retries. Giving up.`
            );
            throw new Error(
              "VulnZap API rate limit exceeded. Please try again later."
            );
          }
        }

        // For other errors, don't retry
        throw error;
      }
    }

    throw lastError;
  }

  /**
   * Calculates exponential backoff delay
   */
  private calculateBackoffDelay(attempt: number): number {
    // Exponential backoff: 2^attempt * 1000ms, with jitter
    const baseDelay = Math.pow(2, attempt) * 1000;
    const jitter = Math.random() * 0.1 * baseDelay; // Add up to 10% jitter
    return Math.floor(baseDelay + jitter);
  }

  /**
   * Sleep utility function
   */
  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  /**
   * Cancels a running scan job
   */
  private async cancelJob(jobId: string, apiKey: string): Promise<void> {
    try {
      Logger.info(`Cancelling job: ${jobId}`);
      
      await this.makeApiCallWithRetry(async () => {
        return axios.post(
          getJobApiUrl(jobId, "cancel"),
          {},
          {
            headers: {
              "x-api-key": `${apiKey}`,
              "Content-Type": "application/json",
              "User-Agent": VulnZapConfig.userAgent,
            },
          }
        );
      });
      
      Logger.info(`Successfully cancelled job: ${jobId}`);
    } catch (error: any) {
      Logger.warn(`Failed to cancel job ${jobId}:`, error.message);
      // Don't throw error - cancellation failure shouldn't block new scans
    }
  }

  /**
   * Gets information about currently running jobs (for debugging)
   */
  public getRunningJobsInfo(): { filePath: string; jobId: string }[] {
    return Array.from(this.runningJobs.entries()).map(([filePath, jobId]) => ({
      filePath,
      jobId
    }));
  }

  /**
   * Cancels any running job for the given file path
   */
  private async cancelPreviousJobForFile(filePath: string, apiKey: string): Promise<void> {
    const existingJobId = this.runningJobs.get(filePath);
    if (existingJobId) {
Logger.info(`Cancelling existing job ${existingJobId} for file ${filePath}`);
      try {
        await this.cancelJob(existingJobId, apiKey);
Logger.info(`Successfully cancelled job ${existingJobId}`);
      } catch (error) {
Logger.warn(`Failed to cancel job ${existingJobId}, but continuing with new scan`);
      }
      this.runningJobs.delete(filePath);
    } else {
      Logger.debug(`No existing job found for file ${filePath}`);
    }
  }

  /**
   * Normalizes the response from the VulnZap API
   * @param data - The response from the VulnZap API
   * @returns The normalized response
   */
  private normalizeResponse(data: VulnZapResponse): AISecurityResponse {
    try {
      Logger.debug("Normalizing API response:", JSON.stringify(data, null, 2));

      let allVulnerabilities: any[] = [];
      let totalScanTime = 0;
      let totalLinesOfCode = 0;

      // Enhanced debugging of response structure
      Logger.debug("Response data keys:", Object.keys(data.data || {}));
      if (data.data && typeof data.data === "object") {
        Logger.debug("Data structure analysis:");
        Logger.debug("- Has 'results':", "results" in data.data);
        Logger.debug("- Job status:", data.data.status);
        Logger.debug("- Job progress:", data.data.progress);
        if ("results" in data.data && data.data.results) {
          Logger.debug("- Results keys:", Object.keys(data.data.results));
          if (data.data.results.vulnerabilities) {
            Logger.debug(
              "- Results.vulnerabilities length:",
              data.data.results.vulnerabilities.length
            );
          }
        }
      }

      // Handle new API response format (always has results structure now)
      if (data.data.results && data.data.results.vulnerabilities) {
        const results = data.data.results;

        for (const fileResult of results.vulnerabilities) {
          totalScanTime += fileResult.scanTime || 0;
          totalLinesOfCode += fileResult.linesOfCode || 0;

          // Process taint vulnerabilities with new structure
          if (fileResult.taintVulnerabilities) {
            const taintVulns = fileResult.taintVulnerabilities.map(
              (vuln: TaintVulnerability) => ({
                ...vuln,
                file: fileResult.file,
                language: fileResult.language,
                vulnerabilityType: "taint",
                // Map sink location to standard format
                line: vuln.sink.lineNumber,
                column: 1, // No column info in new format, default to 1
                snippet: vuln.sink.codeSnippet,
                // Include taint flow information
                taintFlowPath: vuln.taintFlowPath,
                // Include patched code information
                patchedCode: vuln.patchedCode,
                // Map severity from confidence (if not provided, infer from confidence)
                severity: this.inferSeverityFromConfidence(vuln.confidence),
              })
            );
            allVulnerabilities.push(...taintVulns);
          }

          // Process standalone vulnerabilities with new format
          if (fileResult.standaloneVulnerabilities) {
            const standaloneVulns = fileResult.standaloneVulnerabilities.map(
              (vuln: StandaloneVulnerability) => ({
                ...vuln,
                file: fileResult.file,
                language: fileResult.language,
                vulnerabilityType: "standalone",
                // Map new format to standard format
                line: vuln.lineNumber,
                column: 1, // No column info in new format, default to 1
                endLine: vuln.lineNumber, // Same line for standalone vulns
                endColumn: vuln.codeSnippet?.length || 10, // Estimate end column
                snippet: vuln.codeSnippet,
                // Map severity from confidence (if not provided, infer from confidence)
                severity: this.inferSeverityFromConfidence(vuln.confidence),
              })
            );
            allVulnerabilities.push(...standaloneVulns);
          }
        }
      } else {
        Logger.warn("No results found in API response - expected results.vulnerabilities structure");
        Logger.debug("Full response for debugging:", JSON.stringify(data, null, 2));
      }

      if (allVulnerabilities.length === 0) {
        Logger.warn("No results found in VulnZap scan response.");
        Logger.warn(
          "Full response structure for debugging:",
          JSON.stringify(data, null, 2)
        );
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
        const severity = vuln.severity?.toLowerCase() || "low";
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
          // Taint vulnerability uses sink location (new format)
          line = vuln.line || vuln.sink?.lineNumber || 1;
          column = vuln.column || 1; // New format doesn't have column info
          endLine = line; // Taint vulns typically don't have end positions
          endColumn = column + (vuln.snippet?.length || 10);
          snippet = vuln.snippet || vuln.sink?.codeSnippet || "";
        } else if (vuln.vulnerabilityType === "standalone") {
          // Standalone vulnerability uses direct line number (new format)
          line = vuln.line || vuln.lineNumber || 1;
          column = vuln.column || 1; // New format doesn't have column info
          endLine = vuln.endLine || line;
          endColumn = vuln.endColumn || column + (vuln.codeSnippet?.length || 10);
          snippet = vuln.snippet || vuln.codeSnippet || "";
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
          suggestion: this.formatSuggestion(vuln) || vuln.remediation,
          confidence: Math.min(
            100,
            Math.max(0, Math.round((vuln.confidence ?? 0.5) * 100))
          ),
          cve: vuln.cwe ? [vuln.cwe] : [],
          searchQuery: vuln.type || vuln.category,
          // Additional data for enhanced analysis
          taintFlowPath: vuln.taintFlowPath,
          patchedCode: vuln.patchedCode, // New field for patched code suggestions
          keywords: vuln.keywords, // New field for vulnerability keywords
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
   * Formats suggestion based on vulnerability type and patched code format
   */
  private formatSuggestion(vuln: any): string | undefined {
    if (!vuln.patchedCode) {
      return undefined;
    }

    // Handle array-based patched code (taint vulnerabilities)
    if (Array.isArray(vuln.patchedCode)) {
      return this.formatPatchedCodeSuggestion(vuln.patchedCode);
    }

    // Handle string-based patched code (standalone vulnerabilities)
    if (typeof vuln.patchedCode === 'string') {
      return this.formatStandalonePatchedCode(vuln.patchedCode);
    }

    return undefined;
  }

  /**
   * Formats patched code into a user-friendly suggestion with actual code implementations
   */
  private formatPatchedCodeSuggestion(patchedCode?: Array<{
    lineNumber: number;
    stepNumber: number;
    codeSnippet: string;
    description: string;
    originalFilePath: string;
  }>): string | undefined {
    if (!patchedCode || patchedCode.length === 0) {
      return undefined;
    }

    // Sort by step number to ensure correct order
    const sortedPatches = [...patchedCode].sort((a, b) => a.stepNumber - b.stepNumber);
    
let suggestion = "**Recommended Fix:**\n\n";
    
    sortedPatches.forEach((patch, index) => {
      suggestion += `**Step ${patch.stepNumber}:** ${patch.description}\n`;
      suggestion += "```\n";
      suggestion += patch.codeSnippet;
      suggestion += "\n```\n";
      if (index < sortedPatches.length - 1) {
        suggestion += "\n";
      }
    });

    return suggestion;
  }

  /**
   * Formats standalone patched code (simple string format)
   */
  private formatStandalonePatchedCode(patchedCode?: string): string | undefined {
    if (!patchedCode || typeof patchedCode !== 'string') {
      return undefined;
    }

return `**Recommended Fix:**\n\n\`\`\`\n${patchedCode}\n\`\`\``;
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
   * Infers severity level from confidence score
   */
  private inferSeverityFromConfidence(confidence: number): string {
    if (confidence >= 90) return "high";
    if (confidence >= 70) return "medium";
    if (confidence >= 50) return "low";
    return "low";
  }

  /**
   * Maps API severity levels to VS Code severity levels
   */
  private mapSeverityToVSCode(
    severity: string | undefined
  ): "error" | "warning" | "info" {
    const normalizedSeverity = severity?.toLowerCase() || "low";
    switch (normalizedSeverity) {
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
