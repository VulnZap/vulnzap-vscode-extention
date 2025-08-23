import * as vscode from "vscode";
import axios from "axios";
import { Dependency, DependencyParser } from "./dependencyParser";
import {
  DependencyCache,
  DependencyScanResult,
  VulnerabilityInfo,
} from "./dependencyCache";

export interface BatchScanRequest {
  packages: Array<{
    ecosystem: string;
    packageName: string;
    version: string;
  }>;
}

// Updated interfaces to match actual API response
export interface VulnerabilityData {
  severity: "low" | "medium" | "high" | "critical";
  cveId: string;
  ghsaId?: string;
  vulnerableVersionRange: string;
  firstPatchedVersion?: string;
  summary: string;
  description: string;
  publishedAt: string;
  updatedAt: string;
  references: string[];
  cveStatus: string;
  ghsaStatus?: string;
}

export interface PackageResult {
  message: string;
  found: boolean;
  dataSources: {
    github: VulnerabilityData[];
    nvd: VulnerabilityData[];
    osv: VulnerabilityData[];
    database: VulnerabilityData[];
  };
}

export interface PackageInfo {
  packageName: string;
  ecosystem: string;
  version: string;
}

export interface ScanResultItem {
  package: PackageInfo;
  result: PackageResult;
  processedResult: any;
}

export interface BatchScanResponse {
  message: string;
  status: number;
  data: ScanResultItem[];
}

/**
 * Service for scanning dependencies for vulnerabilities using the VulnZap API
 * Manages batch scanning, caching, and result processing
 */
export class DependencyScanner {
  private parser: DependencyParser;
  private context: vscode.ExtensionContext;
  private dependencyDiagnosticProvider?: any; // Will be set by extension.ts

  // Track scanning progress and state
  private activeScanPromises = new Map<
    string,
    Promise<DependencyScanResult | null>
  >();
  private lastScanTimes = new Map<string, number>();

  constructor(context: vscode.ExtensionContext) {
    this.context = context;
    this.parser = new DependencyParser();
  }

  /**
   * Sets the dependency diagnostic provider for inline vulnerability display
   */
  setDependencyDiagnosticProvider(provider: any) {
    this.dependencyDiagnosticProvider = provider;
  }

  /**
   * Scans all dependencies in the workspace for vulnerabilities
   */
  async scanWorkspaceDependencies(): Promise<DependencyScanResult[]> {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders || workspaceFolders.length === 0) {
      vscode.window.showWarningMessage("No workspace folder found");
      return [];
    }

    const results: DependencyScanResult[] = [];

    for (const folder of workspaceFolders) {
      try {
        console.log(`Scanning dependencies in ${folder.name}`);
        const result = await this.scanProjectDependencies(folder.uri.fsPath);
        if (result) {
          results.push(result);
        }
      } catch (error) {
        console.error(`Error scanning ${folder.name}:`, error);
        vscode.window.showErrorMessage(
          `Failed to scan ${folder.name}: ${error}`
        );
      }
    }

    return results;
  }

  /**
   * Scans dependencies for a specific project folder
   */
  async scanProjectDependencies(
    projectPath: string
  ): Promise<DependencyScanResult | null> {
    const projectHash = DependencyCache.generateProjectHash(projectPath);

    // Check if we're already scanning this project
    if (this.activeScanPromises.has(projectHash)) {
      console.log(`Scan already in progress for project ${projectHash}`);
      return this.activeScanPromises.get(projectHash)!;
    }

    // Create and track the scan promise
    const scanPromise = this.performProjectScan(projectPath, projectHash);
    this.activeScanPromises.set(projectHash, scanPromise);

    try {
      const result = await scanPromise;
      return result;
    } finally {
      this.activeScanPromises.delete(projectHash);
    }
  }

  /**
   * Performs the actual scanning logic for a project
   */
  private async performProjectScan(
    projectPath: string,
    projectHash: string
  ): Promise<DependencyScanResult | null> {
    try {
      // Extract dependencies from project files
      console.log(`Extracting dependencies from ${projectPath}`);
      const dependencies = await this.parser.scanFolderForDependencies(
        projectPath
      );

      if (dependencies.length === 0) {
        console.log(`No dependencies found in ${projectPath}`);
        return null;
      }

      console.log(
        `Found ${dependencies.length} dependencies in ${projectPath}`
      );

      try {
        // Perform fresh scan via API
        console.log(`Performing fresh vulnerability scan for ${projectPath}`);
        const scanResult = await this.performBatchScan(
          projectHash,
          dependencies,
          projectPath
        );

        if (scanResult) {
          // Update last scan time
          this.lastScanTimes.set(projectHash, Date.now());

          // Show results to user
          this.showScanResults(scanResult);
        }

        return scanResult;
      } catch (error) {
        if (axios.isAxiosError(error)) {
          console.error(
            `API error during vulnerability scan:`,
            error.response?.data
          );
          vscode.window.showErrorMessage(
            `Dependency scan failed for ${projectPath}: ${error.response?.data.message}`
          );
        } else {
          console.error(`Error during vulnerability scan:`, error);
          vscode.window.showErrorMessage(
            `Dependency scan failed for ${projectPath}: ${error}`
          );
        }
        return null;
      }
    } catch (error) {
      console.error(`Error scanning project ${projectPath}:`, error);
      vscode.window.showErrorMessage(
        `Dependency scan failed for ${projectPath}: ${error}`
      );
      return null;
    }
  }

  /**
   * Performs batch vulnerability scan via VulnZap API
   */
  private async performBatchScan(
    projectHash: string,
    dependencies: Dependency[],
    projectPath: string
  ): Promise<DependencyScanResult | null> {
    const config = vscode.workspace.getConfiguration("vulnzap");
    const apiKey = config.get<string>("vulnzapApiKey");
    const apiUrl = config.get<string>(
      "vulnzapApiUrl",
      "https://engine.vulnzap.com"
    );
    const timeout = 60000; // Hardcoded timeout: 60 seconds

    if (!apiKey) {
      vscode.window.showErrorMessage(
        "VulnZap API key not configured. Please configure your API key in settings."
      );
      return null;
    }

    try {
      // Prepare batch scan request
      const batchRequest: BatchScanRequest = {
        packages: dependencies.map((dep) => ({
          ecosystem: dep.ecosystem,
          packageName: dep.packageName,
          version: dep.packageVersion,
        })),
      };

      console.log(
        `Sending batch scan request for ${dependencies.length} packages`
      );

      // Show progress indicator
      const progressOptions: vscode.ProgressOptions = {
        location: vscode.ProgressLocation.Notification,
        title: "Scanning Dependencies for Vulnerabilities",
        cancellable: false,
      };

      return vscode.window.withProgress(progressOptions, async (progress) => {
        progress.report({ increment: 0, message: "Scanning packages..." });

        const response = await axios.post<BatchScanResponse>(
          `${apiUrl}/api/scan/dependency`,
          batchRequest,
          {
            headers: {
              "x-api-key": `${apiKey}`,
              "Content-Type": "application/json",
              "User-Agent": "VulnZap-VSCode-Extension",
            },
            timeout,
          }
        );

        progress.report({ increment: 100, message: "Processing results..." });

        if (response.data && response.data.status === 200) {
          return this.processBatchScanResponse(
            projectHash,
            dependencies,
            response.data,
            projectPath
          );
        }

        return null;
      });
    } catch (error) {
      if (axios.isAxiosError(error)) {
        const status = error.response?.status;
        if (status === 401) {
          vscode.window.showErrorMessage(
            "Invalid VulnZap API key. Please check your configuration."
          );
        } else if (status === 429) {
          vscode.window.showErrorMessage(
            "API rate limit exceeded. Please try again later."
          );
        } else if (status && status >= 500) {
          vscode.window.showErrorMessage(
            "VulnZap API server error. Please try again later."
          );
        } else {
          vscode.window.showErrorMessage(
            `API request failed: ${error.response?.statusText || error.message}`
          );
        }
      } else {
        vscode.window.showErrorMessage(
          `Network error during vulnerability scan: ${error}`
        );
      }

      console.error("Batch scan API error:", error);
      return null;
    }
  }

  /**
   * Processes the response from batch scan API with the new format
   */
  private processBatchScanResponse(
    projectHash: string,
    dependencies: Dependency[],
    apiResponse: BatchScanResponse,
    projectPath: string
  ): DependencyScanResult {
    const vulnerabilities: VulnerabilityInfo[] = [];
    const severityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
    let vulnerablePackages = 0;

    // Process each package result
    for (const item of apiResponse.data) {
      if (!item.result.found) {
        continue; // Skip packages with no vulnerabilities
      }

      vulnerablePackages++;
      const packageVulns = this.extractVulnerabilitiesFromDataSources(item);
      vulnerabilities.push(...packageVulns);

      // Count severities
      for (const vuln of packageVulns) {
        if (vuln.severity in severityCounts) {
          severityCounts[vuln.severity as keyof typeof severityCounts]++;
        }
      }
    }

    const scanResult: DependencyScanResult = {
      projectHash,
      dependencies,
      vulnerabilities,
      scanDate: Date.now(),
      totalPackages: apiResponse.data.length,
      vulnerablePackages,
      summary: severityCounts,
    };

    console.log(
      `Scan completed for ${projectPath}: ${vulnerabilities.length} vulnerabilities found across ${vulnerablePackages} packages`
    );
    return scanResult;
  }

  /**
   * Extracts vulnerabilities from all data sources for a package
   */
  private extractVulnerabilitiesFromDataSources(
    item: ScanResultItem
  ): VulnerabilityInfo[] {
    const vulnerabilities: VulnerabilityInfo[] = [];
    const { package: pkg, result } = item;

    // Process vulnerabilities from all data sources
    const allSources = [
      ...result.dataSources.github,
      ...result.dataSources.nvd,
      ...result.dataSources.osv,
      ...result.dataSources.database,
    ];

    // Remove duplicates based on CVE ID
    const uniqueVulns = new Map<string, VulnerabilityData>();
    for (const vuln of allSources) {
      if (
        !uniqueVulns.has(vuln.cveId) ||
        uniqueVulns.get(vuln.cveId)!.references.length < vuln.references.length
      ) {
        uniqueVulns.set(vuln.cveId, vuln);
      }
    }

    // Convert to VulnerabilityInfo format
    for (const vuln of uniqueVulns.values()) {
      vulnerabilities.push({
        packageName: pkg.packageName,
        packageVersion: pkg.version,
        ecosystem: pkg.ecosystem,
        severity: vuln.severity,
        cveId: vuln.cveId,
        description: vuln.description,
        fixedIn: vuln.firstPatchedVersion,
        recommendation: this.generateRecommendation(vuln, pkg),
        references: vuln.references,
      });
    }

    return vulnerabilities;
  }

  /**
   * Generates a recommendation based on vulnerability data
   */
  private generateRecommendation(
    vuln: VulnerabilityData,
    pkg: PackageInfo
  ): string {
    if (vuln.firstPatchedVersion) {
      return `Update ${pkg.packageName} from ${pkg.version} to ${vuln.firstPatchedVersion} or later to fix this vulnerability.`;
    } else {
      return `Review the vulnerability details and consider alternative packages or mitigation strategies for ${pkg.packageName}@${pkg.version}.`;
    }
  }

  /**
   * Shows scan results to the user
   */
  private showScanResults(scanResult: DependencyScanResult): void {
    const { vulnerabilities, summary } = scanResult;
    const totalVulns = vulnerabilities.length;

    // Update dependency diagnostic provider with scan results
    if (this.dependencyDiagnosticProvider) {
      // Find the project path from the scan result (we'll need to get this from the context)
      const workspaceFolders = vscode.workspace.workspaceFolders;
      if (workspaceFolders && workspaceFolders.length > 0) {
        const projectPath = workspaceFolders[0].uri.fsPath;
        this.dependencyDiagnosticProvider.updateDependencyDiagnostics(
          scanResult,
          projectPath
        );
      }
    }

    if (totalVulns === 0) {
      vscode.window.showInformationMessage(
        `✅ No vulnerabilities found in ${scanResult.totalPackages} dependencies.`
      );
      return;
    }

    // Determine severity of notification based on highest severity found
    const hasCritical = summary.critical > 0;
    const hasHigh = summary.high > 0;

    let message = `🔍 Found ${totalVulns} vulnerabilities in ${scanResult.vulnerablePackages} packages: `;
    const parts: string[] = [];

    if (summary.critical > 0) parts.push(`${summary.critical} critical`);
    if (summary.high > 0) parts.push(`${summary.high} high`);
    if (summary.medium > 0) parts.push(`${summary.medium} medium`);
    if (summary.low > 0) parts.push(`${summary.low} low`);

    message += parts.join(", ");

    // Show appropriate notification based on severity
    if (hasCritical) {
      vscode.window
        .showErrorMessage(message, "View Details")
        .then((selection) => {
          if (selection === "View Details") {
            this.showDetailedResults(scanResult);
          }
        });
    } else if (hasHigh) {
      vscode.window
        .showWarningMessage(message, "View Details")
        .then((selection) => {
          if (selection === "View Details") {
            this.showDetailedResults(scanResult);
          }
        });
    } else {
      vscode.window
        .showInformationMessage(message, "View Details")
        .then((selection) => {
          if (selection === "View Details") {
            this.showDetailedResults(scanResult);
          }
        });
    }
  }

  /**
   * Shows detailed vulnerability results in a new document
   */
  private async showDetailedResults(
    scanResult: DependencyScanResult
  ): Promise<void> {
    const content = this.generateDetailedReport(scanResult);

    const document = await vscode.workspace.openTextDocument({
      content,
      language: "markdown",
    });

    await vscode.window.showTextDocument(document);
  }

  /**
   * Generates a detailed markdown report of vulnerabilities
   */
  private generateDetailedReport(scanResult: DependencyScanResult): string {
    const { vulnerabilities, summary, totalPackages, scanDate } = scanResult;

    let report = `# Dependency Vulnerability Report\n\n`;
    report += `**Scan Date:** ${new Date(scanDate).toLocaleString()}\n`;
    report += `**Total Packages:** ${totalPackages}\n`;
    report += `**Vulnerable Packages:** ${scanResult.vulnerablePackages}\n`;
    report += `**Total Vulnerabilities:** ${vulnerabilities.length}\n\n`;

    // Summary section
    report += `## Summary\n\n`;
    report += `- 🔴 Critical: ${summary.critical}\n`;
    report += `- 🟠 High: ${summary.high}\n`;
    report += `- 🟡 Medium: ${summary.medium}\n`;
    report += `- 🔵 Low: ${summary.low}\n\n`;

    if (vulnerabilities.length === 0) {
      report += `✅ No vulnerabilities detected!\n\n`;
      return report;
    }

    // Group vulnerabilities by severity
    const grouped = {
      critical: vulnerabilities.filter((v) => v.severity === "critical"),
      high: vulnerabilities.filter((v) => v.severity === "high"),
      medium: vulnerabilities.filter((v) => v.severity === "medium"),
      low: vulnerabilities.filter((v) => v.severity === "low"),
    };

    // Detailed vulnerabilities
    report += `## Vulnerabilities\n\n`;

    for (const [severity, vulns] of Object.entries(grouped)) {
      if (vulns.length === 0) continue;

      const emoji =
        severity === "critical"
          ? "🔴"
          : severity === "high"
          ? "🟠"
          : severity === "medium"
          ? "🟡"
          : "🔵";

      report += `### ${emoji} ${severity.toUpperCase()} (${vulns.length})\n\n`;

      for (const vuln of vulns) {
        report += `#### ${vuln.packageName}@${vuln.packageVersion}\n\n`;
        report += `**Ecosystem:** ${vuln.ecosystem}\n\n`;
        report += `**Description:** ${vuln.description}\n\n`;

        if (vuln.cveId) {
          report += `**CVE:** [${vuln.cveId}](https://nvd.nist.gov/vuln/detail/${vuln.cveId})\n\n`;
        }

        if (vuln.fixedIn) {
          report += `**Fixed in:** ${vuln.fixedIn}\n\n`;
        }

        report += `**Recommendation:** ${vuln.recommendation}\n\n`;

        if (vuln.references && vuln.references.length > 0) {
          report += `**References:**\n`;
          for (const ref of vuln.references) {
            report += `- [${ref}](${ref})\n`;
          }
          report += "\n";
        }

        report += "---\n\n";
      }
    }

    return report;
  }

  /**
   * Handles file save events to trigger dependency scanning
   */
  async onFileSaved(document: vscode.TextDocument): Promise<void> {
    // Check if dependency scanning is enabled
    const config = vscode.workspace.getConfiguration("vulnzap");
    const isEnabled = config.get<boolean>("enableDependencyScanning", true);

    if (!isEnabled || !this.parser.isDependencyFile(document.fileName)) {
      return;
    }

    console.log(`Dependency file saved: ${document.fileName}`);

    // Get the workspace folder for this file
    const workspaceFolder = vscode.workspace.getWorkspaceFolder(document.uri);
    if (!workspaceFolder) {
      return;
    }

    const projectPath = workspaceFolder.uri.fsPath;
    const projectHash = DependencyCache.generateProjectHash(projectPath);

    // Get configurable debounce time
    const debounceTime = 5000; // Hardcoded debounce: 5 seconds

    // Debounce rapid saves
    const lastScanTime = this.lastScanTimes.get(projectHash) || 0;
    const timeSinceLastScan = Date.now() - lastScanTime;

    if (timeSinceLastScan < debounceTime) {
      console.log(
        `Skipping scan for ${projectPath} - too soon since last scan (${timeSinceLastScan}ms < ${debounceTime}ms)`
      );
      return;
    }

    // Trigger async scan
    this.scanProjectDependencies(projectPath).catch((error) => {
      console.error("Error during automatic dependency scan:", error);
    });
  }

  /**
   * Gets current scan status for a project
   */
  getScanStatus(
    projectPath: string
  ): "scanning" | "completed" | "never-scanned" {
    const projectHash = DependencyCache.generateProjectHash(projectPath);

    if (this.activeScanPromises.has(projectHash)) {
      return "scanning";
    }

    if (this.lastScanTimes.has(projectHash)) {
      return "completed";
    }

    return "never-scanned";
  }

  /**
   * Forces a fresh scan by clearing cache and rescanning
   */
  async forceScan(projectPath?: string): Promise<DependencyScanResult[]> {
    if (projectPath) {
      const projectHash = DependencyCache.generateProjectHash(projectPath);

      const result = await this.scanProjectDependencies(projectPath);
      return result ? [result] : [];
    } else {
      return this.scanWorkspaceDependencies();
    }
  }
}
