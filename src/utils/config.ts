/**
 * VulnZap Extension Configuration
 * Centralized configuration for API URLs, timeouts, and other constants
 */

export const VulnZapConfig = {
  /**
   * API Configuration
   */
  api: {
    baseUrl: "https://engine.vulnzap.com",
    endpoints: {
      scanContent: "/api/scan/content",
      scanJobs: "/api/scan/jobs",
      userUsage: "/api/user/usage",
      userProfile: "/api/user/profile",
      dependencyVulnerabilities: "/api/vulnerabilities/dependencies",
      dependencyScanning: "/api/scan/dependency",
    },
    timeouts: {
      defaultRequest: 60000, // 60 seconds
      scanPolling: {
        initial: 15000, // 15 seconds
        maximum: 60000, // 60 seconds
        maxAttempts: 1000,
      },
    },
    retry: {
      defaultAttempts: 3,
      queueDelay: 500, // milliseconds
    },
  },

  /**
   * Scanning Configuration
   */
  scanning: {
    limits: {
      maxFileSizeBytes: 1000000, // 1MB
      maxFileLines: 2000,
      maxIssuesPerFile: 100,
    },
    fastScan: true, // Always enable fast scan
  },

  /**
   * User Agent for API requests
   */
  userAgent: "VulnZap-VSCode-Extension",

  /**
   * Default settings
   */
  defaults: {
    enabled: true,
    dependencyScanning: true,
    dependencyScanOnStartup: true,
    debugLogging: false,
    excludeFilePatterns: [],
  },
};

/**
 * Helper function to get full API URL
 */
export function getApiUrl(endpoint: keyof typeof VulnZapConfig.api.endpoints): string {
  return `${VulnZapConfig.api.baseUrl}${VulnZapConfig.api.endpoints[endpoint]}`;
}

/**
 * Helper function to get job-specific API URL
 */
export function getJobApiUrl(jobId: string, action?: string): string {
  const baseJobUrl = `${VulnZapConfig.api.baseUrl}${VulnZapConfig.api.endpoints.scanJobs}/${jobId}`;
  return action ? `${baseJobUrl}/${action}` : baseJobUrl;
}
