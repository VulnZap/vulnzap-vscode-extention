import * as vscode from "vscode";
import { Logger } from "./logger";

export interface UsageData {
  lineScans: number;
  packageScans: number;
  totalScans: number;
  recentScans: Array<{
    id: string;
    type: string;
    status: string;
    startedAt: string;
    completedAt: string;
    metadata?: {
      fileCount: number;
      languages: string[];
    };
  }>;
  scanStats: Array<{
    _count: { id: number };
    status: string;
  }>;
  totalVulnerabilities: number;
  severityBreakdown: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  // Usage limits and tier information
  usageLimits?: {
    lineScansLimit: number;
    packageScansLimit: number;
    tier: string;
  };
}

export interface UserProfile {
  id: string;
  email: string;
  username: string;
  github_username?: string;
  createdAt: string;
  lastLogin: string;
  isActive: boolean;
  github_connected: boolean;
  apiUsage: number;
  usageBased: boolean;
  subscription: {
    id: string;
    tier: string;
    status: string;
    current_period_start: string;
    current_period_end: string;
    line_scans_limit: number;
    package_scans_limit: number;
    toolset_limit: number;
    amplify_prompt_limit: number;
    get_docs_limit: number;
    batch_scan_limit: number;
    vuln_scan_limit: number;
    api_access: boolean;
    audit_logs: boolean;
    dedicated_support: boolean;
    email_alerts: boolean;
    slack_alerts: boolean;
    webhook_alerts: boolean;
    sso_enabled: boolean;
    on_prem: boolean;
  };
}

export interface UsageTier {
  name: string;
  lineScansLimit: number;
  packageScansLimit: number;
  toolCallsLimit: number;
  features: string[];
  price: string;
}

export const USAGE_TIERS: Record<string, UsageTier> = {
  free: {
    name: "Free",
    lineScansLimit: 1000,
    packageScansLimit: 10000,
    toolCallsLimit: 500,
    features: ["Basic scanning", "MCP tools", "Guided onboarding"],
    price: "$0 per month",
  },
  standard: {
    name: "Standard",
    lineScansLimit: 100000,
    packageScansLimit: -1, // -1 means unlimited
    toolCallsLimit: 10000,
    features: ["API access", "Webhooks", "Custom rules", "MCP tools"],
    price: "$29 per month",
  },
  scale: {
    name: "Scale",
    lineScansLimit: 150000, // Updated to match API response
    packageScansLimit: 0, // Updated to match API response (0 means unlimited in this context)
    toolCallsLimit: 150000, // Updated to match toolset_limit from API
    features: ["Priority support", "Higher rate limits", "MCP tools"],
    price: "$99 per month",
  },
  enterprise: {
    name: "Enterprise",
    lineScansLimit: 1000000,
    packageScansLimit: -1,
    toolCallsLimit: -1,
    features: [
      "Business logic enforcement",
      "Dedicated cloud agents",
      "SOC 2 compliance",
      "White label",
      "On-prem",
      "SSO",
    ],
    price: "Custom",
  },
};

export interface UsageResponse {
  success: boolean;
  data: {
    usage: Array<{
      id: number;
      userId: string;
      packageScans: number;
      lineScans: number;
      timestamp: string;
      ipAddress: string | null;
      userAgent: string | null;
      usagePeriod: string;
      subscriptionId: string;
    }>;
    totals: {
      packageScans: number;
      lineScans: number;
    };
    scanStats: Array<{
      _count: { id: number };
      status: string;
    }>;
    totalScans: number;
    recentScans: Array<{
      id: string;
      type: string;
      status: string;
      startedAt: string;
      completedAt: string;
      metadata?: {
        fileCount: number;
        languages: string[];
      };
    }>;
    recentResults: any[];
    totalVulnerabilities: number;
    severityBreakdown: {
      critical: number;
      high: number;
      medium: number;
      low: number;
    };
  };
  message: string;
}

export class UsageService {
  private static instance: UsageService;
  private context: vscode.ExtensionContext;
  private lastUsageData: UsageData | null = null;
  private userProfile: UserProfile | null = null;
  private listeners: Array<(usage: UsageData) => void> = [];

  private constructor(context: vscode.ExtensionContext) {
    this.context = context;
  }

  public static getInstance(context?: vscode.ExtensionContext): UsageService {
    if (!UsageService.instance && context) {
      UsageService.instance = new UsageService(context);
    }
    return UsageService.instance;
  }

  public onUsageUpdated(
    listener: (usage: UsageData) => void
  ): vscode.Disposable {
    this.listeners.push(listener);

    // Immediately call with current data if available
    if (this.lastUsageData) {
      listener(this.lastUsageData);
    }

    return new vscode.Disposable(() => {
      const index = this.listeners.indexOf(listener);
      if (index !== -1) {
        this.listeners.splice(index, 1);
      }
    });
  }

  private notifyListeners(usage: UsageData) {
    this.listeners.forEach((listener) => {
      try {
        listener(usage);
      } catch (error) {
        Logger.error("Error in usage listener:", error as Error);
      }
    });
  }

  public async fetchUsageData(): Promise<UsageData | null> {
    try {
      const config = vscode.workspace.getConfiguration("vulnzap");
      const apiKey = config.get("vulnzapApiKey", "").trim();
      const apiUrl = config.get("vulnzapApiUrl", "").trim();

      if (!apiKey || !apiUrl) {
        throw new Error("VulnZap API key and URL are required");
      }

      Logger.info("Fetching usage data from API...");

      // First, ensure we have the user profile with subscription info
      if (!this.userProfile) {
        await this.fetchUserProfile();
      }

      const response = await fetch(`${apiUrl}/api/user/usage`, {
        method: "GET",
        headers: {
          "x-api-key": apiKey,
          "Content-Type": "application/json",
        },
        cache: "no-store",
      });

      Logger.info("Response received from API...", response);

      if (!response.ok) {
        if (response.status === 401) {
          Logger.warn("Unauthorized - session may have expired");
          return null;
        }
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const usageResponse: UsageResponse = await response.json();

      Logger.info("Usage response received from API...", usageResponse);

      if (!usageResponse.success) {
        throw new Error(usageResponse.message || "Failed to fetch usage data");
      }

      const usageLimits = this.getUsageLimitsFromProfile();
      Logger.debug("Usage limits from profile:", usageLimits);

      const subscription = this.userProfile?.subscription;
      Logger.info("Subscription data:", subscription);

      const usageData: UsageData & {
        subscription: UserProfile["subscription"];
      } = {
        lineScans: usageResponse.data.totals.lineScans,
        packageScans: usageResponse.data.totals.packageScans,
        totalScans: usageResponse.data.totalScans,
        recentScans: usageResponse.data.recentScans,
        scanStats: usageResponse.data.scanStats,
        totalVulnerabilities: usageResponse.data.totalVulnerabilities,
        severityBreakdown: usageResponse.data.severityBreakdown,
        usageLimits: usageLimits,
        subscription: subscription as UserProfile["subscription"],
      };

      this.lastUsageData = usageData;
      this.notifyListeners(usageData);

      Logger.debug(
        `Usage data fetched: ${usageData.lineScans} line scans, ${usageData.totalScans} total scans, tier: ${usageData.usageLimits?.tier}`
      );
      return usageData;
    } catch (error) {
      Logger.error("Error fetching usage data:", error as Error);
      return null;
    }
  }

  /**
   * Fetches the user profile including subscription tier information
   */
  public async fetchUserProfile(): Promise<UserProfile | null> {
    try {
      const config = vscode.workspace.getConfiguration("vulnzap");
      const apiKey = config.get("vulnzapApiKey", "").trim();
      const apiUrl = config.get("vulnzapApiUrl", "").trim();

      if (!apiKey || !apiUrl) {
        Logger.warn("VulnZap API key and URL are required for profile fetch");
        return null;
      }

      Logger.debug("Fetching user profile from API...");

      const response = await fetch(`${apiUrl}/api/user/profile`, {
        method: "GET",
        headers: {
          "x-api-key": apiKey,
          "Content-Type": "application/json",
        },
        cache: "no-store",
      });

      if (!response.ok) {
        if (response.status === 401) {
          Logger.warn("Unauthorized - API key may be invalid");
          return null;
        }
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const profileResponse = await response.json();

      if (!profileResponse.success) {
        throw new Error(
          profileResponse.message || "Failed to fetch user profile"
        );
      }

      this.userProfile = profileResponse.data.user;
      Logger.debug(
        `User profile fetched: ${this.userProfile?.email}, tier: ${this.userProfile?.subscription.tier}`
      );

      return this.userProfile;
    } catch (error) {
      Logger.error("Error fetching user profile:", error as Error);
      return null;
    }
  }

  public getLastUsageData(): UsageData | null {
    return this.lastUsageData;
  }

  public async refreshUsage(): Promise<void> {
    await this.fetchUsageData();
  }

  /**
   * Refreshes both user profile and usage data
   */
  public async refreshAll(): Promise<void> {
    await this.fetchUserProfile();
    await this.fetchUsageData();
  }

  // Start periodic refresh of usage data
  public startPeriodicRefresh(intervalMs: number = 300000): vscode.Disposable {
    let refreshCount = 0;
    const interval = setInterval(() => {
      refreshCount++;
      // Refresh profile every 10th refresh cycle (approximately every 50 minutes if interval is 5 minutes)
      if (refreshCount % 10 === 0) {
        this.refreshAll();
      } else {
        this.fetchUsageData();
      }
    }, intervalMs);

    return new vscode.Disposable(() => {
      clearInterval(interval);
    });
  }

  /**
   * Gets usage limits from the user profile (actual subscription tier)
   */
  private getUsageLimitsFromProfile():
    | {
        lineScansLimit: number;
        packageScansLimit: number;
        tier: string;
      }
    | undefined {
    if (!this.userProfile) {
      Logger.debug("No user profile available, using fallback limits");
      // Fallback to free tier limits if no profile is available
      return {
        lineScansLimit: USAGE_TIERS.free.lineScansLimit,
        packageScansLimit: USAGE_TIERS.free.packageScansLimit,
        tier: "free",
      };
    }

    Logger.debug("User profile available:", this.userProfile);
    Logger.debug("Subscription data:", this.userProfile.subscription);

    const limits = {
      lineScansLimit: this.userProfile.subscription.line_scans_limit,
      packageScansLimit: this.userProfile.subscription.package_scans_limit,
      tier: this.userProfile.subscription.tier.toLowerCase(),
    };

    Logger.debug("Calculated usage limits:", limits);
    return limits;
  }

  /**
   * Gets the current user profile
   */
  public getUserProfile(): UserProfile | null {
    return this.userProfile;
  }

  /**
   * Gets usage tier information
   */
  public getUsageTier(tierName: string): UsageTier | null {
    return USAGE_TIERS[tierName] || null;
  }

  /**
   * Calculates usage percentage for line scans
   */
  public calculateUsagePercentage(usageData: UsageData): number {
    if (!usageData.usageLimits) return 0;

    const { lineScans, usageLimits } = usageData;
    if (usageLimits.lineScansLimit === -1 || usageLimits.lineScansLimit <= 0)
      return 0; // Unlimited

    return Math.min(100, (lineScans / usageLimits.lineScansLimit) * 100);
  }

  /**
   * Gets remaining line scans
   */
  public getRemainingLineScans(usageData: UsageData): number {
    if (!usageData.usageLimits) return 0;

    const { lineScans, usageLimits } = usageData;
    if (usageLimits.lineScansLimit === -1 || usageLimits.lineScansLimit <= 0)
      return -1; // Unlimited

    return Math.max(0, usageData.usageLimits.lineScansLimit - lineScans);
  }
}
