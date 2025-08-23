import * as vscode from "vscode";
import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import { Dependency } from "./dependencyParser";

export interface VulnerabilityInfo {
  packageName: string;
  packageVersion: string;
  ecosystem: string;
  severity: "low" | "medium" | "high" | "critical";
  cveId?: string;
  description: string;
  fixedIn?: string;
  recommendation: string;
  references?: string[];
}

export interface DependencyScanResult {
  projectHash: string;
  dependencies: Dependency[];
  vulnerabilities: VulnerabilityInfo[];
  scanDate: number;
  totalPackages: number;
  vulnerablePackages: number;
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

export interface CacheEntry {
  scanResult: DependencyScanResult;
  timestamp: number;
  dependenciesHash: string;
}

/**
 * Manages caching of dependency scan results to avoid unnecessary API calls
 * Uses project path hashing and dependency content hashing for cache keys
 */
export class DependencyCache {
  private static readonly CACHE_DIR_NAME = ".vulnzap-cache";
  private static readonly DEFAULT_CACHE_EXPIRY_DAYS = 5;

  private cacheDir: string;
  private context: vscode.ExtensionContext;

  constructor(context: vscode.ExtensionContext) {
    this.context = context;
    this.cacheDir = path.join(
      context.globalStorageUri?.fsPath || context.extensionPath,
      DependencyCache.CACHE_DIR_NAME
    );
  }

  /**
   * Generates a unique hash for a project based on its workspace path
   */
  static generateProjectHash(workspacePath: string): string {
    // Normalize path and create hash
    const normalizedPath = path.resolve(workspacePath).toLowerCase();
    return crypto.createHash("md5").update(normalizedPath).digest("hex");
  }

  /**
   * Generates a hash for the current set of dependencies
   * Used to detect if dependencies have changed since last scan
   */
  static generateDependenciesHash(dependencies: Dependency[]): string {
    // Sort dependencies for consistent hashing
    const sortedDeps = dependencies
      .map((dep) => `${dep.ecosystem}:${dep.packageName}:${dep.packageVersion}`)
      .sort();

    const depString = sortedDeps.join("|");
    return crypto.createHash("md5").update(depString).digest("hex");
  }
}
