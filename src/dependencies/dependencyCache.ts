import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { Dependency } from './dependencyParser';

export interface VulnerabilityInfo {
    packageName: string;
    packageVersion: string;
    ecosystem: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
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
    private static readonly CACHE_DIR_NAME = '.vulnzap-cache';
    private static readonly DEFAULT_CACHE_EXPIRY_DAYS = 5;
    
    private cacheDir: string;
    private context: vscode.ExtensionContext;

    constructor(context: vscode.ExtensionContext) {
        this.context = context;
        this.cacheDir = path.join(context.globalStorageUri?.fsPath || context.extensionPath, DependencyCache.CACHE_DIR_NAME);
        this.ensureCacheDirectory();
    }

    /**
     * Gets the cache expiry time in milliseconds from configuration
     */
    private getCacheExpiryMs(): number {
        const config = vscode.workspace.getConfiguration('vulnzap');
        const days = config.get<number>('dependencyCacheExpiry', DependencyCache.DEFAULT_CACHE_EXPIRY_DAYS);
        return days * 24 * 60 * 60 * 1000;
    }

    /**
     * Generates a unique hash for a project based on its workspace path
     */
    static generateProjectHash(workspacePath: string): string {
        // Normalize path and create hash
        const normalizedPath = path.resolve(workspacePath).toLowerCase();
        return crypto.createHash('md5').update(normalizedPath).digest('hex');
    }

    /**
     * Generates a hash for the current set of dependencies
     * Used to detect if dependencies have changed since last scan
     */
    static generateDependenciesHash(dependencies: Dependency[]): string {
        // Sort dependencies for consistent hashing
        const sortedDeps = dependencies
            .map(dep => `${dep.ecosystem}:${dep.packageName}:${dep.packageVersion}`)
            .sort();
        
        const depString = sortedDeps.join('|');
        return crypto.createHash('md5').update(depString).digest('hex');
    }

    /**
     * Retrieves cached scan result for a project if valid and not expired
     */
    async getCachedScanResult(projectHash: string, currentDependencies: Dependency[]): Promise<DependencyScanResult | null> {
        try {
            const cacheFile = this.getCacheFilePath(projectHash);
            
            if (!fs.existsSync(cacheFile)) {
                console.log(`No cache file found for project ${projectHash}`);
                return null;
            }

            const cacheContent = fs.readFileSync(cacheFile, 'utf8');
            const cacheEntry: CacheEntry = JSON.parse(cacheContent);

            // Check if cache is expired
            const now = Date.now();
            const expiryMs = this.getCacheExpiryMs();
            if (now - cacheEntry.timestamp > expiryMs) {
                console.log(`Cache expired for project ${projectHash} (${Math.round((now - cacheEntry.timestamp) / (24 * 60 * 60 * 1000))} days old)`);
                await this.deleteCacheEntry(projectHash);
                return null;
            }

            // Check if dependencies have changed
            const currentDepsHash = DependencyCache.generateDependenciesHash(currentDependencies);
            if (cacheEntry.dependenciesHash !== currentDepsHash) {
                console.log(`Dependencies changed for project ${projectHash}, cache invalidated`);
                await this.deleteCacheEntry(projectHash);
                return null;
            }

            console.log(`Valid cache found for project ${projectHash}`);
            return cacheEntry.scanResult;

        } catch (error) {
            console.error(`Error reading cache for project ${projectHash}:`, error);
            return null;
        }
    }

    /**
     * Stores a scan result in the cache
     */
    async storeScanResult(scanResult: DependencyScanResult, dependencies: Dependency[]): Promise<void> {
        try {
            const dependenciesHash = DependencyCache.generateDependenciesHash(dependencies);
            const cacheEntry: CacheEntry = {
                scanResult,
                timestamp: Date.now(),
                dependenciesHash
            };

            const cacheFile = this.getCacheFilePath(scanResult.projectHash);
            const cacheContent = JSON.stringify(cacheEntry, null, 2);
            
            fs.writeFileSync(cacheFile, cacheContent, 'utf8');
            console.log(`Scan result cached for project ${scanResult.projectHash}`);

        } catch (error) {
            console.error(`Error storing cache for project ${scanResult.projectHash}:`, error);
        }
    }

    /**
     * Deletes a cache entry for a specific project
     */
    async deleteCacheEntry(projectHash: string): Promise<void> {
        try {
            const cacheFile = this.getCacheFilePath(projectHash);
            if (fs.existsSync(cacheFile)) {
                fs.unlinkSync(cacheFile);
                console.log(`Cache deleted for project ${projectHash}`);
            }
        } catch (error) {
            console.error(`Error deleting cache for project ${projectHash}:`, error);
        }
    }

    /**
     * Clears all cached scan results
     */
    async clearAllCache(): Promise<void> {
        try {
            if (fs.existsSync(this.cacheDir)) {
                const files = fs.readdirSync(this.cacheDir);
                for (const file of files) {
                    const filePath = path.join(this.cacheDir, file);
                    if (file.endsWith('.json')) {
                        fs.unlinkSync(filePath);
                    }
                }
                console.log('All dependency cache cleared');
            }
        } catch (error) {
            console.error('Error clearing cache:', error);
        }
    }

    /**
     * Gets statistics about cached entries
     */
    async getCacheStats(): Promise<{
        totalEntries: number;
        totalSize: number;
        oldestEntry: number | null;
        newestEntry: number | null;
        expiredEntries: number;
    }> {
        const stats = {
            totalEntries: 0,
            totalSize: 0,
            oldestEntry: null as number | null,
            newestEntry: null as number | null,
            expiredEntries: 0
        };

        try {
            if (!fs.existsSync(this.cacheDir)) {
                return stats;
            }

            const files = fs.readdirSync(this.cacheDir);
            const now = Date.now();

            for (const file of files) {
                if (!file.endsWith('.json')) continue;

                const filePath = path.join(this.cacheDir, file);
                const fileStat = fs.statSync(filePath);
                stats.totalSize += fileStat.size;
                stats.totalEntries++;

                try {
                    const content = fs.readFileSync(filePath, 'utf8');
                    const cacheEntry: CacheEntry = JSON.parse(content);
                    
                    if (stats.oldestEntry === null || cacheEntry.timestamp < stats.oldestEntry) {
                        stats.oldestEntry = cacheEntry.timestamp;
                    }
                    if (stats.newestEntry === null || cacheEntry.timestamp > stats.newestEntry) {
                        stats.newestEntry = cacheEntry.timestamp;
                    }

                    const expiryMs = this.getCacheExpiryMs();
                    if (now - cacheEntry.timestamp > expiryMs) {
                        stats.expiredEntries++;
                    }
                } catch (error) {
                    // Invalid cache file, count as expired
                    stats.expiredEntries++;
                }
            }
        } catch (error) {
            console.error('Error getting cache stats:', error);
        }

        return stats;
    }

    /**
     * Cleans up expired cache entries
     */
    async cleanupExpiredEntries(): Promise<number> {
        let cleanedCount = 0;

        try {
            if (!fs.existsSync(this.cacheDir)) {
                return cleanedCount;
            }

            const files = fs.readdirSync(this.cacheDir);
            const now = Date.now();

            for (const file of files) {
                if (!file.endsWith('.json')) continue;

                const filePath = path.join(this.cacheDir, file);
                
                try {
                    const content = fs.readFileSync(filePath, 'utf8');
                    const cacheEntry: CacheEntry = JSON.parse(content);
                    
                    const expiryMs = this.getCacheExpiryMs();
                    if (now - cacheEntry.timestamp > expiryMs) {
                        fs.unlinkSync(filePath);
                        cleanedCount++;
                    }
                } catch (error) {
                    // Invalid cache file, delete it
                    fs.unlinkSync(filePath);
                    cleanedCount++;
                }
            }

            console.log(`Cleaned up ${cleanedCount} expired cache entries`);
        } catch (error) {
            console.error('Error cleaning up expired cache entries:', error);
        }

        return cleanedCount;
    }

    /**
     * Checks if a scan result should be refreshed based on age and dependency changes
     */
    shouldRefreshScan(dependencies: Dependency[], projectHash: string): Promise<boolean> {
        return this.getCachedScanResult(projectHash, dependencies).then(result => result === null);
    }

    /**
     * Gets all cached project hashes
     */
    async getCachedProjectHashes(): Promise<string[]> {
        const hashes: string[] = [];

        try {
            if (!fs.existsSync(this.cacheDir)) {
                return hashes;
            }

            const files = fs.readdirSync(this.cacheDir);
            for (const file of files) {
                if (file.endsWith('.json')) {
                    const hash = file.replace('.json', '');
                    hashes.push(hash);
                }
            }
        } catch (error) {
            console.error('Error getting cached project hashes:', error);
        }

        return hashes;
    }

    /**
     * Exports cache data for backup or migration
     */
    async exportCache(): Promise<{ [projectHash: string]: CacheEntry }> {
        const exportData: { [projectHash: string]: CacheEntry } = {};

        try {
            const hashes = await this.getCachedProjectHashes();
            
            for (const hash of hashes) {
                const cacheFile = this.getCacheFilePath(hash);
                if (fs.existsSync(cacheFile)) {
                    const content = fs.readFileSync(cacheFile, 'utf8');
                    exportData[hash] = JSON.parse(content);
                }
            }
        } catch (error) {
            console.error('Error exporting cache:', error);
        }

        return exportData;
    }

    /**
     * Imports cache data from backup
     */
    async importCache(cacheData: { [projectHash: string]: CacheEntry }): Promise<void> {
        try {
            for (const [projectHash, cacheEntry] of Object.entries(cacheData)) {
                const cacheFile = this.getCacheFilePath(projectHash);
                const content = JSON.stringify(cacheEntry, null, 2);
                fs.writeFileSync(cacheFile, content, 'utf8');
            }
            console.log(`Imported cache for ${Object.keys(cacheData).length} projects`);
        } catch (error) {
            console.error('Error importing cache:', error);
        }
    }

    /**
     * Ensures the cache directory exists
     */
    private ensureCacheDirectory(): void {
        try {
            if (!fs.existsSync(this.cacheDir)) {
                fs.mkdirSync(this.cacheDir, { recursive: true });
                console.log(`Created cache directory: ${this.cacheDir}`);
            }
        } catch (error) {
            console.error('Error creating cache directory:', error);
        }
    }

    /**
     * Gets the file path for a project's cache entry
     */
    private getCacheFilePath(projectHash: string): string {
        return path.join(this.cacheDir, `${projectHash}.json`);
    }

    /**
     * Validates a cache entry structure
     */
    private isValidCacheEntry(data: any): data is CacheEntry {
        return data &&
               typeof data.timestamp === 'number' &&
               typeof data.dependenciesHash === 'string' &&
               data.scanResult &&
               typeof data.scanResult.projectHash === 'string' &&
               Array.isArray(data.scanResult.dependencies) &&
               Array.isArray(data.scanResult.vulnerabilities);
    }
}