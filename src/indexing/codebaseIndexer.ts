import * as vscode from 'vscode';
import * as path from 'path';
import { SimpleCodeChunker, TextChunk } from './textChunker';
import { VectorStorage, SearchOptions } from './vectorStorage';
import { CodeRetriever } from './codeRetriever';
import { IncrementalIndexer } from './incrementalIndexer';
import { Logger } from '../utils/logger';

/**
 * Main codebase indexer that orchestrates all components
 * Implements the Cursor-style approach described in CODEBASE_INDEXING_SYSTEM.md
 */
export class CodebaseIndexer {
    private vectorStorage: VectorStorage;
    private codeRetriever: CodeRetriever;
    private incrementalIndexer: IncrementalIndexer;
    private context: vscode.ExtensionContext;

    constructor(context: vscode.ExtensionContext) {
        this.context = context;
        
        // Initialize storage path
        const storagePath = path.join(context.globalStorageUri.fsPath, 'indexing');
        
        // Initialize components
        this.vectorStorage = new VectorStorage(storagePath);
        this.codeRetriever = new CodeRetriever(this.vectorStorage);
        this.incrementalIndexer = new IncrementalIndexer(context, this.vectorStorage);

        Logger.info('Codebase indexer initialized');
    }

    /**
     * Initialize the indexing system
     */
    async initialize(): Promise<void> {
        try {
            Logger.info('Initializing codebase indexing system...');
            
            // Check if user wants to build index on startup
            const config = vscode.workspace.getConfiguration('vulnzap.indexing');
            const autoIndex = config.get('autoIndexOnStartup', false);
            
            if (autoIndex) {
                await this.buildIndex();
            } else {
                // Just show index status
                const stats = await this.getIndexStats();
                if (stats.totalChunks > 0) {
                    Logger.info(`Index loaded: ${stats.totalChunks} chunks from ${stats.totalFiles} files`);
                } else {
                    vscode.window.showInformationMessage(
                        'VulnZap: No index found. Run "Build Security Index" to enable enhanced analysis.',
                        'Build Index'
                    ).then(selection => {
                        if (selection === 'Build Index') {
                            this.buildIndex();
                        }
                    });
                }
            }
        } catch (error) {
            Logger.error('Failed to initialize indexing system:', error as Error);
        }
    }

    /**
     * Build the full codebase index
     */
    async buildIndex(): Promise<void> {
        try {
            await this.incrementalIndexer.initializeIndex();
            
            // Show completion message with stats
            const stats = await this.getIndexStats();
            vscode.window.showInformationMessage(
                `Index built successfully! ${stats.totalChunks} chunks from ${stats.totalFiles} files indexed.`
            );
        } catch (error) {
            Logger.error('Failed to build index:', error as Error);
            vscode.window.showErrorMessage(`Failed to build index: ${(error as Error).message}`);
        }
    }

    /**
     * Search for similar code patterns
     */
    async findSimilarCode(
        query: string,
        options: Partial<SearchOptions> = {}
    ): Promise<TextChunk[]> {
        const defaultOptions: SearchOptions = {
            similarity_threshold: 0.7,
            max_results: 10,
            security_focused: false,
            include_context: false,
            ...options
        };

        try {
            return await this.codeRetriever.searchSimilar(query, defaultOptions);
        } catch (error) {
            Logger.error('Failed to search similar code:', error as Error);
            return [];
        }
    }

    /**
     * Get security analysis context for specific code
     */
    async getSecurityAnalysisContext(
        targetCode: string,
        filePath: string,
        line: number
    ): Promise<{
        similarVulnerabilities: TextChunk[];
        relatedSecurityPatterns: TextChunk[];
        dataFlowRelated: TextChunk[];
        frameworkSpecific: TextChunk[];
    }> {
        try {
            return await this.codeRetriever.getSecurityAnalysisContext(
                targetCode,
                filePath,
                line
            );
        } catch (error) {
            Logger.error('Failed to get security context:', error as Error);
            return {
                similarVulnerabilities: [],
                relatedSecurityPatterns: [],
                dataFlowRelated: [],
                frameworkSpecific: []
            };
        }
    }

    /**
     * Find code related to a modified file
     */
    async findRelatedCode(filePath: string, modifiedLines: number[]): Promise<TextChunk[]> {
        try {
            return await this.codeRetriever.findRelatedCode(filePath, modifiedLines);
        } catch (error) {
            Logger.error('Failed to find related code:', error as Error);
            return [];
        }
    }

    /**
     * Get chunks for a specific file
     */
    async getFileChunks(filePath: string): Promise<TextChunk[]> {
        try {
            return await this.vectorStorage.getChunksByFile(filePath);
        } catch (error) {
            Logger.error('Failed to get file chunks:', error as Error);
            return [];
        }
    }

    /**
     * Find security-relevant code across the codebase
     */
    async findSecurityRelevantCode(
        maxResults: number = 50
    ): Promise<TextChunk[]> {
        try {
            // Use a broad security query to find relevant chunks
            const securityQuery = 'security vulnerability password token authentication authorization encryption';
            
            return await this.findSimilarCode(securityQuery, {
                similarity_threshold: 0.6,
                max_results: maxResults,
                security_focused: true,
                include_context: false
            });
        } catch (error) {
            Logger.error('Failed to find security-relevant code:', error as Error);
            return [];
        }
    }

    /**
     * Analyze code quality and patterns
     */
    async analyzeCodePatterns(
        filePath: string
    ): Promise<{
        complexity: number;
        securityScore: number;
        similarPatterns: TextChunk[];
        recommendations: string[];
    }> {
        try {
            const chunks = await this.getFileChunks(filePath);
            
            if (chunks.length === 0) {
                return {
                    complexity: 0,
                    securityScore: 100,
                    similarPatterns: [],
                    recommendations: ['File not indexed yet. Build index first.']
                };
            }

            // Calculate average complexity
            const avgComplexity = chunks.reduce(
                (sum, chunk) => sum + chunk.metadata.estimatedComplexity,
                0
            ) / chunks.length;

            // Calculate security score (higher is better)
            const securityRelevantChunks = chunks.filter(
                chunk => chunk.metadata.hasSecurityKeywords
            ).length;
            const securityScore = Math.max(0, 100 - (securityRelevantChunks / chunks.length) * 50);

            // Find similar patterns
            const fileContent = chunks.map(c => c.content).join('\n');
            const similarPatterns = await this.findSimilarCode(fileContent, {
                similarity_threshold: 0.8,
                max_results: 5,
                security_focused: false,
                include_context: false
            });

            // Generate recommendations
            const recommendations = this.generateRecommendations(
                avgComplexity,
                securityScore,
                securityRelevantChunks
            );

            return {
                complexity: avgComplexity,
                securityScore,
                similarPatterns: similarPatterns.filter(p => p.filePath !== filePath),
                recommendations
            };
        } catch (error) {
            Logger.error('Failed to analyze code patterns:', error as Error);
            return {
                complexity: 0,
                securityScore: 0,
                similarPatterns: [],
                recommendations: ['Analysis failed: ' + (error as Error).message]
            };
        }
    }

    /**
     * Get indexing statistics
     */
    async getIndexStats(): Promise<{
        totalChunks: number;
        totalFiles: number;
        avgChunkSize: number;
        securityRelevantChunks: number;
        isIndexing: boolean;
        lastIndexed: Date | null;
        pendingUpdates: number;
    }> {
        try {
            const [storageStats, indexerStats] = await Promise.all([
                this.vectorStorage.getStats(),
                this.incrementalIndexer.getStats()
            ]);

            return {
                ...storageStats,
                isIndexing: indexerStats.isIndexing,
                lastIndexed: indexerStats.lastIndexed,
                pendingUpdates: indexerStats.pendingUpdates
            };
        } catch (error) {
            Logger.error('Failed to get index stats:', error as Error);
            return {
                totalChunks: 0,
                totalFiles: 0,
                avgChunkSize: 0,
                securityRelevantChunks: 0,
                isIndexing: false,
                lastIndexed: null,
                pendingUpdates: 0
            };
        }
    }

    /**
     * Clear the entire index
     */
    async clearIndex(): Promise<void> {
        try {
            await this.incrementalIndexer.clearIndex();
            Logger.info('Index cleared successfully');
            vscode.window.showInformationMessage('Index cleared successfully');
        } catch (error) {
            Logger.error('Failed to clear index:', error as Error);
            vscode.window.showErrorMessage(`Failed to clear index: ${(error as Error).message}`);
        }
    }

    /**
     * Check if indexing is currently enabled
     */
    isIndexingEnabled(): boolean {
        const config = vscode.workspace.getConfiguration('vulnzap.indexing');
        return config.get('enabled', true);
    }

    /**
     * Dispose of resources
     */
    async dispose(): Promise<void> {
        try {
            this.incrementalIndexer.dispose();
            await this.vectorStorage.close();
            Logger.debug('Codebase indexer disposed');
        } catch (error) {
            Logger.error('Error disposing codebase indexer:', error as Error);
        }
    }

    // Private helper methods

    /**
     * Generate code recommendations based on analysis
     */
    private generateRecommendations(
        complexity: number,
        securityScore: number,
        securityRelevantChunks: number
    ): string[] {
        const recommendations: string[] = [];

        if (complexity > 10) {
            recommendations.push('Consider refactoring complex functions to improve maintainability');
        }

        if (securityScore < 80) {
            recommendations.push('High number of security-relevant patterns detected. Review for vulnerabilities');
        }

        if (securityRelevantChunks > 0) {
            recommendations.push('Security-sensitive code found. Ensure proper validation and sanitization');
        }

        if (complexity > 15) {
            recommendations.push('Very high complexity detected. Consider breaking down into smaller functions');
        }

        if (recommendations.length === 0) {
            recommendations.push('Code quality looks good. Continue following best practices');
        }

        return recommendations;
    }
}

// Export configuration interface for TypeScript
export interface IndexingConfig {
    enabled: boolean;
    chunkSize: number;
    overlapRatio: number;
    updateDebounceMs: number;
    excludePatterns: string[];
    embeddingModel: string;
    maxConcurrentFiles: number;
    securityKeywordBoost: boolean;
    autoIndexOnStartup: boolean;
} 