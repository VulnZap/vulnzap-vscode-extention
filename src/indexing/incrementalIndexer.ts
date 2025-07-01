import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import { SimpleCodeChunker, TextChunk } from './textChunker';
import { VectorStorage } from './vectorStorage';
import { MerkleTreeManager, MerkleNode } from './merkleTreeManager';
import { APIProviderManager } from '../providers/apiProviders';
import { Logger } from '../utils/logger';

/**
 * Incremental indexer with file watching and efficient updates
 * Based on Cursor's proven approach for real-time indexing
 */
export class IncrementalIndexer {
    private chunker: SimpleCodeChunker;
    private vectorStorage: VectorStorage;
    private merkleManager: MerkleTreeManager;
    private apiProvider: APIProviderManager;
    
    private fileWatcher?: vscode.FileSystemWatcher;
    private pendingUpdates = new Set<string>();
    private updateTimer?: NodeJS.Timeout;
    private currentTree?: MerkleNode;
    
    private isIndexing = false;
    private indexingProgress?: vscode.Progress<{ message?: string; increment?: number }>;

    // Configuration
    private readonly UPDATE_DEBOUNCE_MS = 1000;
    private readonly BATCH_SIZE = 5;
    private readonly MAX_CONCURRENT_FILES = 10;
    private readonly EXCLUDE_PATTERNS = [
        '**/node_modules/**',
        '**/.git/**',
        '**/dist/**',
        '**/build/**',
        '**/*.log',
        '**/.vscode/**'
    ];

    constructor(
        context: vscode.ExtensionContext,
        vectorStorage: VectorStorage
    ) {
        this.chunker = new SimpleCodeChunker();
        this.vectorStorage = vectorStorage;
        this.merkleManager = new MerkleTreeManager();
        this.apiProvider = new APIProviderManager();
        
        this.loadStoredTree(context);
        this.setupFileWatcher();
    }

    /**
     * Initialize full workspace indexing
     */
    async initializeIndex(): Promise<void> {
        if (this.isIndexing) {
            vscode.window.showWarningMessage('Indexing already in progress');
            return;
        }

        const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
        if (!workspaceFolder) {
            throw new Error('No workspace folder found');
        }

        await vscode.window.withProgress(
            {
                location: vscode.ProgressLocation.Notification,
                title: 'Building codebase index...',
                cancellable: true
            },
            async (progress, token) => {
                this.indexingProgress = progress;
                this.isIndexing = true;

                try {
                    progress.report({ message: 'Scanning workspace files...' });
                    
                    // Build new Merkle tree
                    const newTree = await this.merkleManager.buildTree(workspaceFolder.uri.fsPath);
                    
                    // Detect changes if we have a previous tree
                    let changedFiles: string[] = [];
                    if (this.currentTree) {
                        changedFiles = await this.merkleManager.detectChanges(this.currentTree, newTree);
                        Logger.info(`Detected ${changedFiles.length} changed files`);
                    } else {
                        // First time indexing - get all code files
                        changedFiles = await this.findCodeFiles(workspaceFolder.uri.fsPath);
                        Logger.info(`First-time indexing: ${changedFiles.length} files`);
                    }

                    progress.report({ message: `Processing ${changedFiles.length} files...` });

                    // Process files in batches
                    let processedFiles = 0;
                    for (let i = 0; i < changedFiles.length; i += this.BATCH_SIZE) {
                        if (token.isCancellationRequested) {
                            throw new Error('Indexing cancelled by user');
                        }

                        const batch = changedFiles.slice(i, i + this.BATCH_SIZE);
                        await Promise.all(batch.map(async (file) => {
                            try {
                                await this.indexFile(file);
                                processedFiles++;
                                progress.report({
                                    message: `Indexed ${processedFiles}/${changedFiles.length} files...`,
                                    increment: (100 / changedFiles.length)
                                });
                            } catch (error) {
                                Logger.warn(`Failed to index file ${file}:`, error as Error);
                            }
                        }));

                        // Small delay between batches to respect API rate limits
                        await new Promise(resolve => setTimeout(resolve, 100));
                    }

                    // Update stored tree
                    this.currentTree = newTree;
                    await this.saveCurrentTree();

                    const stats = await this.vectorStorage.getStats();
                    vscode.window.showInformationMessage(
                        `Index built successfully! ${stats.totalChunks} chunks from ${stats.totalFiles} files.`
                    );

                } finally {
                    this.isIndexing = false;
                    this.indexingProgress = undefined;
                }
            }
        );
    }

    /**
     * Index a single file (used for incremental updates)
     */
    async indexFile(filePath: string): Promise<void> {
        try {
            // Check if file should be excluded
            if (this.shouldExcludeFile(filePath)) {
                return;
            }

            const content = await fs.promises.readFile(filePath, 'utf-8');
            
            // Remove existing chunks for this file
            await this.vectorStorage.removeChunksForFile(filePath);

            // Create new chunks
            const chunks = await this.chunker.chunkFile(filePath, content);
            
            if (chunks.length === 0) {
                Logger.debug(`No chunks created for ${filePath}`);
                return;
            }

            // Generate embeddings in batch
            const embeddings = await this.generateEmbeddingsBatch(chunks);

            // Store chunks with embeddings
            await this.vectorStorage.batchStoreChunks(chunks, embeddings);

            Logger.debug(`Indexed ${filePath}: ${chunks.length} chunks`);

        } catch (error) {
            Logger.error(`Failed to index file ${filePath}:`, error as Error);
            throw error;
        }
    }

    /**
     * Handle file system changes
     */
    private setupFileWatcher(): void {
        // Create file watcher for supported file types
        const pattern = '**/*.{js,jsx,ts,tsx,py,java,c,cpp,cs,php,go,rs,rb}';
        this.fileWatcher = vscode.workspace.createFileSystemWatcher(pattern);

        // Debounce file changes
        this.fileWatcher.onDidChange((uri) => {
            this.scheduleUpdate(uri.fsPath);
        });

        this.fileWatcher.onDidCreate((uri) => {
            this.scheduleUpdate(uri.fsPath);
        });

        this.fileWatcher.onDidDelete((uri) => {
            this.handleFileDeleted(uri.fsPath);
        });

        Logger.debug('File watcher initialized');
    }

    /**
     * Schedule a debounced update for a file
     */
    private scheduleUpdate(filePath: string): void {
        this.pendingUpdates.add(filePath);

        if (this.updateTimer) {
            clearTimeout(this.updateTimer);
        }

        this.updateTimer = setTimeout(async () => {
            await this.processUpdates();
        }, this.UPDATE_DEBOUNCE_MS);
    }

    /**
     * Process all pending updates
     */
    private async processUpdates(): Promise<void> {
        if (this.isIndexing) {
            // Defer updates if full indexing is in progress
            setTimeout(() => this.processUpdates(), 1000);
            return;
        }

        const filesToUpdate = Array.from(this.pendingUpdates);
        this.pendingUpdates.clear();

        Logger.debug(`Processing ${filesToUpdate.length} pending updates`);

        for (const filePath of filesToUpdate) {
            try {
                await this.indexFile(filePath);
            } catch (error) {
                Logger.warn(`Failed to update file ${filePath}:`, error as Error);
            }
        }

        // Update Merkle tree after processing updates
        await this.updateMerkleTree();
    }

    /**
     * Handle file deletion
     */
    private async handleFileDeleted(filePath: string): Promise<void> {
        try {
            await this.vectorStorage.removeChunksForFile(filePath);
            Logger.debug(`Removed chunks for deleted file: ${filePath}`);
        } catch (error) {
            Logger.warn(`Failed to remove chunks for deleted file ${filePath}:`, error as Error);
        }
    }

    /**
     * Generate embeddings for a batch of chunks
     */
    private async generateEmbeddingsBatch(chunks: TextChunk[]): Promise<number[][]> {
        const embeddings: number[][] = [];

        // Process in smaller batches to avoid API rate limits
        const batchSize = 10;
        for (let i = 0; i < chunks.length; i += batchSize) {
            const batch = chunks.slice(i, i + batchSize);
            
            const batchEmbeddings = await Promise.all(
                batch.map(chunk => this.generateEmbedding(chunk.content))
            );

            embeddings.push(...batchEmbeddings);

            // Small delay between batches
            if (i + batchSize < chunks.length) {
                await new Promise(resolve => setTimeout(resolve, 50));
            }
        }

        return embeddings;
    }

    /**
     * Generate embedding for text
     */
    private async generateEmbedding(text: string): Promise<number[]> {
        try {
            const provider = this.apiProvider.getCurrentProvider();
            // TODO: Add embedding generation to API provider interface
            // For now, use mock embedding

            // Fallback to mock embedding
            return this.mockEmbedding(text);
        } catch (error) {
            Logger.warn('Embedding generation failed, using mock:', error as Error);
            return this.mockEmbedding(text);
        }
    }

    /**
     * Mock embedding generation for development
     */
    private mockEmbedding(text: string): number[] {
        const words = text.toLowerCase().split(/\s+/);
        const embedding = new Array(384).fill(0);
        
        for (const word of words) {
            const hash = this.simpleHash(word);
            for (let i = 0; i < embedding.length; i++) {
                embedding[i] += Math.sin(hash + i) * 0.1;
            }
        }

        // Normalize
        const norm = Math.sqrt(embedding.reduce((sum, val) => sum + val * val, 0));
        return embedding.map(val => val / (norm || 1));
    }

    /**
     * Find all code files in workspace
     */
    private async findCodeFiles(workspacePath: string): Promise<string[]> {
        const files: string[] = [];
        
        const findFiles = async (dir: string): Promise<void> => {
            try {
                const entries = await fs.promises.readdir(dir, { withFileTypes: true });
                
                for (const entry of entries) {
                    const fullPath = path.join(dir, entry.name);
                    
                    if (this.shouldExcludeFile(fullPath)) {
                        continue;
                    }
                    
                    if (entry.isDirectory()) {
                        await findFiles(fullPath);
                    } else if (entry.isFile() && this.isCodeFile(fullPath)) {
                        files.push(fullPath);
                    }
                }
            } catch (error) {
                Logger.debug(`Cannot read directory ${dir}:`, error as Error);
            }
        };

        await findFiles(workspacePath);
        return files;
    }

    /**
     * Check if file should be excluded from indexing
     */
    private shouldExcludeFile(filePath: string): boolean {
        const normalizedPath = path.normalize(filePath).replace(/\\/g, '/');
        
        return this.EXCLUDE_PATTERNS.some(pattern => {
            // Convert glob pattern to regex
            const regexPattern = pattern
                .replace(/\*\*/g, '.*')
                .replace(/\*/g, '[^/]*');
            const regex = new RegExp(regexPattern);
            return regex.test(normalizedPath);
        });
    }

    /**
     * Check if file is a code file we should index
     */
    private isCodeFile(filePath: string): boolean {
        const codeExtensions = [
            '.js', '.jsx', '.ts', '.tsx',
            '.py', '.java', '.c', '.cpp', '.cs',
            '.php', '.go', '.rs', '.rb',
            '.json', '.yaml', '.yml'
        ];

        const ext = path.extname(filePath).toLowerCase();
        return codeExtensions.includes(ext);
    }

    /**
     * Update Merkle tree after changes
     */
    private async updateMerkleTree(): Promise<void> {
        const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
        if (!workspaceFolder) return;

        try {
            this.currentTree = await this.merkleManager.buildTree(workspaceFolder.uri.fsPath);
            await this.saveCurrentTree();
        } catch (error) {
            Logger.warn('Failed to update Merkle tree:', error as Error);
        }
    }

    /**
     * Load stored Merkle tree
     */
    private async loadStoredTree(context: vscode.ExtensionContext): Promise<void> {
        try {
            const treePath = path.join(context.globalStorageUri.fsPath, 'merkle-tree.json');
            if (fs.existsSync(treePath)) {
                const treeData = await fs.promises.readFile(treePath, 'utf-8');
                this.currentTree = this.merkleManager.deserializeTree(treeData);
                Logger.debug('Loaded stored Merkle tree');
            }
        } catch (error) {
            Logger.debug('No stored Merkle tree found or failed to load');
        }
    }

    /**
     * Save current Merkle tree
     */
    private async saveCurrentTree(): Promise<void> {
        if (!this.currentTree) return;

        try {
            const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
            if (!workspaceFolder) return;

            const storagePath = path.join(vscode.workspace.workspaceFolders![0].uri.fsPath, '.vscode');
            if (!fs.existsSync(storagePath)) {
                fs.mkdirSync(storagePath, { recursive: true });
            }

            const treePath = path.join(storagePath, 'vulnzap-merkle-tree.json');
            const treeData = this.merkleManager.serializeTree(this.currentTree);
            await fs.promises.writeFile(treePath, treeData);
        } catch (error) {
            Logger.warn('Failed to save Merkle tree:', error as Error);
        }
    }

    /**
     * Get indexing statistics
     */
    async getStats(): Promise<{
        totalChunks: number;
        totalFiles: number;
        isIndexing: boolean;
        lastIndexed: Date | null;
        pendingUpdates: number;
    }> {
        const storageStats = await this.vectorStorage.getStats();
        
        return {
            totalChunks: storageStats.totalChunks,
            totalFiles: storageStats.totalFiles,
            isIndexing: this.isIndexing,
            lastIndexed: this.currentTree ? new Date() : null,
            pendingUpdates: this.pendingUpdates.size
        };
    }

    /**
     * Clear all indexed data
     */
    async clearIndex(): Promise<void> {
        await this.vectorStorage.clearAll();
        this.currentTree = undefined;
        this.pendingUpdates.clear();
        
        Logger.info('Index cleared');
    }

    /**
     * Dispose of resources
     */
    dispose(): void {
        if (this.fileWatcher) {
            this.fileWatcher.dispose();
        }
        
        if (this.updateTimer) {
            clearTimeout(this.updateTimer);
        }
    }

    // Helper methods

    private simpleHash(str: string): number {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash;
        }
        return hash;
    }
} 