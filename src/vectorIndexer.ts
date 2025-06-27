import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import { APIProviderManager } from './apiProviders';
import { ContextAnalyzer, CodeContext } from './contextAnalyzer';

export interface CodeChunk {
    id: string;
    filePath: string;
    startLine: number;
    endLine: number;
    content: string;
    contentHash: string;
    lastModified: number;
    codeContext: CodeContext;
    embedding?: number[];
    semanticType: 'function' | 'class' | 'import' | 'config' | 'variable' | 'comment' | 'unknown';
    securityRelevance: 'high' | 'medium' | 'low' | 'none';
    relationships: CodeRelationship[];
}

export interface CodeRelationship {
    type: 'imports' | 'calls' | 'inherits' | 'implements' | 'references' | 'similar';
    targetChunkId: string;
    confidence: number;
    metadata?: Record<string, any>;
}

export interface IndexMetadata {
    version: string;
    lastFullIndex: number;
    fileHashes: Map<string, string>;
    embeddingModel: string;
    totalChunks: number;
}

export interface SearchResult {
    chunk: CodeChunk;
    similarity: number;
    relevanceScore: number;
    contextMatch: boolean;
}

export class VectorIndexer {
    private chunks = new Map<string, CodeChunk>();
    private fileToChunks = new Map<string, string[]>();
    private embeddingCache = new Map<string, number[]>();
    private indexMetadata: IndexMetadata;
    private contextAnalyzer: ContextAnalyzer;
    private apiProviderManager: APIProviderManager;
    private indexPath: string;
    private isIndexing = false;
    private indexingProgress: vscode.Progress<{ message?: string; increment?: number }> | null = null;

    private readonly CHUNK_SIZE = 500; // Lines per chunk
    private readonly CHUNK_OVERLAP = 50; // Overlapping lines between chunks
    private readonly EMBEDDING_DIMENSION = 1536; // Common for OpenAI embeddings
    private readonly SIMILARITY_THRESHOLD = 0.7;
    private readonly INDEX_VERSION = '1.0.0';

    constructor(context: vscode.ExtensionContext) {
        this.contextAnalyzer = new ContextAnalyzer();
        this.apiProviderManager = new APIProviderManager();
        this.indexPath = path.join(context.globalStorageUri.fsPath, 'vectorIndex');
        
        this.indexMetadata = {
            version: this.INDEX_VERSION,
            lastFullIndex: 0,
            fileHashes: new Map(),
            embeddingModel: 'text-embedding-ada-002',
            totalChunks: 0
        };

        this.ensureIndexDirectory();
        this.loadIndex();
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
                title: 'VulnZap: Building security index...',
                cancellable: true
            },
            async (progress, token) => {
                this.indexingProgress = progress;
                this.isIndexing = true;

                try {
                    progress.report({ message: 'Scanning workspace files...' });
                    const files = await this.findCodeFiles(workspaceFolder.uri.fsPath);
                    
                    progress.report({ message: `Found ${files.length} files to index...` });
                    
                    let processedFiles = 0;
                    const batchSize = 5; // Process files in batches to avoid overwhelming the API

                    for (let i = 0; i < files.length; i += batchSize) {
                        if (token.isCancellationRequested) {
                            throw new Error('Indexing cancelled by user');
                        }

                        const batch = files.slice(i, i + batchSize);
                        await Promise.all(batch.map(async (file) => {
                            try {
                                await this.indexFile(file);
                                processedFiles++;
                                progress.report({
                                    message: `Indexed ${processedFiles}/${files.length} files...`,
                                    increment: (100 / files.length)
                                });
                            } catch (error) {
                                console.error(`Failed to index file ${file}:`, error);
                            }
                        }));

                        // Small delay between batches to respect API rate limits
                        await new Promise(resolve => setTimeout(resolve, 100));
                    }

                    progress.report({ message: 'Building relationships...' });
                    await this.buildRelationships();

                    progress.report({ message: 'Saving index...' });
                    await this.saveIndex();

                    this.indexMetadata.lastFullIndex = Date.now();
                    vscode.window.showInformationMessage(
                        `VulnZap: Index built successfully! Indexed ${this.chunks.size} code chunks from ${processedFiles} files.`
                    );
                } finally {
                    this.isIndexing = false;
                    this.indexingProgress = null;
                }
            }
        );
    }

    /**
     * Index a single file (used for incremental updates)
     */
    async indexFile(filePath: string): Promise<void> {
        try {
            const content = await fs.promises.readFile(filePath, 'utf-8');
            const document = await vscode.workspace.openTextDocument(filePath);
            
            // Calculate file hash to detect changes
            const contentHash = this.calculateHash(content);
            const existingHash = this.indexMetadata.fileHashes.get(filePath);

            // Skip if file hasn't changed
            if (existingHash === contentHash) {
                return;
            }

            // Remove existing chunks for this file
            this.removeFileFromIndex(filePath);

            // Analyze document context
            const codeContext = await this.contextAnalyzer.analyzeDocumentContext(document);

            // Create chunks from the file
            const chunks = this.createChunksFromFile(filePath, content, codeContext);

            // Generate embeddings for each chunk
            for (const chunk of chunks) {
                try {
                    chunk.embedding = await this.generateEmbedding(chunk.content);
                    this.chunks.set(chunk.id, chunk);
                    
                    if (!this.fileToChunks.has(filePath)) {
                        this.fileToChunks.set(filePath, []);
                    }
                    this.fileToChunks.get(filePath)!.push(chunk.id);
                } catch (error) {
                    console.error(`Failed to generate embedding for chunk ${chunk.id}:`, error);
                }
            }

            // Update metadata
            this.indexMetadata.fileHashes.set(filePath, contentHash);
            this.indexMetadata.totalChunks = this.chunks.size;

        } catch (error) {
            console.error(`Failed to index file ${filePath}:`, error);
            throw error;
        }
    }

    /**
     * Search for similar code chunks based on the given code snippet
     */
    async findSimilarCode(
        code: string, 
        options: {
            maxResults?: number;
            similarityThreshold?: number;
            includeContext?: boolean;
            securityRelevanceOnly?: boolean;
        } = {}
    ): Promise<SearchResult[]> {
        const {
            maxResults = 10,
            similarityThreshold = this.SIMILARITY_THRESHOLD,
            includeContext = true,
            securityRelevanceOnly = false
        } = options;

        try {
            // Generate embedding for the search query
            const queryEmbedding = await this.generateEmbedding(code);

            // Calculate similarities with all chunks
            const similarities: Array<{ chunk: CodeChunk; similarity: number }> = [];

            for (const chunk of this.chunks.values()) {
                if (!chunk.embedding) continue;

                // Filter by security relevance if requested
                if (securityRelevanceOnly && chunk.securityRelevance === 'none') {
                    continue;
                }

                const similarity = this.cosineSimilarity(queryEmbedding, chunk.embedding);
                if (similarity >= similarityThreshold) {
                    similarities.push({ chunk, similarity });
                }
            }

            // Sort by similarity and limit results
            similarities.sort((a, b) => b.similarity - a.similarity);
            const topResults = similarities.slice(0, maxResults);

            // Convert to SearchResult format with additional scoring
            return topResults.map(({ chunk, similarity }) => ({
                chunk,
                similarity,
                relevanceScore: this.calculateRelevanceScore(chunk, code),
                contextMatch: includeContext ? this.hasContextualRelationship(chunk, code) : false
            }));

        } catch (error) {
            console.error('Failed to search similar code:', error);
            return [];
        }
    }

    /**
     * Find code chunks that are related to a specific file/function that was modified
     */
    async findRelatedCode(filePath: string, modifiedLines: number[]): Promise<CodeChunk[]> {
        const relatedChunks: CodeChunk[] = [];
        const fileChunkIds = this.fileToChunks.get(filePath) || [];

        // Find chunks that contain the modified lines
        const affectedChunks = fileChunkIds
            .map(id => this.chunks.get(id))
            .filter((chunk): chunk is CodeChunk => {
                if (!chunk) return false;
                return modifiedLines.some(line => 
                    line >= chunk.startLine && line <= chunk.endLine
                );
            });

        // Find chunks related to the affected chunks
        for (const chunk of affectedChunks) {
            relatedChunks.push(chunk);

            // Add directly related chunks through relationships
            for (const relationship of chunk.relationships) {
                const relatedChunk = this.chunks.get(relationship.targetChunkId);
                if (relatedChunk && !relatedChunks.includes(relatedChunk)) {
                    relatedChunks.push(relatedChunk);
                }
            }

            // Find semantically similar chunks
            if (chunk.embedding) {
                const similarChunks = await this.findSimilarCode(chunk.content, {
                    maxResults: 5,
                    similarityThreshold: 0.8
                });

                for (const result of similarChunks) {
                    if (!relatedChunks.includes(result.chunk)) {
                        relatedChunks.push(result.chunk);
                    }
                }
            }
        }

        return relatedChunks;
    }

    /**
     * Get comprehensive context for security analysis
     */
    async getSecurityAnalysisContext(
        targetCode: string,
        filePath: string,
        line: number
    ): Promise<{
        similarVulnerabilities: CodeChunk[];
        relatedSecurityPatterns: CodeChunk[];
        dataFlowRelated: CodeChunk[];
        frameworkSpecific: CodeChunk[];
    }> {
        // Find similar vulnerability patterns
        const similarVulnerabilities = (await this.findSimilarCode(targetCode, {
            maxResults: 5,
            securityRelevanceOnly: true,
            similarityThreshold: 0.6
        })).map(result => result.chunk);

        // Find related security patterns in the same file/function
        const relatedCode = await this.findRelatedCode(filePath, [line]);
        const relatedSecurityPatterns = relatedCode.filter(chunk => 
            chunk.securityRelevance !== 'none'
        );

        // Find data flow related chunks (functions that handle similar data types)
        const dataFlowRelated = await this.findDataFlowRelatedChunks(targetCode);

        // Find framework-specific security patterns
        const frameworkSpecific = await this.findFrameworkSpecificPatterns(filePath);

        return {
            similarVulnerabilities,
            relatedSecurityPatterns,
            dataFlowRelated,
            frameworkSpecific
        };
    }

    private createChunksFromFile(filePath: string, content: string, codeContext: CodeContext): CodeChunk[] {
        const lines = content.split('\n');
        const chunks: CodeChunk[] = [];
        const fileName = path.basename(filePath);

        // Create chunks with overlap
        for (let i = 0; i < lines.length; i += this.CHUNK_SIZE - this.CHUNK_OVERLAP) {
            const endLine = Math.min(i + this.CHUNK_SIZE, lines.length);
            const chunkContent = lines.slice(i, endLine).join('\n');
            
            if (chunkContent.trim().length === 0) continue;

            const chunkId = `${filePath}:${i}-${endLine}:${this.calculateHash(chunkContent)}`;
            
            chunks.push({
                id: chunkId,
                filePath,
                startLine: i + 1, // 1-indexed
                endLine,
                content: chunkContent,
                contentHash: this.calculateHash(chunkContent),
                lastModified: Date.now(),
                codeContext,
                semanticType: this.determineSemanticType(chunkContent),
                securityRelevance: this.assessSecurityRelevance(chunkContent, codeContext),
                relationships: []
            });
        }

        return chunks;
    }

    private async generateEmbedding(text: string): Promise<number[]> {
        // Check cache first
        const cacheKey = this.calculateHash(text);
        if (this.embeddingCache.has(cacheKey)) {
            return this.embeddingCache.get(cacheKey)!;
        }

        try {
            // Use the current API provider to generate embeddings
            const provider = this.apiProviderManager.getCurrentProvider();
            if (!provider || !provider.isConfigured()) {
                throw new Error('No configured API provider for embedding generation');
            }

            // Note: This would need to be implemented in the API providers
            // For now, we'll create a placeholder that returns a random vector
            const embedding = await this.mockEmbeddingGeneration(text);
            
            this.embeddingCache.set(cacheKey, embedding);
            return embedding;
        } catch (error) {
            console.error('Failed to generate embedding:', error);
            // Return a zero vector as fallback
            return new Array(this.EMBEDDING_DIMENSION).fill(0);
        }
    }

    private async mockEmbeddingGeneration(text: string): Promise<number[]> {
        // This is a mock implementation. In a real scenario, you would:
        // 1. Use OpenAI's embedding API
        // 2. Use local embedding models (like sentence-transformers)
        // 3. Use other embedding services
        
        // For demonstration, create a simple hash-based embedding
        const hash = this.calculateHash(text);
        const embedding = new Array(this.EMBEDDING_DIMENSION).fill(0);
        
        for (let i = 0; i < hash.length && i < this.EMBEDDING_DIMENSION; i++) {
            embedding[i] = hash.charCodeAt(i) / 255.0;
        }
        
        // Normalize the vector
        const magnitude = Math.sqrt(embedding.reduce((sum, val) => sum + val * val, 0));
        return embedding.map(val => magnitude > 0 ? val / magnitude : 0);
    }

    private cosineSimilarity(a: number[], b: number[]): number {
        if (a.length !== b.length) return 0;
        
        let dotProduct = 0;
        let normA = 0;
        let normB = 0;
        
        for (let i = 0; i < a.length; i++) {
            dotProduct += a[i] * b[i];
            normA += a[i] * a[i];
            normB += b[i] * b[i];
        }
        
        if (normA === 0 || normB === 0) return 0;
        return dotProduct / (Math.sqrt(normA) * Math.sqrt(normB));
    }

    private determineSemanticType(content: string): CodeChunk['semanticType'] {
        if (/^\s*(import|from|require)\s+/.test(content)) return 'import';
        if (/^\s*(function|def|class)\s+/.test(content)) return 'function';
        if (/^\s*class\s+/.test(content)) return 'class';
        if (/^\s*(const|let|var)\s+/.test(content)) return 'variable';
        if (/^\s*(\/\*|\*|\/\/|#)/.test(content)) return 'comment';
        return 'unknown';
    }

    private assessSecurityRelevance(content: string, codeContext: CodeContext): CodeChunk['securityRelevance'] {
        const securityKeywords = [
            'password', 'token', 'secret', 'key', 'auth', 'login', 'encrypt', 'decrypt',
            'sql', 'query', 'database', 'inject', 'xss', 'csrf', 'cors', 'sanitize',
            'validate', 'escape', 'html', 'script', 'eval', 'exec', 'system'
        ];

        const highRiskPatterns = [
            /eval\s*\(/,
            /exec\s*\(/,
            /innerHTML\s*=/,
            /dangerouslySetInnerHTML/,
            /document\.write/,
            /\.sql\s*=/,
            /password\s*=\s*['"]/
        ];

        // Check for high-risk patterns
        if (highRiskPatterns.some(pattern => pattern.test(content))) {
            return 'high';
        }

        // Check for security keywords
        const keywordCount = securityKeywords.filter(keyword => 
            content.toLowerCase().includes(keyword)
        ).length;

        if (keywordCount >= 3) return 'high';
        if (keywordCount >= 1) return 'medium';
        if (codeContext.isTestFile) return 'low';
        
        return 'none';
    }

    // Additional helper methods...
    
    private calculateHash(content: string): string {
        // Simple hash function - in production, consider using a proper crypto hash
        let hash = 0;
        for (let i = 0; i < content.length; i++) {
            const char = content.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // Convert to 32-bit integer
        }
        return hash.toString(16);
    }

    private calculateRelevanceScore(chunk: CodeChunk, queryCode: string): number {
        // Implement relevance scoring based on various factors
        let score = 0;
        
        // Security relevance bonus
        switch (chunk.securityRelevance) {
            case 'high': score += 0.3; break;
            case 'medium': score += 0.2; break;
            case 'low': score += 0.1; break;
        }
        
        // Semantic type relevance
        if (chunk.semanticType === 'function') score += 0.2;
        if (chunk.semanticType === 'class') score += 0.15;
        
        return Math.min(score, 1.0);
    }

    private hasContextualRelationship(chunk: CodeChunk, queryCode: string): boolean {
        // Check if there are meaningful relationships
        return chunk.relationships.length > 0;
    }

    private async buildRelationships(): Promise<void> {
        // Build relationships between chunks based on imports, function calls, etc.
        for (const chunk of this.chunks.values()) {
            chunk.relationships = await this.findChunkRelationships(chunk);
        }
    }

    private async findChunkRelationships(chunk: CodeChunk): Promise<CodeRelationship[]> {
        const relationships: CodeRelationship[] = [];
        
        // Find import relationships
        const importMatches = chunk.content.match(/import.*from\s+['"]([^'"]+)['"]/g);
        if (importMatches) {
            for (const match of importMatches) {
                const importPath = match.match(/from\s+['"]([^'"]+)['"]/)?.[1];
                if (importPath) {
                    // Find chunks that might be related to this import
                    const relatedChunks = this.findChunksByPath(importPath);
                    for (const relatedChunk of relatedChunks) {
                        relationships.push({
                            type: 'imports',
                            targetChunkId: relatedChunk.id,
                            confidence: 0.9
                        });
                    }
                }
            }
        }

        return relationships;
    }

    private findChunksByPath(searchPath: string): CodeChunk[] {
        const results: CodeChunk[] = [];
        for (const chunk of this.chunks.values()) {
            if (chunk.filePath.includes(searchPath)) {
                results.push(chunk);
            }
        }
        return results;
    }

    private async findDataFlowRelatedChunks(code: string): Promise<CodeChunk[]> {
        // Find chunks that handle similar data patterns
        const dataPatterns = this.extractDataPatterns(code);
        const relatedChunks: CodeChunk[] = [];

        for (const chunk of this.chunks.values()) {
            if (this.hasMatchingDataPatterns(chunk.content, dataPatterns)) {
                relatedChunks.push(chunk);
            }
        }

        return relatedChunks.slice(0, 5); // Limit results
    }

    private extractDataPatterns(code: string): string[] {
        const patterns: string[] = [];
        
        // Extract variable patterns
        const variableMatches = code.match(/\b(req|res|user|data|input|output|password|token)\b/g);
        if (variableMatches) {
            patterns.push(...variableMatches);
        }

        return [...new Set(patterns)]; // Remove duplicates
    }

    private hasMatchingDataPatterns(content: string, patterns: string[]): boolean {
        return patterns.some(pattern => content.includes(pattern));
    }

    private async findFrameworkSpecificPatterns(filePath: string): Promise<CodeChunk[]> {
        const fileContent = await fs.promises.readFile(filePath, 'utf-8');
        const framework = this.detectFramework(fileContent);
        
        if (!framework) return [];

        const frameworkChunks: CodeChunk[] = [];
        for (const chunk of this.chunks.values()) {
            if (chunk.content.toLowerCase().includes(framework.toLowerCase())) {
                frameworkChunks.push(chunk);
            }
        }

        return frameworkChunks.slice(0, 5);
    }

    private detectFramework(content: string): string | null {
        const frameworks = ['express', 'react', 'angular', 'vue', 'fastapi', 'django', 'spring'];
        
        for (const framework of frameworks) {
            if (content.toLowerCase().includes(framework)) {
                return framework;
            }
        }
        
        return null;
    }

    private removeFileFromIndex(filePath: string): void {
        const chunkIds = this.fileToChunks.get(filePath) || [];
        for (const chunkId of chunkIds) {
            this.chunks.delete(chunkId);
        }
        this.fileToChunks.delete(filePath);
        this.indexMetadata.fileHashes.delete(filePath);
    }

    private async findCodeFiles(workspacePath: string): Promise<string[]> {
        const files: string[] = [];
        const extensions = ['.js', '.ts', '.jsx', '.tsx', '.py', '.java', '.php', '.rb', '.go', '.rs'];
        
        const findFiles = async (dir: string): Promise<void> => {
            const items = await fs.promises.readdir(dir, { withFileTypes: true });
            
            for (const item of items) {
                const fullPath = path.join(dir, item.name);
                
                if (item.isDirectory()) {
                    // Skip common directories to ignore
                    if (!['node_modules', '.git', 'dist', 'build', '__pycache__'].includes(item.name)) {
                        await findFiles(fullPath);
                    }
                } else {
                    const ext = path.extname(item.name);
                    if (extensions.includes(ext)) {
                        files.push(fullPath);
                    }
                }
            }
        };

        await findFiles(workspacePath);
        return files;
    }

    private setupFileWatcher(): void {
        const watcher = vscode.workspace.createFileSystemWatcher('**/*.{js,ts,jsx,tsx,py,java}');
        
        watcher.onDidChange(async (uri) => {
            try {
                await this.indexFile(uri.fsPath);
                console.log(`Re-indexed file: ${uri.fsPath}`);
            } catch (error) {
                console.error(`Failed to re-index file ${uri.fsPath}:`, error);
            }
        });

        watcher.onDidCreate(async (uri) => {
            try {
                await this.indexFile(uri.fsPath);
                console.log(`Indexed new file: ${uri.fsPath}`);
            } catch (error) {
                console.error(`Failed to index new file ${uri.fsPath}:`, error);
            }
        });

        watcher.onDidDelete((uri) => {
            this.removeFileFromIndex(uri.fsPath);
            console.log(`Removed file from index: ${uri.fsPath}`);
        });
    }

    private ensureIndexDirectory(): void {
        if (!fs.existsSync(this.indexPath)) {
            fs.mkdirSync(this.indexPath, { recursive: true });
        }
    }

    private async saveIndex(): Promise<void> {
        try {
            const indexData = {
                metadata: {
                    ...this.indexMetadata,
                    fileHashes: Array.from(this.indexMetadata.fileHashes.entries())
                },
                chunks: Array.from(this.chunks.entries()),
                fileToChunks: Array.from(this.fileToChunks.entries())
            };

            await fs.promises.writeFile(
                path.join(this.indexPath, 'index.json'),
                JSON.stringify(indexData, null, 2)
            );
        } catch (error) {
            console.error('Failed to save index:', error);
        }
    }

    private async loadIndex(): Promise<void> {
        try {
            const indexFile = path.join(this.indexPath, 'index.json');
            if (fs.existsSync(indexFile)) {
                const data = JSON.parse(await fs.promises.readFile(indexFile, 'utf-8'));
                
                this.indexMetadata = {
                    ...data.metadata,
                    fileHashes: new Map(data.metadata.fileHashes)
                };
                
                this.chunks = new Map(data.chunks);
                this.fileToChunks = new Map(data.fileToChunks);
                
                console.log(`Loaded index with ${this.chunks.size} chunks`);
            }
        } catch (error) {
            console.error('Failed to load index:', error);
        }
    }

    // Public methods for integration with existing security analyzer
    
    /**
     * Get the current index statistics
     */
    getIndexStats(): {
        totalChunks: number;
        totalFiles: number;
        lastFullIndex: Date | null;
        indexSize: string;
    } {
        return {
            totalChunks: this.chunks.size,
            totalFiles: this.fileToChunks.size,
            lastFullIndex: this.indexMetadata.lastFullIndex > 0 ? new Date(this.indexMetadata.lastFullIndex) : null,
            indexSize: `${Math.round(this.chunks.size * 0.1)} MB` // Rough estimate
        };
    }

    /**
     * Check if indexing is currently in progress
     */
    isCurrentlyIndexing(): boolean {
        return this.isIndexing;
    }

    /**
     * Force a refresh of a specific file
     */
    async refreshFile(filePath: string): Promise<void> {
        await this.indexFile(filePath);
        await this.saveIndex();
    }

    /**
     * Clear the entire index
     */
    async clearIndex(): Promise<void> {
        this.chunks.clear();
        this.fileToChunks.clear();
        this.embeddingCache.clear();
        this.indexMetadata.fileHashes.clear();
        this.indexMetadata.totalChunks = 0;
        this.indexMetadata.lastFullIndex = 0;
        
        await this.saveIndex();
    }
} 