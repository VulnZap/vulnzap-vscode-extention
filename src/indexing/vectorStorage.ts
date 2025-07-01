import * as path from 'path';
import * as fs from 'fs';
import { TextChunk } from './textChunker';
import { Logger } from '../utils/logger';

/**
 * Search options for vector queries
 */
export interface SearchOptions {
    similarity_threshold: number;
    max_results: number;
    language_filter?: string[];
    security_focused?: boolean;
    include_context?: boolean;
}

/**
 * Search result with similarity score
 */
export interface SearchResult {
    chunk: TextChunk;
    similarity: number;
    relevanceScore: number;
}

/**
 * File-based vector storage using JSON cache files
 * Simple, portable, and reliable storage without native dependencies
 */
export class VectorStorage {
    private storagePath: string;
    private chunksFile: string;
    private embeddingsFile: string;
    private metadataFile: string;
    private chunks = new Map<string, TextChunk>();
    private embeddings = new Map<string, number[]>();
    private metadata = {
        totalChunks: 0,
        totalFiles: 0,
        lastUpdated: Date.now(),
        version: '1.0'
    };

    constructor(storagePath: string) {
        this.storagePath = storagePath;
        this.chunksFile = path.join(storagePath, 'chunks.json');
        this.embeddingsFile = path.join(storagePath, 'embeddings.json');
        this.metadataFile = path.join(storagePath, 'metadata.json');
        
        this.ensureStorageDirectory(storagePath);
        this.loadFromDisk();
    }

    /**
     * Load data from disk cache files
     */
    private loadFromDisk(): void {
        try {
            // Load chunks
            if (fs.existsSync(this.chunksFile)) {
                const chunksData = JSON.parse(fs.readFileSync(this.chunksFile, 'utf8'));
                this.chunks = new Map(Object.entries(chunksData));
                Logger.debug(`Loaded ${this.chunks.size} chunks from cache`);
            }

            // Load embeddings
            if (fs.existsSync(this.embeddingsFile)) {
                const embeddingsData = JSON.parse(fs.readFileSync(this.embeddingsFile, 'utf8'));
                this.embeddings = new Map(Object.entries(embeddingsData));
                Logger.debug(`Loaded ${this.embeddings.size} embeddings from cache`);
            }

            // Load metadata
            if (fs.existsSync(this.metadataFile)) {
                this.metadata = JSON.parse(fs.readFileSync(this.metadataFile, 'utf8'));
                Logger.debug(`Loaded metadata: ${this.metadata.totalChunks} total chunks`);
            }
        } catch (error) {
            Logger.warn('Failed to load cache from disk, starting fresh:', error as Error);
        }
    }

    /**
     * Save data to disk cache files
     */
    private async saveToDisk(): Promise<void> {
        try {
            // Save chunks
            const chunksData = Object.fromEntries(this.chunks);
            fs.writeFileSync(this.chunksFile, JSON.stringify(chunksData, null, 2));

            // Save embeddings
            const embeddingsData = Object.fromEntries(this.embeddings);
            fs.writeFileSync(this.embeddingsFile, JSON.stringify(embeddingsData, null, 2));

            // Update and save metadata
            this.metadata.totalChunks = this.chunks.size;
            this.metadata.totalFiles = new Set(Array.from(this.chunks.values()).map(c => c.filePath)).size;
            this.metadata.lastUpdated = Date.now();
            fs.writeFileSync(this.metadataFile, JSON.stringify(this.metadata, null, 2));

            Logger.debug(`Saved ${this.chunks.size} chunks and ${this.embeddings.size} embeddings to disk`);
        } catch (error) {
            Logger.error('Failed to save cache to disk:', error as Error);
        }
    }

    /**
     * Store a chunk with its embedding
     */
    async storeChunk(chunk: TextChunk, embedding?: number[]): Promise<void> {
        this.chunks.set(chunk.id, chunk);
        if (embedding) {
            this.embeddings.set(chunk.id, embedding);
        }
        
        // Auto-save every 10 chunks for efficiency
        if (this.chunks.size % 10 === 0) {
            await this.saveToDisk();
        }
    }

    /**
     * Store multiple chunks in batch
     */
    async batchStoreChunks(chunks: TextChunk[], embeddings?: number[][]): Promise<void> {
        chunks.forEach((chunk, index) => {
            this.chunks.set(chunk.id, chunk);
            if (embeddings && embeddings[index]) {
                this.embeddings.set(chunk.id, embeddings[index]);
            }
        });

        // Save after batch operation
        await this.saveToDisk();
    }

    /**
     * Search for similar chunks using cosine similarity
     */
    async searchSimilar(queryEmbedding: number[], options: SearchOptions): Promise<SearchResult[]> {
        const results: SearchResult[] = [];

        for (const [chunkId, chunk] of this.chunks) {
            const embedding = this.embeddings.get(chunkId);
            if (!embedding) continue;

            // Apply language filter if specified
            if (options.language_filter && !options.language_filter.includes(chunk.language)) {
                continue;
            }

            // Apply security filter if specified
            if (options.security_focused && !chunk.metadata.hasSecurityKeywords) {
                continue;
            }

            const similarity = this.cosineSimilarity(queryEmbedding, embedding);

            if (similarity >= options.similarity_threshold) {
                results.push({
                    chunk,
                    similarity,
                    relevanceScore: this.calculateRelevanceScore(chunk, similarity)
                });
            }
        }

        // Sort by relevance score and limit results
        results.sort((a, b) => b.relevanceScore - a.relevanceScore);
        return results.slice(0, options.max_results);
    }

    /**
     * Remove all chunks for a specific file
     */
    async removeChunksForFile(filePath: string): Promise<void> {
        const toRemove: string[] = [];

        for (const [chunkId, chunk] of this.chunks) {
            if (chunk.filePath === filePath) {
                toRemove.push(chunkId);
            }
        }

        toRemove.forEach(id => {
            this.chunks.delete(id);
            this.embeddings.delete(id);
        });

        if (toRemove.length > 0) {
            await this.saveToDisk();
            Logger.debug(`Removed ${toRemove.length} chunks for file: ${filePath}`);
        }
    }

    /**
     * Get all chunks for a specific file
     */
    async getChunksByFile(filePath: string): Promise<TextChunk[]> {
        const fileChunks: TextChunk[] = [];

        for (const chunk of this.chunks.values()) {
            if (chunk.filePath === filePath) {
                fileChunks.push(chunk);
            }
        }

        return fileChunks.sort((a, b) => a.startLine - b.startLine);
    }

    /**
     * Get adjacent chunk (for context expansion)
     */
    async getAdjacentChunk(chunk: TextChunk, offset: number): Promise<TextChunk | null> {
        const targetLine = chunk.startLine + offset;

        for (const candidate of this.chunks.values()) {
            if (candidate.filePath === chunk.filePath && 
                candidate.startLine <= targetLine && 
                candidate.endLine >= targetLine) {
                return candidate;
            }
        }

        return null;
    }

    /**
     * Get storage statistics
     */
    async getStats(): Promise<{
        totalChunks: number;
        totalFiles: number;
        avgChunkSize: number;
        securityRelevantChunks: number;
    }> {
        const chunks = Array.from(this.chunks.values());
        const securityRelevantChunks = chunks.filter(c => c.metadata.hasSecurityKeywords).length;
        const avgChunkSize = chunks.length > 0 
            ? chunks.reduce((sum, c) => sum + c.metadata.charCount, 0) / chunks.length
            : 0;

        return {
            totalChunks: this.chunks.size,
            totalFiles: new Set(chunks.map(c => c.filePath)).size,
            avgChunkSize: Math.round(avgChunkSize),
            securityRelevantChunks
        };
    }

    /**
     * Clear all stored data
     */
    async clearAll(): Promise<void> {
        this.chunks.clear();
        this.embeddings.clear();
        this.metadata = {
            totalChunks: 0,
            totalFiles: 0,
            lastUpdated: Date.now(),
            version: '1.0'
        };

        // Remove cache files
        try {
            if (fs.existsSync(this.chunksFile)) fs.unlinkSync(this.chunksFile);
            if (fs.existsSync(this.embeddingsFile)) fs.unlinkSync(this.embeddingsFile);
            if (fs.existsSync(this.metadataFile)) fs.unlinkSync(this.metadataFile);
            Logger.debug('Cleared all cache files');
        } catch (error) {
            Logger.warn('Failed to remove cache files:', error as Error);
        }
    }

    /**
     * Close and save storage
     */
    async close(): Promise<void> {
        await this.saveToDisk();
        Logger.debug('Vector storage closed and saved');
    }

    /**
     * Ensure storage directory exists
     */
    private ensureStorageDirectory(storagePath: string): void {
        if (!fs.existsSync(storagePath)) {
            fs.mkdirSync(storagePath, { recursive: true });
        }
    }

    /**
     * Calculate cosine similarity between two vectors
     */
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

        const denominator = Math.sqrt(normA) * Math.sqrt(normB);
        return denominator === 0 ? 0 : dotProduct / denominator;
    }

    /**
     * Calculate relevance score combining similarity and chunk metadata
     */
    private calculateRelevanceScore(chunk: TextChunk, similarity: number): number {
        let score = similarity;

        // Boost security-relevant chunks
        if (chunk.metadata.hasSecurityKeywords) {
            score *= 1.2;
        }

        // Slight penalty for very long chunks (may be less focused)
        if (chunk.metadata.charCount > 2000) {
            score *= 0.95;
        }

        // Boost for moderate complexity (not too simple, not too complex)
        if (chunk.metadata.estimatedComplexity >= 2 && chunk.metadata.estimatedComplexity <= 4) {
            score *= 1.1;
        }

        return score;
    }
}
