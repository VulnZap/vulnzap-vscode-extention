import { VectorStorage, SearchOptions, SearchResult } from './vectorStorage';
import { TextChunk } from './textChunker';
import { APIProviderManager } from '../providers/apiProviders';
import { Logger } from '../utils/logger';

/**
 * Multi-stage search and retrieval system
 * Implements Cursor-style fast retrieval with context expansion
 */
export class CodeRetriever {
    private vectorStorage: VectorStorage;
    private apiProvider: APIProviderManager;

    constructor(vectorStorage: VectorStorage) {
        this.vectorStorage = vectorStorage;
        this.apiProvider = new APIProviderManager();
    }

    /**
     * Search for similar code with multi-stage approach
     */
    async searchSimilar(query: string, options: SearchOptions): Promise<TextChunk[]> {
        Logger.debug(`Searching for: "${query.substring(0, 50)}..."`);

        // Stage 1: Generate query embedding
        const queryEmbedding = await this.generateEmbedding(query);
        if (!queryEmbedding) {
            Logger.warn('Failed to generate embedding, falling back to keyword search');
            return this.fallbackKeywordSearch(query, options);
        }

        // Stage 2: Vector similarity search
        const similarChunks = await this.vectorStorage.searchSimilar(queryEmbedding, options);
        
        // Stage 3: Apply additional filters
        const filteredChunks = this.applyFilters(similarChunks, options);
        
        // Stage 4: Expand context if requested
        const expandedChunks = options.include_context 
            ? await this.expandContext(filteredChunks)
            : filteredChunks.map(r => r.chunk);

        Logger.debug(`Found ${expandedChunks.length} relevant chunks`);
        return expandedChunks.slice(0, options.max_results);
    }

    /**
     * Find security analysis context for a specific code location
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
        Logger.debug(`Getting security context for ${filePath}:${line}`);

        const [
            similarVulnerabilities,
            relatedSecurityPatterns,
            dataFlowRelated,
            frameworkSpecific
        ] = await Promise.all([
            this.findSimilarVulnerabilities(targetCode),
            this.findSecurityPatterns(targetCode),
            this.findDataFlowRelated(targetCode),
            this.findFrameworkSpecific(filePath, targetCode)
        ]);

        return {
            similarVulnerabilities,
            relatedSecurityPatterns,
            dataFlowRelated,
            frameworkSpecific
        };
    }

    /**
     * Find code chunks related to a modified file
     */
    async findRelatedCode(filePath: string, modifiedLines: number[]): Promise<TextChunk[]> {
        // Get chunks from the modified file
        const fileChunks = await this.vectorStorage.getChunksByFile(filePath);
        
        // Find chunks that overlap with modified lines
        const relevantChunks = fileChunks.filter(chunk => 
            this.hasLineOverlap(chunk, modifiedLines)
        );

        if (relevantChunks.length === 0) {
            return [];
        }

        // Find similar code across the codebase
        const allRelatedChunks: TextChunk[] = [];
        
        for (const chunk of relevantChunks) {
            const similar = await this.searchSimilar(chunk.content, {
                similarity_threshold: 0.7,
                max_results: 5,
                security_focused: true,
                include_context: false
            });
            
            allRelatedChunks.push(...similar);
        }

        // Deduplicate and return
        return this.deduplicateChunks(allRelatedChunks);
    }

    // Private methods

    /**
     * Generate embedding for text
     */
    private async generateEmbedding(text: string): Promise<number[] | null> {
        try {
            // Use mock embedding for development
            // TODO: Integrate with a proper embedding service when available
            return this.mockEmbeddingGeneration(text);
        } catch (error) {
            Logger.error('Embedding generation failed:', error as Error);
            return null;
        }
    }

    /**
     * Mock embedding generation for development/testing
     */
    private async mockEmbeddingGeneration(text: string): Promise<number[]> {
        // Simple hash-based embedding for development
        const words = text.toLowerCase().split(/\s+/);
        const embedding = new Array(384).fill(0); // Use smaller dimension for mock
        
        for (const word of words) {
            const hash = this.simpleHash(word);
            for (let i = 0; i < embedding.length; i++) {
                embedding[i] += Math.sin(hash + i) * 0.1;
            }
        }

        // Normalize the embedding
        const norm = Math.sqrt(embedding.reduce((sum, val) => sum + val * val, 0));
        return embedding.map(val => val / (norm || 1));
    }

    /**
     * Apply additional filters to search results
     */
    private applyFilters(results: SearchResult[], options: SearchOptions): SearchResult[] {
        return results.filter(result => {
            // Language filter
            if (options.language_filter && 
                !options.language_filter.includes(result.chunk.language)) {
                return false;
            }

            // Security focus filter
            if (options.security_focused && 
                !result.chunk.metadata.hasSecurityKeywords) {
                return false;
            }

            return true;
        });
    }

    /**
     * Expand context by including adjacent chunks
     */
    private async expandContext(results: SearchResult[]): Promise<TextChunk[]> {
        const expandedChunks: TextChunk[] = [];

        for (const result of results) {
            const chunk = result.chunk;

            // Get previous chunk
            const prevChunk = await this.vectorStorage.getAdjacentChunk(chunk, -1);
            if (prevChunk) expandedChunks.push(prevChunk);

            // Current chunk
            expandedChunks.push(chunk);

            // Get next chunk
            const nextChunk = await this.vectorStorage.getAdjacentChunk(chunk, 1);
            if (nextChunk) expandedChunks.push(nextChunk);
        }

        return this.deduplicateChunks(expandedChunks);
    }

    /**
     * Find similar vulnerabilities
     */
    private async findSimilarVulnerabilities(code: string): Promise<TextChunk[]> {
        return this.searchSimilar(code, {
            similarity_threshold: 0.8,
            max_results: 3,
            security_focused: true,
            include_context: false
        });
    }

    /**
     * Find related security patterns
     */
    private async findSecurityPatterns(code: string): Promise<TextChunk[]> {
        // Extract security-relevant keywords and patterns
        const securityKeywords = this.extractSecurityKeywords(code);
        const patternQuery = securityKeywords.join(' ');

        if (!patternQuery) return [];

        return this.searchSimilar(patternQuery, {
            similarity_threshold: 0.6,
            max_results: 5,
            security_focused: true,
            include_context: false
        });
    }

    /**
     * Find data flow related code
     */
    private async findDataFlowRelated(code: string): Promise<TextChunk[]> {
        const dataPatterns = this.extractDataPatterns(code);
        if (dataPatterns.length === 0) return [];

        const allRelated: TextChunk[] = [];
        
        for (const pattern of dataPatterns) {
            const related = await this.searchSimilar(pattern, {
                similarity_threshold: 0.7,
                max_results: 3,
                security_focused: false,
                include_context: false
            });
            allRelated.push(...related);
        }

        return this.deduplicateChunks(allRelated);
    }

    /**
     * Find framework-specific patterns
     */
    private async findFrameworkSpecific(filePath: string, code: string): Promise<TextChunk[]> {
        const framework = this.detectFramework(code);
        if (!framework) return [];

        // Search for framework-specific security patterns
        const frameworkQuery = `${framework} security vulnerability`;
        
        return this.searchSimilar(frameworkQuery, {
            similarity_threshold: 0.6,
            max_results: 3,
            security_focused: true,
            include_context: false
        });
    }

    /**
     * Fallback keyword search when embeddings are not available
     */
    private async fallbackKeywordSearch(query: string, options: SearchOptions): Promise<TextChunk[]> {
        // This is a simplified fallback - in a real implementation,
        // you might want to use full-text search capabilities
        Logger.warn('Using fallback keyword search');
        return [];
    }

    /**
     * Check if chunk overlaps with modified lines
     */
    private hasLineOverlap(chunk: TextChunk, modifiedLines: number[]): boolean {
        return modifiedLines.some(line => 
            line >= chunk.startLine && line <= chunk.endLine
        );
    }

    /**
     * Deduplicate chunks by ID
     */
    private deduplicateChunks(chunks: TextChunk[]): TextChunk[] {
        const seen = new Set<string>();
        return chunks.filter(chunk => {
            if (seen.has(chunk.id)) return false;
            seen.add(chunk.id);
            return true;
        });
    }

    /**
     * Extract security-relevant keywords from code
     */
    private extractSecurityKeywords(code: string): string[] {
        const securityKeywords = [
            'password', 'secret', 'token', 'api_key', 'auth',
            'sql', 'query', 'exec', 'eval', 'innerHTML',
            'xss', 'injection', 'crypto', 'hash', 'encrypt'
        ];

        const lowerCode = code.toLowerCase();
        return securityKeywords.filter(keyword => lowerCode.includes(keyword));
    }

    /**
     * Extract data flow patterns from code
     */
    private extractDataPatterns(code: string): string[] {
        const patterns: string[] = [];

        // Extract variable names
        const variableMatches = code.match(/\b[a-zA-Z_$][a-zA-Z0-9_$]*\b/g);
        if (variableMatches) {
            patterns.push(...variableMatches.slice(0, 5)); // Limit to avoid noise
        }

        // Extract function calls
        const functionMatches = code.match(/\b[a-zA-Z_$][a-zA-Z0-9_$]*\s*\(/g);
        if (functionMatches) {
            patterns.push(...functionMatches.map(m => m.replace(/\s*\($/, '')).slice(0, 3));
        }

        return patterns;
    }

    /**
     * Detect framework from code patterns
     */
    private detectFramework(code: string): string | null {
        const frameworks = {
            'react': ['React', 'jsx', 'useState', 'useEffect'],
            'vue': ['Vue', 'v-if', 'v-for', '$emit'],
            'angular': ['@Component', '@Injectable', 'ngOnInit'],
            'express': ['express', 'app.get', 'req.', 'res.'],
            'spring': ['@Controller', '@Service', '@Autowired'],
            'django': ['django', 'models.Model', 'views.']
        };

        for (const [framework, patterns] of Object.entries(frameworks)) {
            if (patterns.some(pattern => code.includes(pattern))) {
                return framework;
            }
        }

        return null;
    }

    /**
     * Simple hash function for mock embeddings
     */
    private simpleHash(str: string): number {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // Convert to 32-bit integer
        }
        return hash;
    }
} 