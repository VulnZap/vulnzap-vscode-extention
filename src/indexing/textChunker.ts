import * as crypto from 'crypto';
import * as path from 'path';
import { Logger } from '../utils/logger';

/**
 * Represents a simple text chunk with metadata
 */
export interface TextChunk {
    id: string;
    filePath: string;
    startByte: number;
    endByte: number;
    startLine: number;
    endLine: number;
    content: string;
    hash: string;
    language: string;
    metadata: ChunkMetadata;
}

/**
 * Metadata for each chunk
 */
export interface ChunkMetadata {
    fileExtension: string;
    hasSecurityKeywords: boolean;
    estimatedComplexity: number;
    lineCount: number;
    charCount: number;
}

/**
 * Simple, fast text chunker based on Cursor's proven approach
 * Prioritizes speed and reliability over complex AST parsing
 */
export class SimpleCodeChunker {
    private readonly CHUNK_SIZE = 1500; // characters
    private readonly OVERLAP_RATIO = 0.1;
    
    // Security keywords for relevance scoring
    private readonly SECURITY_KEYWORDS = [
        'eval', 'innerHTML', 'document.write', 'exec', 'system',
        'password', 'secret', 'token', 'api_key', 'crypto',
        'sql', 'query', 'database', 'auth', 'login',
        'xss', 'injection', 'sanitize', 'validate',
        'cookie', 'session', 'jwt', 'bearer',
        'https', 'ssl', 'tls', 'encryption'
    ];

    /**
     * Chunk a file into overlapping text segments
     */
    async chunkFile(filePath: string, content: string): Promise<TextChunk[]> {
        const chunks: TextChunk[] = [];
        const overlapSize = Math.floor(this.CHUNK_SIZE * this.OVERLAP_RATIO);
        const language = this.detectLanguage(filePath);
        
        let chunkId = 0;
        for (let start = 0; start < content.length; start += this.CHUNK_SIZE - overlapSize) {
            const end = Math.min(start + this.CHUNK_SIZE, content.length);
            
            // Try to break at line boundaries for better chunking
            const adjustedEnd = this.findGoodBreakPoint(content, start, end);
            const chunkContent = content.slice(start, adjustedEnd);
            
            const chunk: TextChunk = {
                id: `${filePath}:${chunkId++}`,
                filePath,
                startByte: start,
                endByte: adjustedEnd,
                startLine: this.getLineNumber(content, start),
                endLine: this.getLineNumber(content, adjustedEnd),
                content: chunkContent,
                hash: this.hashContent(chunkContent),
                language,
                metadata: this.extractMetadata(chunkContent, language)
            };
            
            chunks.push(chunk);
        }
        
        Logger.debug(`Chunked ${filePath}: ${chunks.length} chunks`);
        return chunks;
    }

    /**
     * Find a good break point near the ideal end position
     */
    private findGoodBreakPoint(content: string, start: number, idealEnd: number): number {
        // Try to break at newlines near the ideal end
        const searchStart = Math.max(idealEnd - 100, start);
        const searchEnd = Math.min(idealEnd + 100, content.length);
        
        for (let i = idealEnd; i >= searchStart; i--) {
            if (content[i] === '\n') return i + 1;
        }
        
        return idealEnd; // Fallback to ideal position
    }

    /**
     * Get line number at a given byte position
     */
    private getLineNumber(content: string, position: number): number {
        return content.substring(0, position).split('\n').length;
    }

    /**
     * Detect programming language from file path
     */
    private detectLanguage(filePath: string): string {
        const ext = path.extname(filePath).toLowerCase();
        const languageMap: { [key: string]: string } = {
            '.js': 'javascript',
            '.jsx': 'javascript',
            '.ts': 'typescript',
            '.tsx': 'typescript',
            '.py': 'python',
            '.java': 'java',
            '.c': 'c',
            '.cpp': 'cpp',
            '.cs': 'csharp',
            '.php': 'php',
            '.go': 'go',
            '.rs': 'rust',
            '.rb': 'ruby',
            '.json': 'json',
            '.yaml': 'yaml',
            '.yml': 'yaml',
            '.xml': 'xml',
            '.html': 'html',
            '.css': 'css',
            '.sql': 'sql',
            '.sh': 'shell',
            '.ps1': 'powershell'
        };
        
        return languageMap[ext] || 'text';
    }

    /**
     * Extract metadata from chunk content
     */
    private extractMetadata(content: string, language: string): ChunkMetadata {
        const lines = content.split('\n');
        
        return {
            fileExtension: language,
            hasSecurityKeywords: this.hasSecurityRelevance(content),
            estimatedComplexity: this.estimateComplexity(content),
            lineCount: lines.length,
            charCount: content.length
        };
    }

    /**
     * Check if chunk has security-relevant keywords
     */
    private hasSecurityRelevance(chunk: string): boolean {
        const lowerContent = chunk.toLowerCase();
        return this.SECURITY_KEYWORDS.some(keyword => 
            lowerContent.includes(keyword)
        );
    }

    /**
     * Estimate code complexity (simple metric)
     */
    private estimateComplexity(content: string): number {
        // Simple complexity estimation based on control structures
        const complexityKeywords = [
            'if', 'else', 'for', 'while', 'switch', 'case',
            'try', 'catch', 'function', 'class', 'async'
        ];
        
        let complexity = 0;
        const lowerContent = content.toLowerCase();
        
        for (const keyword of complexityKeywords) {
            const matches = lowerContent.match(new RegExp(`\\b${keyword}\\b`, 'g'));
            complexity += matches ? matches.length : 0;
        }
        
        return complexity;
    }

    /**
     * Generate content hash
     */
    private hashContent(content: string): string {
        return crypto.createHash('sha256').update(content).digest('hex');
    }
} 