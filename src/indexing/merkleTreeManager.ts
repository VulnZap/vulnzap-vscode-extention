import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { Logger } from '../utils/logger';

/**
 * Represents a node in the Merkle tree
 */
export interface MerkleNode {
    path: string;
    hash: string;
    type: 'file' | 'directory';
    lastModified: number;
    size: number;
    children?: Map<string, MerkleNode>;
}

/**
 * Manages Merkle tree construction and change detection
 * Used only for change detection, not parsing - keeps it simple and fast
 */
export class MerkleTreeManager {
    private readonly excludePatterns = [
        'node_modules',
        '.git',
        '*.log',
        'dist',
        'build',
        '.vscode',
        'coverage',
        '*.tmp',
        '*.temp'
    ];

    /**
     * Build Merkle tree from file system
     */
    async buildTree(rootPath: string): Promise<MerkleNode> {
        Logger.debug(`Building Merkle tree for: ${rootPath}`);
        
        const stats = await fs.promises.stat(rootPath);
        
        if (stats.isFile()) {
            return this.createFileNode(rootPath, stats);
        }

        if (stats.isDirectory()) {
            return this.createDirectoryNode(rootPath, stats);
        }

        throw new Error(`Unsupported file type: ${rootPath}`);
    }

    /**
     * Compare two trees to find changed files
     */
    async detectChanges(oldTree: MerkleNode, newTree: MerkleNode): Promise<string[]> {
        const changedFiles: string[] = [];
        
        await this.compareNodes(oldTree, newTree, changedFiles);
        
        Logger.debug(`Detected ${changedFiles.length} changed files`);
        return changedFiles;
    }

    /**
     * Create a file node with hash
     */
    private async createFileNode(filePath: string, stats: fs.Stats): Promise<MerkleNode> {
        try {
            const content = await fs.promises.readFile(filePath, 'utf8');
            const hash = this.hashFile(content);
            
            return {
                path: filePath,
                hash,
                type: 'file',
                lastModified: stats.mtime.getTime(),
                size: stats.size
            };
        } catch (error) {
            // If file can't be read as text, hash the binary content
            const content = await fs.promises.readFile(filePath);
            const hash = crypto.createHash('sha256').update(content).digest('hex');
            
            return {
                path: filePath,
                hash,
                type: 'file',
                lastModified: stats.mtime.getTime(),
                size: stats.size
            };
        }
    }

    /**
     * Create a directory node with child hashes
     */
    private async createDirectoryNode(dirPath: string, stats: fs.Stats): Promise<MerkleNode> {
        const children = new Map<string, MerkleNode>();
        const childHashes: string[] = [];

        try {
            const entries = await fs.promises.readdir(dirPath);
            
            for (const entry of entries) {
                const entryPath = path.join(dirPath, entry);
                
                // Skip excluded patterns
                if (this.shouldExclude(entryPath)) {
                    continue;
                }
                
                try {
                    const childNode = await this.buildTree(entryPath);
                    children.set(entry, childNode);
                    childHashes.push(childNode.hash);
                } catch (error) {
                    Logger.debug(`Skipping inaccessible path: ${entryPath}`);
                    // Continue with other files
                }
            }
        } catch (error) {
            Logger.warn(`Cannot read directory: ${dirPath}`);
        }

        // Directory hash is combination of all child hashes
        const combinedHash = childHashes.sort().join('');
        const hash = crypto.createHash('sha256').update(combinedHash).digest('hex');

        return {
            path: dirPath,
            hash,
            type: 'directory',
            lastModified: stats.mtime.getTime(),
            size: stats.size,
            children
        };
    }

    /**
     * Compare two nodes recursively
     */
    private async compareNodes(oldNode: MerkleNode, newNode: MerkleNode, changedFiles: string[]): Promise<void> {
        // Different hashes mean content changed
        if (oldNode.hash !== newNode.hash) {
            if (oldNode.type === 'file') {
                changedFiles.push(oldNode.path);
                return;
            }

            // For directories, recursively compare children
            if (oldNode.type === 'directory' && newNode.type === 'directory') {
                await this.compareDirectoryChildren(oldNode, newNode, changedFiles);
            }
        }
    }

    /**
     * Compare children of directory nodes
     */
    private async compareDirectoryChildren(oldDir: MerkleNode, newDir: MerkleNode, changedFiles: string[]): Promise<void> {
        const oldChildren = oldDir.children || new Map();
        const newChildren = newDir.children || new Map();

        // Check for changed and deleted files
        for (const [name, oldChild] of oldChildren) {
            const newChild = newChildren.get(name);
            
            if (!newChild) {
                // File was deleted - mark as changed to remove from index
                if (oldChild.type === 'file') {
                    changedFiles.push(oldChild.path);
                } else {
                    // Directory deleted - recursively mark all files as changed
                    await this.markAllFilesAsChanged(oldChild, changedFiles);
                }
            } else {
                // File exists in both - compare recursively
                await this.compareNodes(oldChild, newChild, changedFiles);
            }
        }

        // Check for new files
        for (const [name, newChild] of newChildren) {
            if (!oldChildren.has(name)) {
                // New file or directory
                if (newChild.type === 'file') {
                    changedFiles.push(newChild.path);
                } else {
                    // New directory - mark all files as changed
                    await this.markAllFilesAsChanged(newChild, changedFiles);
                }
            }
        }
    }

    /**
     * Mark all files in a directory as changed (for deletion or new directories)
     */
    private async markAllFilesAsChanged(node: MerkleNode, changedFiles: string[]): Promise<void> {
        if (node.type === 'file') {
            changedFiles.push(node.path);
        } else if (node.type === 'directory' && node.children) {
            for (const child of node.children.values()) {
                await this.markAllFilesAsChanged(child, changedFiles);
            }
        }
    }

    /**
     * Check if path should be excluded from indexing
     */
    private shouldExclude(filePath: string): boolean {
        const normalizedPath = path.normalize(filePath).replace(/\\/g, '/');
        
        return this.excludePatterns.some(pattern => {
            if (pattern.includes('*')) {
                // Glob pattern matching
                const regex = new RegExp(pattern.replace(/\*/g, '.*'));
                return regex.test(normalizedPath);
            } else {
                // Direct pattern matching
                return normalizedPath.includes(pattern);
            }
        });
    }

    /**
     * Hash file content directly - no parsing required
     */
    private hashFile(content: string): string {
        return crypto.createHash('sha256').update(content).digest('hex');
    }

    /**
     * Serialize tree to JSON for storage
     */
    serializeTree(tree: MerkleNode): string {
        return JSON.stringify(tree, (key, value) => {
            if (value instanceof Map) {
                return Array.from(value.entries());
            }
            return value;
        });
    }

    /**
     * Deserialize tree from JSON
     */
    deserializeTree(json: string): MerkleNode {
        return JSON.parse(json, (key, value) => {
            if (key === 'children' && Array.isArray(value)) {
                return new Map(value);
            }
            return value;
        });
    }

    /**
     * Get file count in tree
     */
    getFileCount(tree: MerkleNode): number {
        if (tree.type === 'file') {
            return 1;
        }

        if (tree.type === 'directory' && tree.children) {
            let count = 0;
            for (const child of tree.children.values()) {
                count += this.getFileCount(child);
            }
            return count;
        }

        return 0;
    }
} 