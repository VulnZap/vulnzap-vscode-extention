# Vector Indexing for Enhanced Security Analysis

## Overview

The Vector Indexing feature creates a semantic index of your codebase to provide context-aware security analysis. It finds similar code patterns, detects relationships between components, and enhances vulnerability detection.

## Key Features

- **Semantic Code Analysis**: Vector embeddings for similarity matching
- **Real-time Updates**: Auto-indexes files on save
- **Enhanced Security Detection**: Context-aware vulnerability analysis
- **Code Relationship Mapping**: Tracks imports, calls, and data flow

## Commands

- `VulnZap: Build Security Index` - Build complete workspace index
- `VulnZap: View Index Statistics` - Show index stats
- `VulnZap: Clear Security Index` - Remove indexed data
- `VulnZap: Find Similar Code Patterns` - Find similar code to selection

## Configuration

```json
{
  "vulnzap.enableVectorIndexing": true,
  "vulnzap.autoIndexOnSave": true, 
  "vulnzap.vectorSimilarityThreshold": 0.7,
  "vulnzap.indexChunkSize": 500
}
```

## How It Works

1. **Code Chunking**: Divides files into semantic chunks
2. **Vector Embeddings**: Converts code to numerical vectors  
3. **Similarity Detection**: Uses cosine similarity for pattern matching
4. **Relationship Building**: Maps code dependencies and data flow

## Enhanced Security Analysis

When enabled, security analysis includes:
- Similar vulnerability patterns found in codebase
- Contextual fix suggestions based on related code
- Improved confidence scoring
- Framework-specific security patterns

## Performance

- Initial indexing: ~1-5 seconds per 100 files
- Index size: ~0.1MB per 1000 code chunks
- Memory usage: ~10MB for 1000 chunks
- Supports: JS, TS, Python, Java, PHP, Ruby, Go, Rust

## File Support

### Supported Languages
- JavaScript (.js)
- TypeScript (.ts, .tsx)
- Python (.py)
- Java (.java)
- PHP (.php)
- Ruby (.rb)
- Go (.go)
- Rust (.rs)

### Excluded Directories
- `node_modules/`
- `.git/`
- `dist/`
- `build/`
- `__pycache__/`

## Index Storage

### Location
- **Global Storage**: `{extension-storage}/vectorIndex/`
- **Index File**: `index.json`
- **Embeddings**: Cached in memory, persisted to disk

### Structure
```json
{
  "metadata": {
    "version": "1.0.0",
    "lastFullIndex": 1234567890,
    "totalChunks": 150,
    "embeddingModel": "text-embedding-ada-002"
  },
  "chunks": [...],
  "fileToChunks": {...}
}
```

## Usage Examples

### 1. Finding Similar Code Patterns

```typescript
// Select this code in the editor
function validateInput(userInput) {
  return userInput.replace(/[<>]/g, '');
}
```

Run `VulnZap: Find Similar Code Patterns` to find similar validation functions across your codebase.

### 2. Building Initial Index

1. Open Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`)
2. Run `VulnZap: Build Security Index`
3. Wait for indexing to complete
4. Check status with `VulnZap: View Index Statistics`

### 3. Monitoring Index Health

```bash
# View current index statistics
VulnZap: View Index Statistics

# Example output:
Index Stats:
• Total Chunks: 247
• Total Files: 45
• Index Size: 25 MB
• Last Full Index: 2024-01-15 10:30:45
```

## Troubleshooting

### Common Issues

**Q: Index building is slow**
A: Reduce `indexChunkSize` or enable batch processing in settings

**Q: High memory usage**
A: Clear the index and rebuild with smaller chunk size

**Q: Similarity search returns no results**
A: Lower `vectorSimilarityThreshold` (try 0.5-0.6)

**Q: Index not updating on file save**
A: Check `autoIndexOnSave` setting and file permissions

### Debug Information

Enable debug logging by setting:
```json
{
  "vulnzap.debugLogging": true
}
```

Check the Output panel (VulnZap channel) for detailed logs.

## Future Enhancements

### Planned Features
- **Real OpenAI Embeddings**: Integration with OpenAI's embedding API
- **Local Embedding Models**: Support for offline sentence transformers
- **Cross-Project Index**: Index multiple workspaces simultaneously
- **Semantic Search**: Natural language queries for code patterns
- **Auto-Fix Suggestions**: AI-generated fixes based on similar patterns

### API Integration
```typescript
// Future API for real embeddings
async generateEmbedding(text: string): Promise<number[]> {
  const response = await openai.embeddings.create({
    model: "text-embedding-ada-002",
    input: text
  });
  return response.data[0].embedding;
}
```

## Contributing

To extend the vector indexing feature:

1. **Add New Embedding Providers**: Implement in `generateEmbedding()` method
2. **Enhance Relationship Detection**: Extend `findChunkRelationships()` 
3. **Improve Similarity Algorithms**: Modify similarity calculation methods
4. **Add New File Types**: Update `findCodeFiles()` method

See `src/vectorIndexer.ts` for implementation details. 