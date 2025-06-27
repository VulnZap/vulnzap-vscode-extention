# Quick Setup Guide: Vector Indexing

## 🚀 Getting Started

### 1. Enable Vector Indexing
1. Open VS Code Settings (`Ctrl+,` / `Cmd+,`)
2. Search for "vulnzap vector"
3. Ensure `vulnzap.enableVectorIndexing` is checked ✅

### 2. Build Your First Index
1. Open Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`)
2. Run `VulnZap: Build Security Index`
3. Wait for completion (progress shown in notification)

### 3. Verify Setup
1. Run `VulnZap: View Index Statistics`
2. You should see indexed files and chunks

## 🎯 Testing the Feature

### Find Similar Code Patterns
1. Select any function or code block
2. Run `VulnZap: Find Similar Code Patterns`
3. Review similar patterns in the new document

### Enhanced Security Analysis
1. Save any file (triggers re-indexing)
2. Security issues now include contextual information
3. Look for "Related patterns found" in suggestions

## ⚙️ Recommended Settings

```json
{
  "vulnzap.enableVectorIndexing": true,
  "vulnzap.autoIndexOnSave": true,
  "vulnzap.vectorSimilarityThreshold": 0.7,
  "vulnzap.indexChunkSize": 500
}
```

## 🔧 Troubleshooting

**Index building is slow?**
- Reduce `indexChunkSize` to 300
- Check if large files are present

**No similar patterns found?**
- Lower `vectorSimilarityThreshold` to 0.6
- Ensure you have similar code in the workspace

**High memory usage?**
- Run `VulnZap: Clear Index` and rebuild
- Reduce `indexChunkSize`

## 🎉 You're Ready!
Your vector indexing is now set up and will enhance your security analysis with contextual insights! 