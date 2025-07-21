# VulnZap Indexing Ignore Patterns

This document explains how VulnZap determines which files and directories to exclude from codebase indexing.

## Overview

VulnZap uses a comprehensive ignore pattern system to exclude irrelevant files from indexing, improving performance and focusing security analysis on actual source code. The system combines multiple sources of ignore patterns:

1. **Built-in Default Patterns** - Common directories and files that should typically be ignored
2. **User-Defined Patterns** - Custom patterns configured in VS Code settings
3. **Gitignore Patterns** - Automatically loaded from your project's `.gitignore` files

## Built-in Default Patterns

VulnZap includes extensive default patterns covering:

### Package Managers & Dependencies
```
**/node_modules/**     # npm, yarn, pnpm
**/vendor/**           # Composer, Go modules
**/.pnpm/**            # pnpm store
**/bower_components/** # Bower
**/jspm_packages/**    # jspm
```

### Version Control
```
**/.git/**             # Git
**/.svn/**             # Subversion  
**/.hg/**              # Mercurial
**/.bzr/**             # Bazaar
```

### Build Outputs
```
**/dist/**             # Distribution builds
**/build/**            # Build outputs
**/out/**              # Output directories
**/target/**           # Maven/Gradle builds
**/bin/**              # Binary outputs
**/Debug/**            # Visual Studio debug
**/Release/**          # Visual Studio release
**/.next/**            # Next.js
**/.nuxt/**            # Nuxt.js
**/coverage/**         # Test coverage
```

### IDE & Editor Files
```
**/.vscode/**          # VS Code settings
**/.idea/**            # JetBrains IDEs
**/.vs/**              # Visual Studio
**/*.swp               # Vim swap files
**/*.swo               # Vim swap files
**/*~                  # Backup files
```

### Cache & Temporary
```
**/.cache/**           # General cache
**/tmp/**              # Temporary files
**/temp/**             # Temporary files
**/.webpack/**         # Webpack cache
**/.parcel-cache/**    # Parcel cache
**/.eslintcache        # ESLint cache
```

### Sensitive Files
```
**/.env                # Environment files
**/.env.*              # Environment variants
**/secrets/**          # Secret directories
**/config/secrets/**   # Config secrets
```

### Binary & Media Files
```
**/*.exe               # Executables
**/*.dll               # Libraries
**/*.so                # Shared objects
**/*.pdf               # Documents
**/*.zip               # Archives
**/*.class             # Java bytecode
**/*.pyc               # Python bytecode
**/__pycache__/**      # Python cache
```

### Lock Files
```
**/package-lock.json   # npm lock
**/yarn.lock           # Yarn lock
**/pnpm-lock.yaml      # pnpm lock
**/Pipfile.lock        # Python pipenv
**/composer.lock       # PHP Composer
```

## User-Defined Patterns

You can add custom ignore patterns through VS Code settings:

### Adding Custom Patterns

1. Open VS Code Settings (`Ctrl+,` or `Cmd+,`)
2. Search for "vulnzap indexing"
3. Find "Additional Ignore Patterns"
4. Add your custom glob patterns

Example configuration:
```json
{
  "vulnzap.indexing.additionalIgnorePatterns": [
    "**/my-custom-build/**",
    "**/*.generated.js",
    "**/legacy-code/**",
    "**/third-party/**"
  ]
}
```

### Disabling Default Patterns

If you need more control, you can disable all default patterns:

```json
{
  "vulnzap.indexing.disableDefaultIgnorePatterns": true
}
```

⚠️ **Warning**: Disabling default patterns may significantly slow down indexing as it will process `node_modules`, build outputs, and other typically irrelevant directories.

## Gitignore Integration

VulnZap automatically respects your project's `.gitignore` files:

### Automatic Loading
- Automatically loads patterns from `.gitignore` in your workspace root
- Converts gitignore syntax to glob patterns
- Handles directory patterns (`folder/`) and file patterns (`*.log`)

### Disabling Gitignore
If you don't want VulnZap to respect `.gitignore`:

```json
{
  "vulnzap.indexing.respectGitignore": false
}
```

### Gitignore Pattern Conversion
VulnZap converts gitignore patterns to glob patterns:

| Gitignore Pattern | Converted Glob Pattern | Description |
|-------------------|------------------------|-------------|
| `node_modules/`   | `**/node_modules/**`   | Directory anywhere |
| `*.log`           | `**/*.log`             | File pattern anywhere |
| `/dist`           | `dist/**`              | Root-relative directory |
| `temp`            | `**/temp`              | File or folder anywhere |

### Limitations
- Negation patterns (`!pattern`) are currently not supported
- Complex gitignore rules may not be perfectly converted

## Debugging Ignore Patterns

### View Active Patterns
Use the command palette (`Ctrl+Shift+P` or `Cmd+Shift+P`) and run:
```
Security: Show Indexing Ignore Patterns
```

This opens a markdown document showing:
- All default patterns
- Your custom patterns  
- Loaded gitignore patterns
- Total pattern count

### Check if File is Ignored
To test if a specific file would be ignored:
1. Run the "Show Indexing Ignore Patterns" command
2. Look for patterns that might match your file path
3. Check the VS Code output panel for debug logs (if debug logging is enabled)

### Enable Debug Logging
```json
{
  "vulnzap.enableDebugLogging": true
}
```

Then check the VulnZap output channel (`View > Output > VulnZap`) for detailed pattern matching information.

## Best Practices

### Recommended Custom Patterns
Common patterns you might want to add:

```json
{
  "vulnzap.indexing.additionalIgnorePatterns": [
    // Generated code
    "**/*.generated.*",
    "**/generated/**",
    "**/*_pb.js",          // Protocol buffers
    "**/*_pb.ts",
    
    // Documentation builds
    "**/docs/build/**",
    "**/_site/**",
    
    // Test fixtures with large data
    "**/test/fixtures/**",
    "**/test/data/**",
    
    // Vendor/third-party code you don't control
    "**/vendor/**",
    "**/third-party/**",
    
    // Large datasets
    "**/*.csv",
    "**/*.json",           // Only if they're large data files
    
    // Backup and temporary files
    "**/*.tmp",
    "**/*.backup",
    "**/*.old"
  ]
}
```

### Performance Considerations
- More patterns = slower pattern matching but faster indexing overall
- Very broad patterns (like `**/*`) should be avoided
- Specific patterns are more efficient than general ones

### Security Considerations
- Always exclude directories containing secrets
- Be careful not to exclude important security-related configuration files
- Consider excluding test files if they contain mock sensitive data

## Supported File Types

VulnZap only indexes files with these extensions:
```
.js .jsx .ts .tsx .py .java .c .cpp .cs .php .go .rs .rb .swift
.kt .scala .clj .hs .ml .json .yaml .yml .xml .html .htm .css
.scss .sass .less .sql .graphql .gql
```

Files with other extensions are automatically ignored regardless of patterns.

## Troubleshooting

### Too Many Files Being Indexed
1. Check if default patterns are disabled
2. Add more specific ignore patterns
3. Verify `.gitignore` is being loaded (check debug output)

### Important Files Being Ignored
1. Run "Show Indexing Ignore Patterns" command
2. Look for patterns that might match your files
3. Add negation patterns or modify existing patterns
4. Check if the file extension is supported

### Performance Issues
1. Enable debug logging to see how many patterns are being processed
2. Consider disabling gitignore loading if you have a complex `.gitignore`
3. Add more specific patterns instead of relying on broad patterns

## Examples

### Monorepo Configuration
```json
{
  "vulnzap.indexing.additionalIgnorePatterns": [
    "**/packages/*/dist/**",
    "**/packages/*/build/**",
    "**/packages/*/node_modules/**",
    "**/apps/*/dist/**",
    "**/libs/*/dist/**"
  ]
}
```

### Documentation Project
```json
{
  "vulnzap.indexing.additionalIgnorePatterns": [
    "**/_site/**",
    "**/site/**", 
    "**/.docusaurus/**",
    "**/public/**",
    "**/*.md"
  ]
}
```

### Game Development
```json
{
  "vulnzap.indexing.additionalIgnorePatterns": [
    "**/assets/**",
    "**/*.asset",
    "**/*.prefab", 
    "**/build/**",
    "**/Builds/**"
  ]
}
``` 