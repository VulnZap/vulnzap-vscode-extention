# Dependency Vulnerability Scanning Feature

## Overview

A comprehensive dependency vulnerability scanning system has been implemented for the VulnZap VS Code extension. This feature automatically detects and scans dependencies across multiple package ecosystems for known security vulnerabilities.

## Architecture

### Core Components

1. **DependencyParser** (`src/dependencyParser.ts`)
   - Parses dependency files across multiple ecosystems
   - Supports npm, pip, go, rust, gradle, maven, composer, rubygems, nuget, cocoapods
   - Extracts package names, versions, and development/production flags

2. **DependencyCache** (`src/dependencyCache.ts`)
   - Manages caching of scan results using project path hashes
   - Configurable cache expiry (default: 5 days)
   - Automatic cache invalidation when dependencies change
   - Dependency content hashing for change detection

3. **DependencyScanner** (`src/dependencyScanner.ts`)
   - Main service orchestrating dependency vulnerability scanning
   - Integrates with VulnZap API for batch vulnerability checks
   - Handles scan debouncing, progress reporting, and result presentation
   - Generates detailed markdown reports

## Supported Ecosystems

| Ecosystem | Files Supported | Example |
|-----------|----------------|---------|
| npm | package.json | `{"dependencies": {"express": "4.16.0"}}` |
| pip | requirements.txt, Pipfile, pyproject.toml | `django==2.2.0` |
| go | go.mod | `require github.com/gin-gonic/gin v1.8.0` |
| rust | Cargo.toml | `serde = "1.0"` |
| maven | pom.xml | `<artifactId>spring-core</artifactId>` |
| gradle | build.gradle, build.gradle.kts | `implementation 'org.springframework:spring-core:5.3.0'` |
| composer | composer.json | `"symfony/symfony": "^4.4"` |
| rubygems | Gemfile | `gem 'rails', '~> 6.0'` |
| nuget | packages.config, *.csproj | `<PackageReference Include="Newtonsoft.Json" Version="12.0.3" />` |
| cocoapods | Podfile | `pod 'AFNetworking', '~> 3.0'` |

## Features

### Automatic Scanning
- **File Save Triggers**: Automatically scans when dependency files are saved
- **Startup Scanning**: Scans all dependencies when workspace is opened (configurable)
- **Debouncing**: Prevents rapid successive scans (configurable delay)

### Intelligent Caching
- **Project-based Hashing**: Uses MD5 hash of normalized project path as cache key
- **Dependency Change Detection**: Invalidates cache when dependencies change
- **Configurable Expiry**: Default 5-day cache expiry, configurable from 1-30 days
- **Automatic Cleanup**: Removes expired cache entries

### API Integration
- **Batch Scanning**: Efficient batch API calls to VulnZap vulnerability database
- **Timeout Configuration**: Configurable API timeout (default: 60 seconds)
- **Error Handling**: Comprehensive error handling for network issues, rate limits, and API errors
- **Progress Reporting**: Visual progress indicators during scanning

### Result Presentation
- **Severity-based Notifications**: Different notification types based on vulnerability severity
- **Detailed Reports**: Comprehensive markdown reports with:
  - CVE information
  - Severity levels (critical, high, medium, low)
  - Fix recommendations
  - Reference links
- **Summary Statistics**: Package counts and vulnerability breakdowns

## Commands Added

| Command | Description |
|---------|-------------|
| `vulnzap.scanDependencies` | Scan Dependencies for Vulnerabilities |
| `vulnzap.forceDependencyScan` | Force Dependency Scan (Ignore Cache) |
| `vulnzap.dependencyCacheStats` | View Dependency Cache Statistics |
| `vulnzap.cleanDependencyCache` | Clean Dependency Cache |

## Configuration Options

```json
{
  "vulnzap.enableDependencyScanning": {
    "type": "boolean",
    "default": true,
    "description": "Enable automatic dependency vulnerability scanning"
  },
  "vulnzap.dependencyScanTimeout": {
    "type": "number",
    "default": 60000,
    "description": "Timeout in milliseconds for dependency vulnerability scans"
  },
  "vulnzap.dependencyCacheExpiry": {
    "type": "number",
    "default": 5,
    "description": "Number of days to cache dependency scan results"
  },
  "vulnzap.dependencyScanOnStartup": {
    "type": "boolean",
    "default": true,
    "description": "Automatically scan dependencies when workspace is opened"
  },
  "vulnzap.dependencyScanDebounce": {
    "type": "number",
    "default": 5000,
    "description": "Debounce time in milliseconds to prevent rapid dependency scans"
  }
}
```

## API Contract

### Batch Scan Request
```typescript
interface BatchScanRequest {
  packages: Array<{
    ecosystem: string;
    packageName: string;
    packageVersion: string;
  }>;
}
```

### Batch Scan Response
```typescript
interface BatchScanResponse {
  vulnerabilities: Array<{
    packageName: string;
    packageVersion: string;
    ecosystem: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    cveId?: string;
    description: string;
    fixedIn?: string;
    recommendation: string;
    references?: string[];
  }>;
  summary: {
    totalPackages: number;
    vulnerablePackages: number;
    severityCounts: {
      critical: number;
      high: number;
      medium: number;
      low: number;
    };
  };
  scanId: string;
  timestamp: number;
}
```

## Extension Integration

### File Event Handling
- Integrated into the main `onDidSaveTextDocument` event handler
- Automatic detection of dependency files using filename patterns
- Workspace-aware scanning (scans per workspace folder)

### Status Bar Integration
- No additional status bar indicators (uses existing security status)
- Progress notifications during scanning operations

### Security View Integration
- Dependency scanning commands added to security view menu
- Cache statistics accessible from security panel

## Error Handling

### Network Errors
- Graceful handling of network timeouts
- Rate limit detection and user notification
- API key validation with helpful error messages

### File System Errors
- Safe handling of unreadable files and directories
- Graceful degradation when cache operations fail
- Permission error handling for cache directory creation

### Parsing Errors
- Robust parsing with error recovery
- Logging of parsing failures without breaking the extension
- Support for malformed dependency files

## Security Considerations

### Cache Security
- Cache stored in extension's global storage directory
- No sensitive data cached (only dependency metadata and scan results)
- Automatic cleanup of expired entries

### API Security
- API keys stored securely in VS Code settings
- HTTPS-only communication with VulnZap API
- User-Agent header for proper API identification

## Performance Optimizations

### Caching Strategy
- Project-level caching to minimize API calls
- Dependency content hashing for efficient change detection
- Configurable cache expiry for balance between freshness and performance

### Scanning Efficiency
- Batch API requests instead of individual package queries
- Debouncing to prevent rapid successive scans
- Asynchronous operations to prevent UI blocking

### Memory Management
- Streaming file processing for large dependency files
- Cleanup of scan promises after completion
- Efficient data structures for dependency parsing

## Future Enhancements

1. **Dependency Tree Analysis**: Support for transitive dependency vulnerability detection
2. **Custom Vulnerability Databases**: Integration with additional vulnerability sources
3. **Automated Fixes**: Suggested dependency updates with version compatibility checks
4. **CI/CD Integration**: Export scan results for continuous integration pipelines
5. **Whitelist/Blacklist**: User-defined rules for ignoring specific vulnerabilities
6. **Severity Filtering**: User-configurable severity thresholds for notifications

## Testing

The feature can be tested by:
1. Creating dependency files with known vulnerable packages
2. Saving the files to trigger automatic scanning
3. Using manual scan commands
4. Verifying cache behavior by re-scanning without changes
5. Testing different ecosystems and file formats

## Conclusion

This comprehensive dependency vulnerability scanning feature significantly enhances the VulnZap extension's security capabilities by providing automated, multi-ecosystem vulnerability detection with intelligent caching and detailed reporting. The feature is designed to be performant, user-friendly, and extensible for future enhancements.