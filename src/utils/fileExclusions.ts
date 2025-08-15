import * as path from "path";
import * as vscode from "vscode";

/**
 * Comprehensive file exclusion patterns for security scanning
 * These files should not be scanned for security vulnerabilities
 */
export class FileExclusionManager {
  // File extensions that should never be scanned
  private static readonly EXCLUDED_EXTENSIONS = new Set([
    // Package manager files
    ".json", // package.json, composer.json, etc.
    ".lock", // package-lock.json, yarn.lock, composer.lock, etc.
    ".toml", // Cargo.toml, pyproject.toml, etc.
    ".xml", // pom.xml, packages.config, etc.

    // Configuration files
    ".config", // Various config files
    ".conf", // Configuration files
    ".ini", // INI configuration files
    ".env", // Environment files (may contain secrets but not code to scan)
    ".properties", // Java properties files
    ".yaml", // YAML configuration files
    ".yml", // YAML configuration files

    // Documentation and markup
    ".md", // Markdown files
    ".txt", // Text files
    ".rst", // reStructuredText
    ".adoc", // AsciiDoc
    ".tex", // LaTeX files
    ".rtf", // Rich Text Format

    // Media files
    ".png", // Images
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".webp",
    ".bmp",
    ".tiff",
    ".mp3", // Audio
    ".wav",
    ".ogg",
    ".mp4", // Video
    ".avi",
    ".mov",
    ".wmv",
    ".flv",

    // Binary and compiled files
    ".exe", // Executables
    ".dll", // Dynamic libraries
    ".so", // Shared objects
    ".dylib", // macOS dynamic libraries
    ".bin", // Binary files
    ".dat", // Data files
    ".db", // Database files
    ".sqlite", // SQLite databases
    ".sqlite3",

    // Archive files
    ".zip", // Archives
    ".tar",
    ".gz",
    ".rar",
    ".7z",
    ".bz2",
    ".xz",

    // IDE and editor files
    ".vscode", // VS Code settings (directory)
    ".idea", // IntelliJ IDEA settings (directory)
    ".sublime-workspace",
    ".sublime-project",

    // Font files
    ".ttf", // Fonts
    ".otf",
    ".woff",
    ".woff2",
    ".eot",

    // Certificate and key files (sensitive but not code)
    ".pem", // Certificates
    ".crt",
    ".cer",
    ".key",
    ".p12",
    ".pfx",

    // Log files
    ".log", // Log files
    ".out", // Output files

    // Temporary files
    ".tmp", // Temporary files
    ".temp",
    ".bak", // Backup files
    ".swp", // Vim swap files
    ".swo",

    // Source maps and generated files
    ".map", // Source maps
    ".min.js", // Minified JavaScript (usually generated)
    ".min.css", // Minified CSS (usually generated)
  ]);

  // Specific filenames that should never be scanned
  private static readonly EXCLUDED_FILENAMES = new Set([
    // Package manager files
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "composer.json",
    "composer.lock",
    "Pipfile",
    "Pipfile.lock",
    "requirements.txt",
    "requirements-dev.txt",
    "requirements-test.txt",
    "pyproject.toml",
    "poetry.lock",
    "Cargo.toml",
    "Cargo.lock",
    "go.mod",
    "go.sum",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "gradle.properties",
    "settings.gradle",
    "packages.config",
    "Podfile",
    "Podfile.lock",
    "Gemfile",
    "Gemfile.lock",

    // Configuration files
    ".gitignore",
    ".gitattributes",
    ".editorconfig",
    ".eslintrc",
    ".eslintrc.js",
    ".eslintrc.json",
    ".prettierrc",
    ".prettierrc.js",
    ".prettierrc.json",
    "prettier.config.js",
    "tsconfig.json",
    "jsconfig.json",
    "webpack.config.js",
    "vite.config.js",
    "rollup.config.js",
    "babel.config.js",
    ".babelrc",
    ".babelrc.js",
    ".babelrc.json",
    "jest.config.js",
    "vitest.config.js",
    "cypress.config.js",
    "playwright.config.js",
    "tailwind.config.js",
    "postcss.config.js",
    "next.config.js",
    "nuxt.config.js",
    "vue.config.js",
    "angular.json",
    "nx.json",
    "lerna.json",
    "rush.json",
    ".nvmrc",
    ".node-version",
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    ".dockerignore",
    "Makefile",
    "CMakeLists.txt",
    "configure",
    "configure.ac",
    "Makefile.in",
    "Makefile.am",

    // IDE and editor files
    ".DS_Store",
    "Thumbs.db",
    "desktop.ini",

    // CI/CD files
    ".travis.yml",
    ".github",
    ".gitlab-ci.yml",
    "appveyor.yml",
    "azure-pipelines.yml",
    "buildspec.yml",
    "cloudbuild.yaml",

    // Documentation
    "README.md",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "LICENSE",
    "LICENSE.txt",
    "LICENSE.md",
    "NOTICE",
    "NOTICE.txt",
    "AUTHORS",
    "CONTRIBUTORS",
    "MAINTAINERS",
    "SECURITY.md",
    "CODE_OF_CONDUCT.md",

    // Other common files
    "favicon.ico",
    "robots.txt",
    "sitemap.xml",
    "manifest.json",
    "sw.js",
    "service-worker.js",
  ]);

  // Directory patterns that should be excluded (and their contents)
  private static readonly EXCLUDED_DIRECTORIES = new Set([
    "node_modules",
    ".git",
    ".svn",
    ".hg",
    "dist",
    "build",
    "out",
    "target",
    "bin",
    "obj",
    "vendor",
    "__pycache__",
    ".pytest_cache",
    ".coverage",
    ".nyc_output",
    "coverage",
    ".venv",
    "venv",
    "env",
    ".env",
    ".next",
    ".nuxt",
    ".output",
    ".vercel",
    ".netlify",
    ".cache",
    ".parcel-cache",
    ".temp",
    ".tmp",
    "tmp",
    "temp",
    "logs",
    ".logs",
    ".vscode",
    ".idea",
    ".vs",
    ".gradle",
    ".mvn",
    ".m2",
    ".cargo",
    ".rustup",
    "Pods",
    "DerivedData",
    ".expo",
    ".expo-shared",
    "android/app/build",
    "ios/build",
    "web-build",
  ]);

  // File patterns (glob-like) that should be excluded
  private static readonly EXCLUDED_PATTERNS = [
    "*.min.js",
    "*.min.css",
    "*.bundle.js",
    "*.chunk.js",
    "*.map",
    "*.d.ts",
    "*.spec.js",
    "*.test.js",
    "*.spec.ts",
    "*.test.ts",
    "*.spec.jsx",
    "*.test.jsx",
    "*.spec.tsx",
    "*.test.tsx",
    "*.stories.js",
    "*.stories.ts",
    "*.stories.jsx",
    "*.stories.tsx",
    "*.config.*",
    "*.conf.*",
    "webpack.*.js",
    "rollup.*.js",
    "vite.*.js",
    "jest.*.js",
    "*.lock",
    "*.log",
    "*.pid",
    "*.seed",
    "*.tgz",
    "*.tar.gz",
    "npm-debug.log*",
    "yarn-debug.log*",
    "yarn-error.log*",
    "lerna-debug.log*",
    ".DS_Store",
    ".DS_Store?",
    "._*",
    ".Spotlight-V100",
    ".Trashes",
    "ehthumbs.db",
    "Thumbs.db",
  ];

  /**
   * Check if a file should be excluded from security scanning
   */
  public static shouldExcludeFile(filePath: string): boolean {
    const fileName = path.basename(filePath);
    const fileExt = path.extname(filePath).toLowerCase();
    const dirName = path.dirname(filePath);

    // Check if file extension is excluded
    if (this.EXCLUDED_EXTENSIONS.has(fileExt)) {
      return true;
    }

    // Check if filename is explicitly excluded
    if (this.EXCLUDED_FILENAMES.has(fileName)) {
      return true;
    }

    // Check if file is in an excluded directory
    const pathParts = filePath.split(path.sep);
    for (const part of pathParts) {
      if (this.EXCLUDED_DIRECTORIES.has(part)) {
        return true;
      }
    }

    // Check if file matches excluded patterns
    for (const pattern of this.EXCLUDED_PATTERNS) {
      if (this.matchesPattern(fileName, pattern)) {
        return true;
      }
    }

    // Check user-configured exclusions
    const userExclusions = this.getUserConfiguredExclusions();
    for (const pattern of userExclusions) {
      if (
        this.matchesPattern(filePath, pattern) ||
        this.matchesPattern(fileName, pattern)
      ) {
        return true;
      }
    }

    return false;
  }

  /**
   * Get reason why a file is excluded (for user feedback)
   */
  public static getExclusionReason(filePath: string): string {
    const fileName = path.basename(filePath);
    const fileExt = path.extname(filePath).toLowerCase();

    if (this.EXCLUDED_EXTENSIONS.has(fileExt)) {
      return `File extension '${fileExt}' is excluded from security scanning`;
    }

    if (this.EXCLUDED_FILENAMES.has(fileName)) {
      return `File '${fileName}' is a configuration/package file and is excluded from scanning`;
    }

    const pathParts = filePath.split(path.sep);
    for (const part of pathParts) {
      if (this.EXCLUDED_DIRECTORIES.has(part)) {
        return `File is in excluded directory '${part}'`;
      }
    }

    for (const pattern of this.EXCLUDED_PATTERNS) {
      if (this.matchesPattern(fileName, pattern)) {
        return `File matches excluded pattern '${pattern}'`;
      }
    }

    const userExclusions = this.getUserConfiguredExclusions();
    for (const pattern of userExclusions) {
      if (
        this.matchesPattern(filePath, pattern) ||
        this.matchesPattern(fileName, pattern)
      ) {
        return `File matches user-configured exclusion pattern '${pattern}'`;
      }
    }

    return "File is excluded from scanning";
  }

  /**
   * Get all excluded file patterns as a readable list
   */
  public static getExcludedPatterns(): {
    extensions: string[];
    filenames: string[];
    directories: string[];
    patterns: string[];
  } {
    return {
      extensions: Array.from(this.EXCLUDED_EXTENSIONS).sort(),
      filenames: Array.from(this.EXCLUDED_FILENAMES).sort(),
      directories: Array.from(this.EXCLUDED_DIRECTORIES).sort(),
      patterns: this.EXCLUDED_PATTERNS.slice().sort(),
    };
  }

  /**
   * Simple glob pattern matching
   */
  private static matchesPattern(str: string, pattern: string): boolean {
    // Convert glob pattern to regex
    const regexPattern = pattern
      .replace(/\./g, "\\.")
      .replace(/\*/g, ".*")
      .replace(/\?/g, ".");

    const regex = new RegExp(`^${regexPattern}$`, "i");
    return regex.test(str);
  }

  /**
   * Get user-configured exclusion patterns from VS Code settings
   */
  private static getUserConfiguredExclusions(): string[] {
    const config = vscode.workspace.getConfiguration("vulnzap");
    return config.get<string[]>("excludeFilePatterns", []);
  }

  /**
   * Check if a file type is supported for scanning (even if not excluded)
   */
  public static isSupportedForScanning(languageId: string): boolean {
    const supportedLanguages = [
      "javascript",
      "typescript",
      "javascriptreact",
      "typescriptreact",
      "python",
      "java",
      "php",
      "csharp",
    ];
    return supportedLanguages.includes(languageId);
  }

  /**
   * Get statistics about file exclusions in the current workspace
   */
  public static async getWorkspaceExclusionStats(): Promise<{
    totalFiles: number;
    excludedFiles: number;
    supportedFiles: number;
    exclusionReasons: Record<string, number>;
  }> {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders) {
      return {
        totalFiles: 0,
        excludedFiles: 0,
        supportedFiles: 0,
        exclusionReasons: {},
      };
    }

    let totalFiles = 0;
    let excludedFiles = 0;
    let supportedFiles = 0;
    const exclusionReasons: Record<string, number> = {};

    for (const folder of workspaceFolders) {
      const files = await vscode.workspace.findFiles(
        new vscode.RelativePattern(folder, "**/*"),
        new vscode.RelativePattern(
          folder,
          "{node_modules,dist,build,target,vendor,.git}/**"
        ),
        10000 // Limit to prevent performance issues
      );

      for (const file of files) {
        totalFiles++;

        if (this.shouldExcludeFile(file.fsPath)) {
          excludedFiles++;
          const reason = this.getExclusionReason(file.fsPath);
          exclusionReasons[reason] = (exclusionReasons[reason] || 0) + 1;
        } else {
          const doc = await vscode.workspace.openTextDocument(file);
          if (this.isSupportedForScanning(doc.languageId)) {
            supportedFiles++;
          }
        }
      }
    }

    return {
      totalFiles,
      excludedFiles,
      supportedFiles,
      exclusionReasons,
    };
  }
}
