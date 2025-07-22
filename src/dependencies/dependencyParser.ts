import * as vscode from "vscode";
import * as fs from "fs";
import * as path from "path";

export interface Dependency {
  ecosystem: string;
  packageName: string;
  packageVersion: string;
  isDevelopment?: boolean;
  filePath: string;
}

export interface EcosystemInfo {
  name: string;
  files: string[];
  parser: (content: string, filePath: string) => Dependency[];
}

/**
 * Parser for extracting dependencies from various package manager files
 * Supports npm, pip, go, rust, gradle, maven, composer, rubygems, and more
 */
export class DependencyParser {
  private ecosystems: EcosystemInfo[] = [
    {
      name: "npm",
      files: ["package.json"],
      parser: this.parsePackageJson.bind(this),
    },
    {
      name: "pip",
      files: [
        "requirements.txt",
        "requirements-dev.txt",
        "requirements-test.txt",
        "Pipfile",
        "pyproject.toml",
      ],
      parser: this.parsePythonDependencies.bind(this),
    },
    {
      name: "go",
      files: ["go.mod"],
      parser: this.parseGoMod.bind(this),
    },
    {
      name: "cargo",
      files: ["Cargo.toml"],
      parser: this.parseCargoToml.bind(this),
    },
    {
      name: "maven",
      files: ["pom.xml"],
      parser: this.parsePomXml.bind(this),
    },
    {
      name: "gradle",
      files: ["build.gradle", "build.gradle.kts"],
      parser: this.parseGradleBuild.bind(this),
    },
    {
      name: "composer",
      files: ["composer.json"],
      parser: this.parseComposerJson.bind(this),
    },
    {
      name: "rubygems",
      files: ["Gemfile", "gemspec"],
      parser: this.parseGemfile.bind(this),
    },
    {
      name: "nuget",
      files: ["packages.config", "*.csproj", "*.fsproj", "*.vbproj"],
      parser: this.parseNuGetDependencies.bind(this),
    },
    {
      name: "cocoapods",
      files: ["Podfile"],
      parser: this.parsePodfile.bind(this),
    },
    {
      name: "yarn",
      files: ["yarn.lock"],
      parser: this.parseYarnLock.bind(this),
    },
  ];

  /**
   * Scans a workspace for dependency files and extracts all dependencies
   */
  async scanWorkspaceForDependencies(
    workspaceFolders: readonly vscode.WorkspaceFolder[]
  ): Promise<Dependency[]> {
    const allDependencies: Dependency[] = [];

    for (const folder of workspaceFolders) {
      const dependencies = await this.scanFolderForDependencies(
        folder.uri.fsPath
      );
      allDependencies.push(...dependencies);
    }

    return this.deduplicateDependencies(allDependencies);
  }

  /**
   * Scans a specific folder for dependency files
   */
  async scanFolderForDependencies(folderPath: string): Promise<Dependency[]> {
    const dependencies: Dependency[] = [];

    try {
      const files = await this.getAllFiles(folderPath);

      for (const ecosystem of this.ecosystems) {
        for (const fileName of ecosystem.files) {
          const matchingFiles = this.findMatchingFiles(files, fileName);

          for (const filePath of matchingFiles) {
            try {
              const content = fs.readFileSync(filePath, "utf8");
              const parsedDeps = ecosystem.parser(content, filePath);
              dependencies.push(...parsedDeps);
            } catch (error) {
              console.error(`Error parsing ${filePath}:`, error);
            }
          }
        }
      }
    } catch (error) {
      console.error(`Error scanning folder ${folderPath}:`, error);
    }

    return dependencies;
  }

  /**
   * Gets all files in a directory recursively, excluding common ignore patterns
   */
  private async getAllFiles(dirPath: string): Promise<string[]> {
    const files: string[] = [];
    const ignoreDirs = new Set([
      "node_modules",
      ".git",
      "dist",
      "build",
      "target",
      "vendor",
      "__pycache__",
      ".venv",
      ".next",
    ]);

    const traverse = (currentPath: string) => {
      try {
        const entries = fs.readdirSync(currentPath, { withFileTypes: true });

        for (const entry of entries) {
          const fullPath = path.join(currentPath, entry.name);

          if (entry.isDirectory() && !ignoreDirs.has(entry.name)) {
            traverse(fullPath);
          } else if (entry.isFile()) {
            files.push(fullPath);
          }
        }
      } catch (error) {
        // Skip directories we can't read
      }
    };

    traverse(dirPath);
    return files;
  }

  /**
   * Finds files matching a pattern (supports wildcards)
   */
  private findMatchingFiles(files: string[], pattern: string): string[] {
    if (pattern.includes("*")) {
      const regex = new RegExp(pattern.replace(/\*/g, ".*"));
      return files.filter((file) => regex.test(path.basename(file)));
    } else {
      return files.filter((file) => path.basename(file) === pattern);
    }
  }

  /**
   * Parses package.json for npm dependencies
   */
  private parsePackageJson(content: string, filePath: string): Dependency[] {
    try {
      const packageJson = JSON.parse(content);
      const dependencies: Dependency[] = [];

      // Regular dependencies
      if (packageJson.dependencies) {
        for (const [name, version] of Object.entries(
          packageJson.dependencies
        )) {
          dependencies.push({
            ecosystem: "npm",
            packageName: name,
            packageVersion: this.cleanVersion(version as string),
            isDevelopment: false,
            filePath,
          });
        }
      }

      // Dev dependencies
      if (packageJson.devDependencies) {
        for (const [name, version] of Object.entries(
          packageJson.devDependencies
        )) {
          dependencies.push({
            ecosystem: "npm",
            packageName: name,
            packageVersion: this.cleanVersion(version as string),
            isDevelopment: true,
            filePath,
          });
        }
      }

      return dependencies;
    } catch (error) {
      console.error("Error parsing package.json:", error);
      return [];
    }
  }

  /**
   * Parses Python dependency files
   */
  private parsePythonDependencies(
    content: string,
    filePath: string
  ): Dependency[] {
    const fileName = path.basename(filePath);
    const dependencies: Dependency[] = [];

    try {
      if (fileName === "Pipfile") {
        return this.parsePipfile(content, filePath);
      } else if (fileName === "pyproject.toml") {
        return this.parsePyprojectToml(content, filePath);
      } else {
        // requirements.txt format
        const lines = content.split("\n");
        for (const line of lines) {
          const trimmed = line.trim();
          if (trimmed && !trimmed.startsWith("#") && !trimmed.startsWith("-")) {
            const match = trimmed.match(
              /^([a-zA-Z0-9_-]+)([><=!~\s]*[0-9.*]+)?/
            );
            if (match) {
              dependencies.push({
                ecosystem: "pip",
                packageName: match[1],
                packageVersion: match[2] ? this.cleanVersion(match[2]) : "*",
                isDevelopment:
                  fileName.includes("dev") || fileName.includes("test"),
                filePath,
              });
            }
          }
        }
      }
    } catch (error) {
      console.error("Error parsing Python dependencies:", error);
    }

    return dependencies;
  }

  /**
   * Parses Pipfile for Python dependencies
   */
  private parsePipfile(content: string, filePath: string): Dependency[] {
    // Simple TOML-like parsing for Pipfile
    const dependencies: Dependency[] = [];
    const lines = content.split("\n");
    let currentSection = "";

    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
        currentSection = trimmed.slice(1, -1);
      } else if (
        (currentSection === "packages" || currentSection === "dev-packages") &&
        trimmed.includes("=")
      ) {
        const [name, version] = trimmed.split("=", 2);
        if (name && version) {
          dependencies.push({
            ecosystem: "pip",
            packageName: name.trim(),
            packageVersion: this.cleanVersion(version.trim().replace(/"/g, "")),
            isDevelopment: currentSection === "dev-packages",
            filePath,
          });
        }
      }
    }

    return dependencies;
  }

  /**
   * Parses pyproject.toml for Python dependencies
   */
  private parsePyprojectToml(content: string, filePath: string): Dependency[] {
    const dependencies: Dependency[] = [];
    // Basic TOML parsing for dependencies section
    const dependenciesMatch = content.match(
      /\[tool\.poetry\.dependencies\]([\s\S]*?)(?=\[|$)/
    );
    if (dependenciesMatch) {
      const lines = dependenciesMatch[1].split("\n");
      for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed && trimmed.includes("=") && !trimmed.startsWith("#")) {
          const [name, version] = trimmed.split("=", 2);
          if (name && version && name.trim() !== "python") {
            dependencies.push({
              ecosystem: "pip",
              packageName: name.trim(),
              packageVersion: this.cleanVersion(
                version.trim().replace(/"/g, "")
              ),
              isDevelopment: false,
              filePath,
            });
          }
        }
      }
    }

    return dependencies;
  }

  /**
   * Parses go.mod for Go dependencies
   */
  private parseGoMod(content: string, filePath: string): Dependency[] {
    const dependencies: Dependency[] = [];
    const lines = content.split("\n");
    let inRequireBlock = false;

    for (const line of lines) {
      const trimmed = line.trim();

      if (trimmed === "require (") {
        inRequireBlock = true;
        continue;
      }

      if (trimmed === ")" && inRequireBlock) {
        inRequireBlock = false;
        continue;
      }

      if (trimmed.startsWith("require ") || inRequireBlock) {
        const requireLine = trimmed.startsWith("require ")
          ? trimmed.substring(8)
          : trimmed;
        const parts = requireLine.split(/\s+/);
        if (parts.length >= 2) {
          dependencies.push({
            ecosystem: "go",
            packageName: parts[0],
            packageVersion: parts[1],
            isDevelopment: false,
            filePath,
          });
        }
      }
    }

    return dependencies;
  }

  /**
   * Parses Cargo.toml for Rust dependencies
   */
  private parseCargoToml(content: string, filePath: string): Dependency[] {
    const dependencies: Dependency[] = [];

    // Simple TOML parsing for dependencies
    const sections = [
      "[dependencies]",
      "[dev-dependencies]",
      "[build-dependencies]",
    ];

    for (const section of sections) {
      const sectionMatch = content.match(
        new RegExp(`\\${section}([\\s\\S]*?)(?=\\[|$)`)
      );
      if (sectionMatch) {
        const lines = sectionMatch[1].split("\n");
        for (const line of lines) {
          const trimmed = line.trim();
          if (trimmed && trimmed.includes("=") && !trimmed.startsWith("#")) {
            const [name, version] = trimmed.split("=", 2);
            if (name && version) {
              dependencies.push({
                ecosystem: "cargo",
                packageName: name.trim(),
                packageVersion: this.cleanVersion(
                  version.trim().replace(/"/g, "")
                ),
                isDevelopment:
                  section.includes("dev") || section.includes("build"),
                filePath,
              });
            }
          }
        }
      }
    }

    return dependencies;
  }

  /**
   * Parses pom.xml for Maven dependencies
   */
  private parsePomXml(content: string, filePath: string): Dependency[] {
    const dependencies: Dependency[] = [];

    // Simple XML parsing for Maven dependencies
    const dependencyRegex = /<dependency>([\s\S]*?)<\/dependency>/g;
    let match;

    while ((match = dependencyRegex.exec(content)) !== null) {
      const depContent = match[1];
      const groupIdMatch = depContent.match(/<groupId>(.*?)<\/groupId>/);
      const artifactIdMatch = depContent.match(
        /<artifactId>(.*?)<\/artifactId>/
      );
      const versionMatch = depContent.match(/<version>(.*?)<\/version>/);
      const scopeMatch = depContent.match(/<scope>(.*?)<\/scope>/);

      if (groupIdMatch && artifactIdMatch && versionMatch) {
        dependencies.push({
          ecosystem: "maven",
          packageName: `${groupIdMatch[1]}:${artifactIdMatch[1]}`,
          packageVersion: versionMatch[1],
          isDevelopment: scopeMatch ? scopeMatch[1] === "test" : false,
          filePath,
        });
      }
    }

    return dependencies;
  }

  /**
   * Parses Gradle build files
   */
  private parseGradleBuild(content: string, filePath: string): Dependency[] {
    const dependencies: Dependency[] = [];

    // Parse both Groovy and Kotlin DSL formats
    const dependencyPatterns = [
      /(?:implementation|compile|api|testImplementation|testCompile)\s+['"](.*?)['"]/g,
      /(?:implementation|compile|api|testImplementation|testCompile)\s*\(\s*['"](.*?)['"]\s*\)/g,
    ];

    for (const pattern of dependencyPatterns) {
      let match;
      while ((match = pattern.exec(content)) !== null) {
        const depString = match[1];
        const parts = depString.split(":");
        if (parts.length >= 3) {
          dependencies.push({
            ecosystem: "gradle",
            packageName: `${parts[0]}:${parts[1]}`,
            packageVersion: parts[2],
            isDevelopment: match[0].includes("test"),
            filePath,
          });
        }
      }
    }

    return dependencies;
  }

  /**
   * Parses composer.json for PHP dependencies
   */
  private parseComposerJson(content: string, filePath: string): Dependency[] {
    try {
      const composer = JSON.parse(content);
      const dependencies: Dependency[] = [];

      if (composer.require) {
        for (const [name, version] of Object.entries(composer.require)) {
          dependencies.push({
            ecosystem: "composer",
            packageName: name,
            packageVersion: this.cleanVersion(version as string),
            isDevelopment: false,
            filePath,
          });
        }
      }

      if (composer["require-dev"]) {
        for (const [name, version] of Object.entries(composer["require-dev"])) {
          dependencies.push({
            ecosystem: "composer",
            packageName: name,
            packageVersion: this.cleanVersion(version as string),
            isDevelopment: true,
            filePath,
          });
        }
      }

      return dependencies;
    } catch (error) {
      console.error("Error parsing composer.json:", error);
      return [];
    }
  }

  /**
   * Parses Gemfile for Ruby dependencies
   */
  private parseGemfile(content: string, filePath: string): Dependency[] {
    const dependencies: Dependency[] = [];
    const lines = content.split("\n");

    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed.startsWith("gem ")) {
        const gemMatch = trimmed.match(
          /gem\s+['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?/
        );
        if (gemMatch) {
          dependencies.push({
            ecosystem: "rubygems",
            packageName: gemMatch[1],
            packageVersion: gemMatch[2] ? this.cleanVersion(gemMatch[2]) : "*",
            isDevelopment:
              trimmed.includes("group:") && trimmed.includes("development"),
            filePath,
          });
        }
      }
    }

    return dependencies;
  }

  /**
   * Parses NuGet package files
   */
  private parseNuGetDependencies(
    content: string,
    filePath: string
  ): Dependency[] {
    const dependencies: Dependency[] = [];
    const fileName = path.basename(filePath);

    if (fileName === "packages.config") {
      const packageRegex = /<package\s+id="([^"]+)"\s+version="([^"]+)"/g;
      let match;
      while ((match = packageRegex.exec(content)) !== null) {
        dependencies.push({
          ecosystem: "nuget",
          packageName: match[1],
          packageVersion: match[2],
          isDevelopment: false,
          filePath,
        });
      }
    } else {
      // .csproj, .fsproj, .vbproj
      const packageRefRegex =
        /<PackageReference\s+Include="([^"]+)"\s+Version="([^"]+)"/g;
      let match;
      while ((match = packageRefRegex.exec(content)) !== null) {
        dependencies.push({
          ecosystem: "nuget",
          packageName: match[1],
          packageVersion: match[2],
          isDevelopment: false,
          filePath,
        });
      }
    }

    return dependencies;
  }

  /**
   * Parses Podfile for CocoaPods dependencies
   */
  private parsePodfile(content: string, filePath: string): Dependency[] {
    const dependencies: Dependency[] = [];
    const lines = content.split("\n");

    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed.startsWith("pod ")) {
        const podMatch = trimmed.match(
          /pod\s+['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?/
        );
        if (podMatch) {
          dependencies.push({
            ecosystem: "cocoapods",
            packageName: podMatch[1],
            packageVersion: podMatch[2] ? this.cleanVersion(podMatch[2]) : "*",
            isDevelopment: false,
            filePath,
          });
        }
      }
    }

    return dependencies;
  }

  /**
   * Parses yarn.lock file
   */
  private parseYarnLock(content: string, filePath: string): Dependency[] {
    const dependencies: Dependency[] = [];
    const blocks = content.split("\n\n");

    for (const block of blocks) {
      const lines = block.split("\n");
      if (lines.length > 0) {
        const headerMatch = lines[0].match(/^"?([^@"]+)@/);
        const versionMatch = block.match(/version\s+"([^"]+)"/);

        if (headerMatch && versionMatch) {
          dependencies.push({
            ecosystem: "npm",
            packageName: headerMatch[1],
            packageVersion: versionMatch[1],
            isDevelopment: false,
            filePath,
          });
        }
      }
    }

    return dependencies;
  }

  /**
   * Cleans version strings by removing prefixes and operators
   */
  private cleanVersion(version: string): string {
    return version.replace(/^[~^>=<!\s]+/, "").trim();
  }

  /**
   * Removes duplicate dependencies from the list
   */
  private deduplicateDependencies(dependencies: Dependency[]): Dependency[] {
    const seen = new Set<string>();
    return dependencies.filter((dep) => {
      const key = `${dep.ecosystem}:${dep.packageName}:${dep.packageVersion}`;
      if (seen.has(key)) {
        return false;
      }
      seen.add(key);
      return true;
    });
  }

  /**
   * Checks if a file is a dependency file that should trigger scanning
   */
  isDependencyFile(filePath: string): boolean {
    const fileName = path.basename(filePath);
    return this.ecosystems.some((ecosystem) =>
      ecosystem.files.some((pattern) => {
        if (pattern.includes("*")) {
          const regex = new RegExp(pattern.replace(/\*/g, ".*"));
          return regex.test(fileName);
        }
        return fileName === pattern;
      })
    );
  }

  /**
   * Gets the ecosystem name for a given file
   */
  getEcosystemForFile(filePath: string): string | null {
    const fileName = path.basename(filePath);

    for (const ecosystem of this.ecosystems) {
      if (
        ecosystem.files.some((pattern) => {
          if (pattern.includes("*")) {
            const regex = new RegExp(pattern.replace(/\*/g, ".*"));
            return regex.test(fileName);
          }
          return fileName === pattern;
        })
      ) {
        return ecosystem.name;
      }
    }

    return null;
  }
}
