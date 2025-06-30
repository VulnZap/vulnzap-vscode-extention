import * as vscode from 'vscode';
import * as ts from 'typescript';
import * as path from 'path';

export interface CodeContext {
    isTestFile: boolean;
    isConfigFile: boolean;
    isDocumentationFile: boolean;
    framework?: string;
    dependencies: string[];
    imports: string[];
    exports: string[];
    functionContexts: FunctionContext[];
    variableContexts: VariableContext[];
    fileType: 'production' | 'test' | 'config' | 'documentation' | 'unknown';
}

export interface FunctionContext {
    name: string;
    isAsync: boolean;
    parameters: string[];
    isExported: boolean;
    isPrivate: boolean;
    isTestFunction: boolean;
    containsSecurityPatterns: boolean;
    securityRelevantOperations: string[];
}

export interface VariableContext {
    name: string;
    type?: string;
    isConstant: boolean;
    isSecuritySensitive: boolean;
    scope: 'global' | 'function' | 'block';
    usagePattern: 'input' | 'output' | 'internal' | 'config';
}

export interface SecurityContext {
    isInTestContext: boolean;
    isInMockContext: boolean;
    isInCommentBlock: boolean;
    isInStringLiteral: boolean;
    isInRegularExpression: boolean;
    hasInputValidation: boolean;
    hasOutputSanitization: boolean;
    usesSecurityLibrary: boolean;
    dataFlowContext: DataFlowContext;
}

export interface DataFlowContext {
    hasUserInput: boolean;
    hasNetworkInput: boolean;
    hasFileInput: boolean;
    hasDataBaseOutput: boolean;
    hasNetworkOutput: boolean;
    hasFileOutput: boolean;
    dataValidationMethods: string[];
    sanitizationMethods: string[];
}

export class ContextAnalyzer {
    private workspaceFolder: string;
    private packageJsonCache = new Map<string, any>();
    private astCache = new Map<string, ts.SourceFile>();

    constructor(workspaceFolder?: string) {
        this.workspaceFolder = workspaceFolder || vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || '';
    }

    /**
     * Analyzes the complete context of a document to understand its security relevance
     */
    async analyzeDocumentContext(document: vscode.TextDocument): Promise<CodeContext> {
        const filePath = document.fileName;
        const text = document.getText();
        const languageId = document.languageId;

        // Determine file type and purpose
        const fileType = this.determineFileType(filePath, text);
        const isTestFile = this.isTestFile(filePath, text);
        const isConfigFile = this.isConfigurationFile(filePath);
        const isDocumentationFile = this.isDocumentationFile(filePath);

        // Get project dependencies and framework
        const dependencies = await this.getProjectDependencies(filePath);
        const framework = this.detectFramework(dependencies, text);

        // Analyze code structure
        let functionContexts: FunctionContext[] = [];
        let variableContexts: VariableContext[] = [];
        let imports: string[] = [];
        let exports: string[] = [];

        if (languageId === 'typescript' || languageId === 'javascript') {
            const analysis = this.analyzeTypeScriptCode(text, filePath);
            functionContexts = analysis.functions;
            variableContexts = analysis.variables;
            imports = analysis.imports;
            exports = analysis.exports;
        } else if (languageId === 'python') {
            const analysis = this.analyzePythonCode(text);
            functionContexts = analysis.functions;
            variableContexts = analysis.variables;
            imports = analysis.imports;
            exports = analysis.exports;
        }

        return {
            isTestFile,
            isConfigFile,
            isDocumentationFile,
            framework,
            dependencies,
            imports,
            exports,
            functionContexts,
            variableContexts,
            fileType
        };
    }

    /**
     * Analyzes the security context around a specific line/position
     */
    analyzeSecurityContext(
        document: vscode.TextDocument, 
        line: number, 
        column: number,
        codeContext: CodeContext
    ): SecurityContext {
        const text = document.getText();
        const lines = text.split('\n');
        const currentLine = lines[line];
        
        // Check if we're in a test context
        const isInTestContext = this.isInTestContext(line, lines, codeContext);
        const isInMockContext = this.isInMockContext(line, lines);
        const isInCommentBlock = this.isInCommentBlock(line, column, text);
        const isInStringLiteral = this.isInStringLiteral(line, column, currentLine);
        const isInRegularExpression = this.isInRegularExpression(line, column, currentLine);

        // Analyze security patterns
        const hasInputValidation = this.hasInputValidationNearby(line, lines);
        const hasOutputSanitization = this.hasOutputSanitizationNearby(line, lines);
        const usesSecurityLibrary = this.usesSecurityLibrary(codeContext.imports, codeContext.dependencies);

        // Analyze data flow
        const dataFlowContext = this.analyzeDataFlow(line, lines, codeContext);

        return {
            isInTestContext,
            isInMockContext,
            isInCommentBlock,
            isInStringLiteral,
            isInRegularExpression,
            hasInputValidation,
            hasOutputSanitization,
            usesSecurityLibrary,
            dataFlowContext
        };
    }

    /**
     * Determines if a security issue is likely a false positive based on context
     */
    isLikelyFalsePositive(
        issue: any,
        codeContext: CodeContext,
        securityContext: SecurityContext
    ): boolean {
        const config = vscode.workspace.getConfiguration('vulnzap');
        const enableContextAnalysis = config.get<boolean>('enableContextAnalysis', true);
        const enableTestFileFiltering = config.get<boolean>('enableTestFileFiltering', true);
        const enableDataFlowAnalysis = config.get<boolean>('enableDataFlowAnalysis', true);

        if (!enableContextAnalysis) {
            return false; // Skip context-based filtering if disabled
        }

        // Rule 1: Issues in test files are often false positives
        if (enableTestFileFiltering && securityContext.isInTestContext && !this.isSecurityTestPattern(issue)) {
            return true;
        }

        // Rule 2: Issues in mock/stub code
        if (securityContext.isInMockContext) {
            return true;
        }

        // Rule 3: Issues in comments or documentation
        if (securityContext.isInCommentBlock || codeContext.isDocumentationFile) {
            return true;
        }

        // Rule 4: Hardcoded values in configuration files (often legitimate)
        if (codeContext.isConfigFile && this.isConfigurationValue(issue)) {
            return true;
        }

        // Rule 5: Security patterns with proper validation/sanitization
        if (this.hasProperSecurityMeasures(issue, securityContext)) {
            return true;
        }

        // Rule 6: String literals that are not user-controlled
        if (enableDataFlowAnalysis && securityContext.isInStringLiteral && !securityContext.dataFlowContext.hasUserInput) {
            return true;
        }

        // Rule 7: Development/debugging code in non-production context
        if (this.isDevelopmentCode(issue, codeContext)) {
            return true;
        }

        return false;
    }

    private determineFileType(filePath: string, content: string): 'production' | 'test' | 'config' | 'documentation' | 'unknown' {
        const fileName = path.basename(filePath).toLowerCase();
        const fileContent = content.toLowerCase();

        // Test files
        if (this.isTestFile(filePath, content)) {
            return 'test';
        }

        // Configuration files
        if (this.isConfigurationFile(filePath)) {
            return 'config';
        }

        // Documentation
        if (this.isDocumentationFile(filePath)) {
            return 'documentation';
        }

        // Check content for production patterns
        if (fileContent.includes('export') || fileContent.includes('module.exports') || 
            fileContent.includes('class ') || fileContent.includes('function ')) {
            return 'production';
        }

        return 'unknown';
    }

    private isTestFile(filePath: string, content: string): boolean {
        const fileName = path.basename(filePath).toLowerCase();
        const fileContent = content.toLowerCase();
        
        // File name patterns
        const testFilePatterns = [
            /\.test\./,
            /\.spec\./,
            /_test\./,
            /_spec\./,
            /test_.*\.py$/,
            /tests?\/.*\.py$/
        ];

        if (testFilePatterns.some(pattern => pattern.test(fileName))) {
            return true;
        }

        // Content patterns
        const testContentPatterns = [
            /describe\s*\(/,
            /it\s*\(/,
            /test\s*\(/,
            /expect\s*\(/,
            /assert/,
            /jest/,
            /mocha/,
            /unittest/,
            /pytest/
        ];

        return testContentPatterns.some(pattern => pattern.test(fileContent));
    }

    private isConfigurationFile(filePath: string): boolean {
        const fileName = path.basename(filePath).toLowerCase();
        const configPatterns = [
            /package\.json$/,
            /\.config\./,
            /config\./,
            /\.env/,
            /settings\.py$/,
            /webpack\./,
            /babel\./,
            /tsconfig\./,
            /\.yml$/,
            /\.yaml$/,
            /\.toml$/
        ];

        return configPatterns.some(pattern => pattern.test(fileName));
    }

    private isDocumentationFile(filePath: string): boolean {
        const fileName = path.basename(filePath).toLowerCase();
        return /\.(md|txt|rst)$/.test(fileName) || fileName === 'readme';
    }

    private async getProjectDependencies(filePath: string): Promise<string[]> {
        try {
            const workspaceRoot = this.workspaceFolder;
            const packageJsonPath = path.join(workspaceRoot, 'package.json');
            
            if (this.packageJsonCache.has(packageJsonPath)) {
                const pkg = this.packageJsonCache.get(packageJsonPath);
                return Object.keys({ ...pkg.dependencies, ...pkg.devDependencies });
            }

            const document = await vscode.workspace.openTextDocument(packageJsonPath);
            const packageJson = JSON.parse(document.getText());
            this.packageJsonCache.set(packageJsonPath, packageJson);
            
            return Object.keys({ ...packageJson.dependencies, ...packageJson.devDependencies });
        } catch {
            return [];
        }
    }

    private detectFramework(dependencies: string[], content: string): string | undefined {
        const frameworks = [
            { name: 'react', patterns: ['react', '@types/react'] },
            { name: 'vue', patterns: ['vue', '@vue/'] },
            { name: 'angular', patterns: ['@angular/', 'angular'] },
            { name: 'express', patterns: ['express'] },
            { name: 'nestjs', patterns: ['@nestjs/'] },
            { name: 'django', patterns: ['django'] },
            { name: 'flask', patterns: ['flask'] },
            { name: 'spring', patterns: ['spring'] }
        ];

        for (const framework of frameworks) {
            if (framework.patterns.some(pattern => 
                dependencies.some(dep => dep.includes(pattern)) ||
                content.toLowerCase().includes(pattern)
            )) {
                return framework.name;
            }
        }

        return undefined;
    }

    private analyzeTypeScriptCode(text: string, filePath: string) {
        try {
            const sourceFile = ts.createSourceFile(
                filePath,
                text,
                ts.ScriptTarget.Latest,
                true
            );

            const functions: FunctionContext[] = [];
            const variables: VariableContext[] = [];
            const imports: string[] = [];
            const exports: string[] = [];

            const visit = (node: ts.Node) => {
                if (ts.isFunctionDeclaration(node) || ts.isMethodDeclaration(node)) {
                    functions.push(this.extractFunctionContext(node, sourceFile));
                } else if (ts.isVariableDeclaration(node)) {
                    variables.push(this.extractVariableContext(node, sourceFile));
                } else if (ts.isImportDeclaration(node)) {
                    imports.push(this.extractImportName(node));
                } else if (ts.isExportDeclaration(node) || ts.isExportAssignment(node)) {
                    exports.push(this.extractExportName(node));
                }

                ts.forEachChild(node, visit);
            };

            visit(sourceFile);

            return { functions, variables, imports, exports };
        } catch (error) {
            console.warn('Failed to parse TypeScript code:', error);
            return { functions: [], variables: [], imports: [], exports: [] };
        }
    }

    private analyzePythonCode(text: string) {
        // Basic Python analysis using regex patterns
        const functions: FunctionContext[] = [];
        const variables: VariableContext[] = [];
        const imports: string[] = [];
        const exports: string[] = [];

        const lines = text.split('\n');
        
        for (const line of lines) {
            // Function definitions
            const funcMatch = line.match(/^(\s*)def\s+(\w+)\s*\(([^)]*)\)/);
            if (funcMatch) {
                functions.push({
                    name: funcMatch[2],
                    isAsync: line.includes('async '),
                    parameters: funcMatch[3].split(',').map(p => p.trim()).filter(p => p),
                    isExported: !funcMatch[2].startsWith('_'),
                    isPrivate: funcMatch[2].startsWith('_'),
                    isTestFunction: funcMatch[2].startsWith('test_') || funcMatch[2].includes('test'),
                    containsSecurityPatterns: false,
                    securityRelevantOperations: []
                });
            }

            // Import statements
            const importMatch = line.match(/^(?:from\s+(\w+)|import\s+(\w+))/);
            if (importMatch) {
                imports.push(importMatch[1] || importMatch[2]);
            }
        }

        return { functions, variables, imports, exports };
    }

    private extractFunctionContext(node: ts.FunctionDeclaration | ts.MethodDeclaration, sourceFile: ts.SourceFile): FunctionContext {
        const name = node.name?.getText(sourceFile) || 'anonymous';
        const isAsync = node.modifiers?.some(mod => mod.kind === ts.SyntaxKind.AsyncKeyword) || false;
        const parameters = node.parameters.map(param => param.name.getText(sourceFile));
        const isExported = node.modifiers?.some(mod => mod.kind === ts.SyntaxKind.ExportKeyword) || false;
        const isPrivate = node.modifiers?.some(mod => mod.kind === ts.SyntaxKind.PrivateKeyword) || false;

        return {
            name,
            isAsync,
            parameters,
            isExported,
            isPrivate,
            isTestFunction: /test|spec|describe|it/.test(name.toLowerCase()),
            containsSecurityPatterns: false,
            securityRelevantOperations: []
        };
    }

    private extractVariableContext(node: ts.VariableDeclaration, sourceFile: ts.SourceFile): VariableContext {
        const name = node.name.getText(sourceFile);
        const isConstant = node.parent && ts.isVariableDeclarationList(node.parent) && 
                          (node.parent.flags & ts.NodeFlags.Const) !== 0;

        return {
            name,
            isConstant,
            isSecuritySensitive: this.isSecuritySensitiveVariable(name),
            scope: 'function', // Simplified for now
            usagePattern: 'internal'
        };
    }

    private extractImportName(node: ts.ImportDeclaration): string {
        const moduleSpecifier = node.moduleSpecifier;
        if (ts.isStringLiteral(moduleSpecifier)) {
            return moduleSpecifier.text;
        }
        return '';
    }

    private extractExportName(node: ts.ExportDeclaration | ts.ExportAssignment): string {
        // Simplified export name extraction
        return 'export';
    }

    private isSecuritySensitiveVariable(name: string): boolean {
        const sensitivePatterns = [
            /password/i,
            /secret/i,
            /token/i,
            /key/i,
            /credential/i,
            /auth/i,
            /session/i
        ];

        return sensitivePatterns.some(pattern => pattern.test(name));
    }

    private isInTestContext(line: number, lines: string[], codeContext: CodeContext): boolean {
        if (codeContext.isTestFile) {
            return true;
        }

        // Check surrounding lines for test patterns
        const contextLines = lines.slice(Math.max(0, line - 5), Math.min(lines.length, line + 5));
        const testPatterns = [
            /describe\s*\(/,
            /it\s*\(/,
            /test\s*\(/,
            /expect\s*\(/,
            /jest\./,
            /sinon\./,
            /mock/i
        ];

        return contextLines.some(contextLine => 
            testPatterns.some(pattern => pattern.test(contextLine))
        );
    }

    private isInMockContext(line: number, lines: string[]): boolean {
        const contextLines = lines.slice(Math.max(0, line - 3), Math.min(lines.length, line + 3));
        const mockPatterns = [
            /mock/i,
            /stub/i,
            /fake/i,
            /jest\.fn/,
            /sinon\./,
            /\.spyOn/
        ];

        return contextLines.some(contextLine => 
            mockPatterns.some(pattern => pattern.test(contextLine))
        );
    }

    private isInCommentBlock(line: number, column: number, text: string): boolean {
        const lines = text.split('\n');
        const currentLine = lines[line];
        
        // Single line comment
        const beforeColumn = currentLine.substring(0, column);
        if (beforeColumn.includes('//') || beforeColumn.includes('#')) {
            return true;
        }

        // Multi-line comment block
        const textBeforePosition = lines.slice(0, line + 1).join('\n') + currentLine.substring(0, column);
        const lastCommentStart = Math.max(
            textBeforePosition.lastIndexOf('/*'),
            textBeforePosition.lastIndexOf('"""'),
            textBeforePosition.lastIndexOf("'''")
        );
        const lastCommentEnd = Math.max(
            textBeforePosition.lastIndexOf('*/'),
            textBeforePosition.lastIndexOf('"""', lastCommentStart - 1),
            textBeforePosition.lastIndexOf("'''", lastCommentStart - 1)
        );

        return lastCommentStart > lastCommentEnd;
    }

    private isInStringLiteral(line: number, column: number, lineText: string): boolean {
        const beforeColumn = lineText.substring(0, column);
        const singleQuotes = (beforeColumn.match(/'/g) || []).length;
        const doubleQuotes = (beforeColumn.match(/"/g) || []).length;
        const backticks = (beforeColumn.match(/`/g) || []).length;

        return (singleQuotes % 2 === 1) || (doubleQuotes % 2 === 1) || (backticks % 2 === 1);
    }

    private isInRegularExpression(line: number, column: number, lineText: string): boolean {
        const regexPatterns = [
            /\/.*\//g,
            /new\s+RegExp\s*\(/g,
            /re\.compile\s*\(/g
        ];

        return regexPatterns.some(pattern => {
            const matches = Array.from(lineText.matchAll(pattern));
            return matches.some(match => 
                column >= match.index! && column <= match.index! + match[0].length
            );
        });
    }

    private hasInputValidationNearby(line: number, lines: string[]): boolean {
        const contextLines = lines.slice(Math.max(0, line - 5), Math.min(lines.length, line + 5));
        const validationPatterns = [
            /validate/i,
            /sanitize/i,
            /escape/i,
            /filter/i,
            /typeof\s+.*===/,
            /instanceof/,
            /\.test\s*\(/,
            /isNaN\s*\(/,
            /parseInt\s*\(/,
            /parseFloat\s*\(/
        ];

        return contextLines.some(contextLine => 
            validationPatterns.some(pattern => pattern.test(contextLine))
        );
    }

    private hasOutputSanitizationNearby(line: number, lines: string[]): boolean {
        const contextLines = lines.slice(Math.max(0, line - 3), Math.min(lines.length, line + 3));
        const sanitizationPatterns = [
            /sanitize/i,
            /escape/i,
            /encode/i,
            /textContent/,
            /innerText/,
            /createElement/,
            /createTextNode/,
            /DOMPurify/,
            /xss/i
        ];

        return contextLines.some(contextLine => 
            sanitizationPatterns.some(pattern => pattern.test(contextLine))
        );
    }

    private usesSecurityLibrary(imports: string[], dependencies: string[]): boolean {
        const securityLibraries = [
            'helmet',
            'cors',
            'bcrypt',
            'bcryptjs',
            'crypto',
            'jsonwebtoken',
            'passport',
            'express-validator',
            'joi',
            'yup',
            'dompurify',
            'xss',
            'escape-html',
            'sanitize-html'
        ];

        const allImportsAndDeps = [...imports, ...dependencies];
        return securityLibraries.some(lib => 
            allImportsAndDeps.some(item => item.includes(lib))
        );
    }

    private analyzeDataFlow(line: number, lines: string[], codeContext: CodeContext): DataFlowContext {
        const contextLines = lines.slice(Math.max(0, line - 10), Math.min(lines.length, line + 10));
        const contextText = contextLines.join('\n');

        return {
            hasUserInput: this.hasUserInputPatterns(contextText),
            hasNetworkInput: this.hasNetworkInputPatterns(contextText),
            hasFileInput: this.hasFileInputPatterns(contextText),
            hasDataBaseOutput: this.hasDatabaseOutputPatterns(contextText),
            hasNetworkOutput: this.hasNetworkOutputPatterns(contextText),
            hasFileOutput: this.hasFileOutputPatterns(contextText),
            dataValidationMethods: this.extractValidationMethods(contextText),
            sanitizationMethods: this.extractSanitizationMethods(contextText)
        };
    }

    private hasUserInputPatterns(text: string): boolean {
        const patterns = [
            /req\.body/,
            /req\.query/,
            /req\.params/,
            /input\s*\(/,
            /readline/,
            /prompt/,
            /process\.argv/,
            /document\.getElementById/,
            /document\.querySelector/,
            /window\.location/,
            /location\.search/
        ];

        return patterns.some(pattern => pattern.test(text));
    }

    private hasNetworkInputPatterns(text: string): boolean {
        const patterns = [
            /fetch\s*\(/,
            /axios\./,
            /http\./,
            /request\s*\(/,
            /socket\./,
            /WebSocket/,
            /XMLHttpRequest/
        ];

        return patterns.some(pattern => pattern.test(text));
    }

    private hasFileInputPatterns(text: string): boolean {
        const patterns = [
            /fs\.read/,
            /readFile/,
            /open\s*\(/,
            /file\.read/,
            /\.read\s*\(/
        ];

        return patterns.some(pattern => pattern.test(text));
    }

    private hasDatabaseOutputPatterns(text: string): boolean {
        const patterns = [
            /\.query\s*\(/,
            /\.execute\s*\(/,
            /INSERT\s+INTO/i,
            /UPDATE\s+.*SET/i,
            /DELETE\s+FROM/i,
            /SELECT\s+.*FROM/i
        ];

        return patterns.some(pattern => pattern.test(text));
    }

    private hasNetworkOutputPatterns(text: string): boolean {
        const patterns = [
            /res\.send/,
            /res\.json/,
            /response\./,
            /socket\.emit/,
            /fetch\s*\(/,
            /axios\./
        ];

        return patterns.some(pattern => pattern.test(text));
    }

    private hasFileOutputPatterns(text: string): boolean {
        const patterns = [
            /fs\.write/,
            /writeFile/,
            /\.write\s*\(/,
            /file\.write/
        ];

        return patterns.some(pattern => pattern.test(text));
    }

    private extractValidationMethods(text: string): string[] {
        const methods: string[] = [];
        const patterns = [
            /(\w+\.validate\w*)/g,
            /(\w+\.check\w*)/g,
            /(\w+\.sanitize\w*)/g
        ];

        patterns.forEach(pattern => {
            const matches = text.match(pattern);
            if (matches) {
                methods.push(...matches);
            }
        });

        return methods;
    }

    private extractSanitizationMethods(text: string): string[] {
        const methods: string[] = [];
        const patterns = [
            /(\w+\.escape\w*)/g,
            /(\w+\.sanitize\w*)/g,
            /(\w+\.clean\w*)/g
        ];

        patterns.forEach(pattern => {
            const matches = text.match(pattern);
            if (matches) {
                methods.push(...matches);
            }
        });

        return methods;
    }

    private isSecurityTestPattern(issue: any): boolean {
        const message = issue.message.toLowerCase();
        const securityTestPatterns = [
            /penetration.*test/,
            /security.*test/,
            /vulnerability.*test/,
            /injection.*test/,
            /xss.*test/
        ];

        return securityTestPatterns.some(pattern => pattern.test(message));
    }

    private isConfigurationValue(issue: any): boolean {
        const configPatterns = [
            /default.*value/i,
            /configuration/i,
            /setting/i,
            /option/i,
            /parameter/i
        ];

        return configPatterns.some(pattern => pattern.test(issue.message));
    }

    private hasProperSecurityMeasures(issue: any, securityContext: SecurityContext): boolean {
        // If we detect validation and sanitization around the issue, it's likely a false positive
        return securityContext.hasInputValidation && 
               securityContext.hasOutputSanitization && 
               securityContext.usesSecurityLibrary;
    }

    private isDevelopmentCode(issue: any, codeContext: CodeContext): boolean {
        const message = issue.message.toLowerCase();
        const devPatterns = [
            /console\.log/,
            /debug/,
            /temp/,
            /todo/,
            /fixme/,
            /hack/,
            /temporary/
        ];

        return devPatterns.some(pattern => pattern.test(message)) && 
               (codeContext.fileType === 'test' || !codeContext.fileType);
    }
} 