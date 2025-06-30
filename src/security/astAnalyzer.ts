import { parse } from '@babel/parser';
import traverse, { NodePath } from '@babel/traverse';
import * as t from '@babel/types';
import * as vscode from 'vscode';

/**
 * Represents a security-relevant AST node with precise positioning
 */
export interface SecurityNode {
  id: number;
  type: string;
  riskType: string;
  start: number;
  end: number;
  line: number;
  column: number;
  endLine: number;
  endColumn: number;
  text: string;
  parentType?: string;
  functionContext?: string;
  dataFlow?: string[];
}

/**
 * Precise vulnerability location with exact character positions
 */
export interface PreciseVulnerability {
  astNodeId: number;
  vulnerableSubstring: string;
  startOffset: number;
  endOffset: number;
  absoluteStart: number;
  absoluteEnd: number;
  line: number;
  column: number;
  endLine: number;
  endColumn: number;
  vulnerability: string;
  severity: 'high' | 'medium' | 'low';
  confidence: number;
  explanation: string;
  context: {
    nodeType: string;
    parentContext: string;
    dataFlow?: string[];
  };
}

/**
 * AI response format for AST-guided analysis
 */
export interface ASTGuidedAnalysisResponse {
  vulnerabilities: PreciseVulnerability[];
  summary: string;
  overallRisk: 'low' | 'medium' | 'high' | 'critical';
  astStats: {
    totalNodes: number;
    securityRelevantNodes: number;
    preciselyLocated: number;
  };
}

/**
 * AST-powered security analyzer for precise vulnerability detection
 */
export class ASTSecurityAnalyzer {
  protected language: string;
  private vulnerableNodes: SecurityNode[] = [];
  private nodeIndex = new Map<number, SecurityNode>();
  private code: string = '';

  constructor(language: string) {
    this.language = language;
  }

  /**
   * Main analysis method that combines AST parsing with AI analysis
   */
  async analyzeCode(code: string): Promise<ASTGuidedAnalysisResponse> {
    this.code = code;
    console.log('Starting AST analysis for JavaScript code');
    
    // Parse the code into an AST
    const ast = this.parseCode(code);
    if (!ast) {
      console.warn('AST parsing failed, returning fallback response');
      return this.createFallbackResponse();
    }

    console.log('AST parsing successful, extracting security nodes');
    
    // Extract security-relevant nodes
    const securityNodes = this.extractSecurityRelevantNodes(ast);
    
    console.log(`Found ${securityNodes.length} security-relevant AST nodes`);
    
    // If no security nodes found, return early
    if (securityNodes.length === 0) {
      return {
        vulnerabilities: [],
        summary: 'No security-relevant code patterns found in AST',
        overallRisk: 'low',
        astStats: {
          totalNodes: 0,
          securityRelevantNodes: 0,
          preciselyLocated: 0
        }
      };
    }

    try {
      // Build enhanced prompt with AST context
      const prompt = this.buildASTEnhancedPrompt(code, securityNodes);
      
      // Get AI analysis
      const aiResponse = await this.getAIAnalysis(prompt);
      
      // Convert to standardized response
      return this.convertToASTResponse(aiResponse, securityNodes);
    } catch (error) {
      console.error('AST-guided AI analysis failed:', error);
      return this.createFallbackResponse();
    }
  }

  /**
   * Parse code into Abstract Syntax Tree
   */
  protected parseCode(code: string): t.Node | null {
    try {
      // First try as a module
      const moduleOptions = this.getParserOptions();
      return parse(code, moduleOptions);
    } catch (moduleError: any) {
      console.log('Module parsing failed, trying as script:', moduleError?.message || moduleError);
      
      try {
        // Try as a script instead of module
        const scriptOptions = {
          ...this.getParserOptions(),
          sourceType: 'script' as const
        };
        return parse(code, scriptOptions);
      } catch (scriptError: any) {
        console.log('Script parsing failed, trying with relaxed options:', scriptError?.message || scriptError);
        
        try {
          // Try with more relaxed options
          const relaxedOptions = {
            sourceType: 'unambiguous' as const,
            allowImportExportEverywhere: true,
            allowReturnOutsideFunction: true,
            allowHashBang: true,
            allowAwaitOutsideFunction: true,
            strictMode: false,
            ranges: true,
            locations: true,
            plugins: [
              'jsx' as any,
              'objectRestSpread',
              'functionBind',
              'dynamicImport'
            ]
          };
          
          return parse(code, relaxedOptions);
        } catch (relaxedError: any) {
          console.error('All AST parsing attempts failed:');
          console.error('Module error:', moduleError?.message || moduleError);
          console.error('Script error:', scriptError?.message || scriptError);
          console.error('Relaxed error:', relaxedError?.message || relaxedError);
          console.error('Code that failed to parse:', code.substring(0, 200) + '...');
          return null;
        }
      }
    }
  }

  /**
   * Get parser options based on language
   */
  private getParserOptions(): any {
    const baseOptions = {
      sourceType: 'module' as const,
      allowImportExportEverywhere: true,
      allowReturnOutsideFunction: true,
      ranges: true,
      locations: true,
    };

    if (this.language === 'typescript') {
      return {
        ...baseOptions,
        plugins: [
          ['typescript', { dts: false }],
          'jsx',
          'decorators-legacy',
          'classProperties',
          'objectRestSpread',
          'asyncGenerators',
          'functionBind',
          'exportDefaultFrom',
          'exportNamespaceFrom',
          'dynamicImport',
          'nullishCoalescingOperator',
          'optionalChaining'
        ]
      };
    }

    return {
      ...baseOptions,
      plugins: [
        'jsx',
        'decorators-legacy',
        'classProperties',
        'objectRestSpread',
        'asyncGenerators',
        'functionBind',
        'exportDefaultFrom',
        'exportNamespaceFrom',
        'dynamicImport',
        'nullishCoalescingOperator',
        'optionalChaining'
      ]
    };
  }

  /**
   * Extract security-relevant nodes from AST
   */
  private extractSecurityRelevantNodes(ast: t.Node): SecurityNode[] {
    const securityNodes: SecurityNode[] = [];
    let nodeId = 0;

    traverse(ast, {
             // SQL injection patterns
       TemplateLiteral: (path: NodePath<t.TemplateLiteral>) => {
         if (this.hasUserInput(path)) {
           securityNodes.push(this.createSecurityNode(path, nodeId++, 'sql_injection_risk'));
         }
       },

       // XSS patterns
       AssignmentExpression: (path: NodePath<t.AssignmentExpression>) => {
         if (this.isInnerHTMLAssignment(path)) {
           securityNodes.push(this.createSecurityNode(path, nodeId++, 'xss_risk'));
         }
       },

             // Code injection patterns and file operations
       CallExpression: (path: NodePath<t.CallExpression>) => {
         if (this.isDangerousFunction(path.node.callee)) {
           securityNodes.push(this.createSecurityNode(path, nodeId++, 'code_injection_risk'));
         } else if (this.isFileOperation(path)) {
           securityNodes.push(this.createSecurityNode(path, nodeId++, 'file_operation_risk'));
         }
       },

       // Hardcoded secrets
       StringLiteral: (path: NodePath<t.StringLiteral>) => {
         if (this.looksLikeSecret(path.node.value)) {
           securityNodes.push(this.createSecurityNode(path, nodeId++, 'hardcoded_secret'));
         }
       },

       // Weak crypto
       MemberExpression: (path: NodePath<t.MemberExpression>) => {
         if (this.isWeakCryptoFunction(path)) {
           securityNodes.push(this.createSecurityNode(path, nodeId++, 'weak_crypto'));
         }
       }
    });

    this.vulnerableNodes = securityNodes;
    securityNodes.forEach(node => this.nodeIndex.set(node.id, node));

    return securityNodes;
  }

  /**
   * Create a security node from AST path
   */
  private createSecurityNode(path: any, id: number, riskType: string): SecurityNode {
    const node = path.node;
    const loc = node.loc;

    return {
      id,
      type: node.type,
      riskType,
      start: node.start || 0,
      end: node.end || 0,
      line: loc?.start.line || 1,
      column: loc?.start.column || 0,
      endLine: loc?.end.line || 1,
      endColumn: loc?.end.column || 0,
      text: this.getNodeText(path),
      parentType: path.parent?.type,
      functionContext: this.getFunctionContext(path),
      dataFlow: this.analyzeDataFlow(path)
    };
  }

  /**
   * Get text content of AST node
   */
  private getNodeText(path: any): string {
    const node = path.node;
    if (node.start !== undefined && node.end !== undefined) {
      return this.code.substring(node.start, node.end);
    }
    return '';
  }

  /**
   * Get function context for a node
   */
  private getFunctionContext(path: any): string {
    let current = path;
    while (current) {
      if (current.node.type === 'FunctionDeclaration' || 
          current.node.type === 'FunctionExpression' ||
          current.node.type === 'ArrowFunctionExpression') {
        const funcNode = current.node;
        if (funcNode.type === 'FunctionDeclaration' && funcNode.id) {
          return funcNode.id.name;
        }
        return 'anonymous function';
      }
      current = current.parent;
    }
    return 'global scope';
  }

  /**
   * Analyze data flow for a node
   */
  private analyzeDataFlow(path: any): string[] {
    const dataFlow: string[] = [];
    
    // Simple data flow analysis - trace variable usage
    if (path.node.type === 'Identifier') {
      const binding = path.scope.getBinding(path.node.name);
      if (binding) {
        dataFlow.push(path.node.name);
      }
    }

    return dataFlow;
  }

  /**
   * Check if node contains user input patterns
   */
  private hasUserInput(path: any): boolean {
    const userInputPatterns = ['req.query', 'req.body', 'req.params', 'process.argv'];
    const nodeText = this.getNodeText(path);
    return userInputPatterns.some(pattern => nodeText.includes(pattern));
  }

  /**
   * Check if assignment is to innerHTML
   */
  private isInnerHTMLAssignment(path: any): boolean {
    const left = path.node.left;
    return left.type === 'MemberExpression' && 
           left.property && left.property.name === 'innerHTML';
  }

  /**
   * Check if function call is dangerous
   */
  private isDangerousFunction(callee: any): boolean {
    const dangerous = ['eval', 'Function', 'setTimeout', 'setInterval', 'execSync', 'exec'];
    if (callee.type === 'Identifier') {
      return dangerous.includes(callee.name);
    }
    if (callee.type === 'MemberExpression' && callee.property) {
      return dangerous.includes(callee.property.name);
    }
    return false;
  }

  /**
   * Check if string looks like a secret
   */
  private looksLikeSecret(value: string): boolean {
    if (typeof value !== 'string' || value.length < 10) return false;

    // API key patterns
    if (/^[a-zA-Z0-9_-]{20,}$/.test(value) && 
        !/^[0-9]+$/.test(value) && 
        !/^[a-zA-Z]+$/.test(value)) {
      return true;
    }

    // JWT tokens
    if (/^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*$/.test(value)) {
      return true;
    }

    // Common secret patterns
    const secretPatterns = [
      /^sk_[a-zA-Z0-9]{24,}$/, // Stripe keys
      /^pk_[a-zA-Z0-9]{24,}$/, // Stripe public keys
      /^rk_[a-zA-Z0-9]{24,}$/, // Stripe restricted keys
      /^AKIA[0-9A-Z]{16}$/, // AWS access keys
      /^ghp_[a-zA-Z0-9]{36}$/, // GitHub personal access tokens
      /^gho_[a-zA-Z0-9]{36}$/, // GitHub OAuth tokens
    ];

    return secretPatterns.some(pattern => pattern.test(value));
  }

  /**
   * Check if member expression is weak crypto
   */
  private isWeakCryptoFunction(path: any): boolean {
    const weakCrypto = ['md5', 'sha1', 'des', 'rc4'];
    const nodeText = this.getNodeText(path).toLowerCase();
    return weakCrypto.some(algo => nodeText.includes(algo));
  }

  /**
   * Check if call is a file operation
   */
  private isFileOperation(path: any): boolean {
    const fileOps = ['readFile', 'writeFile', 'unlinkSync', 'rmSync', 'open', 'createReadStream'];
    if (path.node.callee.type === 'MemberExpression' && path.node.callee.property) {
      return fileOps.includes(path.node.callee.property.name);
    }
    if (path.node.callee.type === 'Identifier') {
      return fileOps.includes(path.node.callee.name);
    }
    return false;
  }

  /**
   * Build AST-enhanced prompt for AI analysis
   */
  private buildASTEnhancedPrompt(code: string, securityNodes: SecurityNode[]): string {
    return `Analyze this ${this.language} code for security vulnerabilities.

For each vulnerability found, provide:
1. The EXACT syntax element that's vulnerable (function call, variable assignment, etc.)
2. The precise start and end positions within that element
3. WHY that specific part is vulnerable

Code with AST guidance:
${code}

AST Reference (use for precise targeting):
${securityNodes.map((node, i) => 
  `Node ${node.id}: ${node.type} at ${node.start}-${node.end} "${node.text.substring(0, 50)}${node.text.length > 50 ? '...' : ''}" (Risk: ${node.riskType})`
).join('\n')}

Response format:
{
  "vulnerabilities": [
    {
      "astNodeId": 15,
      "vulnerableSubstring": "\${user}",
      "startOffset": 23,
      "endOffset": 30,
      "absoluteStart": 456,
      "absoluteEnd": 463,
      "line": 12,
      "column": 23,
      "endLine": 12,
      "endColumn": 30,
      "vulnerability": "SQL injection in template literal",
      "severity": "high",
      "confidence": 95,
      "explanation": "User input directly interpolated into SQL query without sanitization",
      "context": {
        "nodeType": "TemplateLiteral",
        "parentContext": "Variable assignment",
        "dataFlow": ["req.query.id", "template literal"]
      }
    }
  ]
}`;
  }

  /**
   * Get AI analysis using the enhanced prompt
   */
  private async getAIAnalysis(prompt: string): Promise<any> {
    // Import here to avoid circular dependency
    const vscode = require('vscode');
    const axios = require('axios');
    
    const config = vscode.workspace.getConfiguration("vulnzap");
    const apiKey = config.get("vulnzapApiKey", "").trim();
    const apiUrl = config.get("vulnzapApiUrl", "").trim();
    
    if (!apiKey || !apiUrl) {
      console.warn('VulnZap API not configured for AST analysis');
      return { vulnerabilities: [] };
    }

    try {
      const response = await axios.post(
        `${apiUrl}/api/v1/vulnzap/code-scan`,
        {
          code: this.code,
          language: this.language,
          prompt,
          options: {
            astGuided: true,
            precisionMode: true,
            includeLineNumbers: true
          }
        },
        {
          headers: {
            "Authorization": `Bearer ${apiKey}`,
            "Content-Type": "application/json",
            "User-Agent": "VulnZap-AST-Analyzer"
          },
          timeout: 45000
        }
      );

      return response.data;
    } catch (error) {
      console.error('AST-guided analysis API call failed:', error);
      return { vulnerabilities: [] };
    }
  }

  /**
   * Convert AI response to AST-guided analysis response
   */
  private convertToASTResponse(aiResponse: any, securityNodes: SecurityNode[]): ASTGuidedAnalysisResponse {
    const vulnerabilities = aiResponse.vulnerabilities || [];
    
    return {
      vulnerabilities,
      summary: `Found ${vulnerabilities.length} precise vulnerabilities`,
      overallRisk: this.calculateOverallRisk(vulnerabilities),
      astStats: {
        totalNodes: securityNodes.length,
        securityRelevantNodes: securityNodes.length,
        preciselyLocated: vulnerabilities.filter((v: any) => v.confidence > 85).length
      }
    };
  }

  /**
   * Calculate overall risk based on vulnerabilities
   */
  private calculateOverallRisk(vulnerabilities: PreciseVulnerability[]): 'low' | 'medium' | 'high' | 'critical' {
    if (vulnerabilities.length === 0) return 'low';
    
    const highSeverityCount = vulnerabilities.filter(v => v.severity === 'high').length;
    const mediumSeverityCount = vulnerabilities.filter(v => v.severity === 'medium').length;
    
    if (highSeverityCount >= 3) return 'critical';
    if (highSeverityCount >= 1) return 'high';
    if (mediumSeverityCount >= 3) return 'high';
    if (mediumSeverityCount >= 1) return 'medium';
    
    return 'low';
  }

  /**
   * Create fallback response when AST parsing fails
   */
  private createFallbackResponse(): ASTGuidedAnalysisResponse {
    return {
      vulnerabilities: [],
      summary: 'AST parsing failed, falling back to basic analysis',
      overallRisk: 'low',
      astStats: {
        totalNodes: 0,
        securityRelevantNodes: 0,
        preciselyLocated: 0
      }
    };
  }

  /**
   * Convert AST vulnerabilities to VS Code ranges
   */
  convertToVSCodeRanges(vulnerabilities: PreciseVulnerability[]): Array<{
    line: number;
    column: number;
    endLine: number;
    endColumn: number;
    message: string;
    severity: string;
    code: string;
    suggestion?: string;
    confidence: number;
    precise: boolean;
    astNode?: any;
  }> {
    return vulnerabilities.map(vuln => {
      const node = this.nodeIndex.get(vuln.astNodeId);
      
      return {
        line: vuln.line - 1, // VS Code uses 0-based line numbers
        column: vuln.column,
        endLine: vuln.endLine - 1,
        endColumn: vuln.endColumn,
        message: vuln.vulnerability,
        severity: vuln.severity,
        code: this.generateVulnCode(vuln),
        suggestion: this.generateSuggestion(vuln, node),
        confidence: vuln.confidence,
        precise: true,
        astNode: {
          type: node?.type,
          riskType: node?.riskType,
          context: vuln.context
        }
      };
    });
  }

  /**
   * Generate vulnerability code
   */
  private generateVulnCode(vuln: PreciseVulnerability): string {
    const riskMap: { [key: string]: string } = {
      'sql_injection_risk': 'SQL_INJECTION',
      'xss_risk': 'XSS',
      'code_injection_risk': 'CODE_INJECTION',
      'hardcoded_secret': 'HARDCODED_SECRET',
      'weak_crypto': 'WEAK_CRYPTO',
      'file_operation_risk': 'FILE_OPERATION'
    };
    
    const node = this.nodeIndex.get(vuln.astNodeId);
    return riskMap[node?.riskType || ''] || 'SECURITY_RISK';
  }

  /**
   * Generate fix suggestion
   */
  private generateSuggestion(vuln: PreciseVulnerability, node?: SecurityNode): string {
    if (!node) return 'Review this code for security issues';

    const suggestions: { [key: string]: string } = {
      'sql_injection_risk': 'Use parameterized queries or prepared statements',
      'xss_risk': 'Sanitize user input before inserting into DOM',
      'code_injection_risk': 'Avoid dynamic code execution, use safer alternatives',
      'hardcoded_secret': 'Move secrets to environment variables or secure storage',
      'weak_crypto': 'Use stronger cryptographic algorithms like SHA-256 or AES',
      'file_operation_risk': 'Validate file paths and implement proper access controls'
    };

    return suggestions[node.riskType] || 'Review this code for security issues';
  }
}