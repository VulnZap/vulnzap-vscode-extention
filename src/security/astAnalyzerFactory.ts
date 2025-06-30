import { ASTSecurityAnalyzer } from './astAnalyzer';

/**
 * JavaScript/TypeScript specific AST analyzer
 */
export class JavaScriptASTAnalyzer extends ASTSecurityAnalyzer {
  constructor() {
    super('javascript');
  }

  /**
   * Detect SQL injection patterns specific to JavaScript
   */
  protected detectSQLInjection(path: any): boolean {
    // Check for template literals with user input
    if (path.node.type === 'TemplateLiteral') {
      const expressions = path.node.expressions;
      return expressions.some((expr: any) => this.tracesToUserInput(expr));
    }
    
    // Check for string concatenation with user input
    if (path.node.type === 'BinaryExpression' && path.node.operator === '+') {
      return this.tracesToUserInput(path.node.left) || this.tracesToUserInput(path.node.right);
    }
    
    return false;
  }

  /**
   * Trace if expression leads to user input
   */
  protected tracesToUserInput(node: any, visited = new Set()): boolean {
    if (visited.has(node)) return false;
    visited.add(node);

    // Direct user input patterns
    if (node.type === 'MemberExpression') {
      const object = node.object;
      const property = node.property;
      
      if (object.name === 'req' && 
          ['query', 'body', 'params', 'headers'].includes(property.name)) {
        return true;
      }
    }

    // Follow variable assignments
    if (node.type === 'Identifier') {
      // This would require scope analysis - simplified for now
      return false;
    }

    return false;
  }
}

/**
 * TypeScript specific AST analyzer
 */
export class TypeScriptASTAnalyzer extends JavaScriptASTAnalyzer {
  constructor() {
    super();
    this.language = 'typescript';
  }
}

/**
 * Python AST analyzer (placeholder for future implementation)
 */
export class PythonASTAnalyzer extends ASTSecurityAnalyzer {
  constructor() {
    super('python');
  }

  // Python AST parsing would require a different parser
  // This is a placeholder for future implementation
  protected parseCode(code: string): any {
    console.warn('Python AST analysis not yet implemented');
    return null;
  }
}

/**
 * Java AST analyzer (placeholder for future implementation)
 */
export class JavaASTAnalyzer extends ASTSecurityAnalyzer {
  constructor() {
    super('java');
  }

  // Java AST parsing would require a different parser
  // This is a placeholder for future implementation
  protected parseCode(code: string): any {
    console.warn('Java AST analysis not yet implemented');
    return null;
  }
}

/**
 * Generic AST analyzer for unsupported languages
 */
export class GenericASTAnalyzer extends ASTSecurityAnalyzer {
  constructor(language: string) {
    super(language);
  }

  // Fallback to basic pattern matching for unsupported languages
  protected parseCode(code: string): any {
    console.warn(`AST analysis not supported for ${this.language}`);
    return null;
  }
}

/**
 * Factory class for creating language-specific AST analyzers
 */
export class ASTAnalyzerFactory {
  /**
   * Create appropriate AST analyzer based on language
   */
  static createAnalyzer(language: string): ASTSecurityAnalyzer {
    switch (language.toLowerCase()) {
      case 'javascript':
        return new JavaScriptASTAnalyzer();
      case 'typescript':
        return new TypeScriptASTAnalyzer();
      case 'python':
        return new PythonASTAnalyzer();
      case 'java':
        return new JavaASTAnalyzer();
      default:
        return new GenericASTAnalyzer(language);
    }
  }

  /**
   * Check if AST analysis is supported for a language
   */
  static isSupported(language: string): boolean {
    return ['javascript', 'typescript'].includes(language.toLowerCase());
  }

  /**
   * Get list of supported languages
   */
  static getSupportedLanguages(): string[] {
    return ['javascript', 'typescript'];
  }
} 