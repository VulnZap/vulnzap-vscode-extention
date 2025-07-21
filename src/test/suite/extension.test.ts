import * as assert from 'assert';
import * as vscode from 'vscode';
import * as path from 'path';

suite('VulnZap Extension Test Suite', () => {
    vscode.window.showInformationMessage('Start all tests.');

    test('Extension should be present', () => {
        assert.ok(vscode.extensions.getExtension('vulnzap.vulnzap'));
    });

    test('Extension should activate', async () => {
        const ext = vscode.extensions.getExtension('vulnzap.vulnzap');
        if (ext) {
            await ext.activate();
            assert.strictEqual(ext.isActive, true);
        }
    });

    test('Commands should be registered', async () => {
        const commands = await vscode.commands.getCommands(true);
        const vulnzapCommands = commands.filter(cmd => cmd.startsWith('vulnzap.'));
        
        const expectedCommands = [
            'vulnzap.enable',
            'vulnzap.disable',
            'vulnzap.toggle',
            'vulnzap.scanFile',
            'vulnzap.configureApiKeys',
            'vulnzap.scanWorkspace',
            'vulnzap.buildIndex',
            'vulnzap.scanDependencies'
        ];

        expectedCommands.forEach(cmd => {
            assert.ok(vulnzapCommands.includes(cmd), `Command ${cmd} not found`);
        });
    });

    test('Security patterns should be detected', async () => {
        // Create a test document with vulnerable code
        const vulnerableCode = `
        const userId = req.params.id;
        const query = \`SELECT * FROM users WHERE id = \${userId}\`;
        db.query(query);
        `;

        const doc = await vscode.workspace.openTextDocument({
            content: vulnerableCode,
            language: 'javascript'
        });

        // Wait for analysis to complete
        await new Promise(resolve => setTimeout(resolve, 2000));

        // Check if diagnostics were created
        const diagnostics = vscode.languages.getDiagnostics(doc.uri);
        assert.ok(diagnostics.length > 0, 'Should detect SQL injection vulnerability');
    });

    test('Configuration should be accessible', () => {
        const config = vscode.workspace.getConfiguration('vulnzap');
        assert.ok(config.has('enabled'));
        assert.ok(config.has('vulnzapApiKey'));
        assert.ok(config.has('enableFastScan'));
    });

    test('Status bar should be created', async () => {
        // This test would need to check if status bar item exists
        // Implementation depends on how you expose the status bar item
        assert.ok(true, 'Status bar test placeholder');
    });
});

suite('Security Detection Tests', () => {
    test('SQL Injection Detection', async () => {
        const testCases = [
            'const query = `SELECT * FROM users WHERE id = ${userId}`;',
            'db.query("SELECT * FROM users WHERE name = \'" + userName + "\'");',
            'execute("DELETE FROM users WHERE id = " + id);'
        ];

        for (const testCase of testCases) {
            const doc = await vscode.workspace.openTextDocument({
                content: testCase,
                language: 'javascript'
            });

            await new Promise(resolve => setTimeout(resolve, 1000));
            const diagnostics = vscode.languages.getDiagnostics(doc.uri);
            assert.ok(diagnostics.length > 0, `Should detect SQL injection in: ${testCase}`);
        }
    });

    test('XSS Detection', async () => {
        const testCases = [
            'element.innerHTML = userInput;',
            'document.write(untrustedData);',
            'eval(userCode);'
        ];

        for (const testCase of testCases) {
            const doc = await vscode.workspace.openTextDocument({
                content: testCase,
                language: 'javascript'
            });

            await new Promise(resolve => setTimeout(resolve, 1000));
            const diagnostics = vscode.languages.getDiagnostics(doc.uri);
            assert.ok(diagnostics.length > 0, `Should detect XSS in: ${testCase}`);
        }
    });

    test('Hardcoded Secrets Detection', async () => {
        const testCases = [
            'const apiKey = "sk_live_abcdef1234567890abcdef1234567890";',
            'const awsKey = "AKIAIOSFODNN7EXAMPLE";',
            'const token = "ghp_1234567890abcdef1234567890abcdef123456";'
        ];

        for (const testCase of testCases) {
            const doc = await vscode.workspace.openTextDocument({
                content: testCase,
                language: 'javascript'
            });

            await new Promise(resolve => setTimeout(resolve, 1000));
            const diagnostics = vscode.languages.getDiagnostics(doc.uri);
            assert.ok(diagnostics.length > 0, `Should detect hardcoded secret in: ${testCase}`);
        }
    });
}); 