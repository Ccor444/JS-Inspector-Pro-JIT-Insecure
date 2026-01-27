// scanner-functions.js
// Autor: Cleiton & ChatGPT — Modo Insano Dev
// Scanner avançado para localizar TODAS as funções possíveis dentro de um arquivo JS
// Versão Elite Security

export function scanFunctions(source) {
    const results = [];
    const lines = source.split(/\r?\n/);

    // =============== REGEX AVANÇADAS ===============
    const re_named_function = /^\s*(async\s+)?function\s+([A-Za-z0-9_$]+)\s*\(/;
    const re_var_function = /^\s*(const|let|var)\s+([A-Za-z0-9_$]+)\s*=\s*(async\s+)?function\s*\(/;
    const re_arrow_function = /^\s*(const|let|var)\s+([A-Za-z0-9_$]+)\s*=\s*(async\s+)?\(/;
    const re_object_function = /^\s*([A-Za-z0-9_$]+)\s*:\s*(async\s+)?function\s*\(/;
    const re_class_method = /^\s*(async\s+)?([A-Za-z0-9_$]+)\s*\((.*?)\)\s*\{/;

    // =============== LOOP DE LEITURA ===============
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        let match;

        // function foo()
        if ((match = line.match(re_named_function))) {
            const security = analyzeFunctionSecurity(line, match[2]);
            results.push({
                type: "function-declaration",
                name: match[2],
                line: i + 1,
                async: !!match[1],
                security: security
            });
            continue;
        }

        // const foo = function()
        if ((match = line.match(re_var_function))) {
            const security = analyzeFunctionSecurity(line, match[2]);
            results.push({
                type: "var-function",
                name: match[2],
                line: i + 1,
                async: !!match[3],
                security: security
            });
            continue;
        }

        // const foo = () =>
        if ((match = line.match(re_arrow_function))) {
            const security = analyzeFunctionSecurity(line, match[2]);
            results.push({
                type: "arrow-function",
                name: match[2],
                line: i + 1,
                async: !!match[3],
                security: security
            });
            continue;
        }

        // foo: function()
        if ((match = line.match(re_object_function))) {
            const security = analyzeFunctionSecurity(line, match[1]);
            results.push({
                type: "object-function",
                name: match[1],
                line: i + 1,
                async: !!match[2],
                security: security
            });
            continue;
        }

        // método de classe
        if ((match = line.match(re_class_method))) {
            // Não capturar palavras-chave especiais (constructor)
            if (match[2] !== "constructor") {
                const security = analyzeFunctionSecurity(line, match[2]);
                results.push({
                    type: "class-method",
                    name: match[2],
                    line: i + 1,
                    async: !!match[1],
                    security: security
                });
            }
            continue;
        }
    }

    // Modo avançado: remover duplicados por segurança
    const unique = {};
    const final = [];

    for (const f of results) {
        const key = f.name + "_" + f.line;
        if (!unique[key]) {
            unique[key] = true;
            final.push(f);
        }
    }

    return final;
}

// Nova função: Análise de segurança de funções
function analyzeFunctionSecurity(line, functionName) {
    const dangerousPatterns = [
        { pattern: /eval\s*\(/, severity: 'CRITICAL', description: 'Usa eval()' },
        { pattern: /new\s+Function/, severity: 'HIGH', description: 'Usa Function constructor' },
        { pattern: /\.innerHTML\s*=/, severity: 'HIGH', description: 'Atribui innerHTML' },
        { pattern: /\.outerHTML\s*=/, severity: 'HIGH', description: 'Atribui outerHTML' },
        { pattern: /document\.write/, severity: 'MEDIUM', description: 'Usa document.write()' },
        { pattern: /setTimeout\s*\([^,)]*\)/, severity: 'MEDIUM', description: 'setTimeout dinâmico' },
        { pattern: /setInterval\s*\([^,)]*\)/, severity: 'MEDIUM', description: 'setInterval dinâmico' },
        { pattern: /XMLHttpRequest/, severity: 'MEDIUM', description: 'Usa XMLHttpRequest' },
        { pattern: /fetch\s*\(/, severity: 'MEDIUM', description: 'Usa fetch()' },
        { pattern: /localStorage/, severity: 'LOW', description: 'Acessa localStorage' },
        { pattern: /sessionStorage/, severity: 'LOW', description: 'Acessa sessionStorage' },
        { pattern: /cookie/, severity: 'LOW', description: 'Manipula cookies' }
    ];
    
    const security = {
        isDangerous: false,
        dangerousPatterns: [],
        severity: 'LOW',
        suspicious: false
    };
    
    // Verificar padrões perigosos
    dangerousPatterns.forEach(pattern => {
        if (pattern.pattern.test(line)) {
            security.isDangerous = true;
            security.dangerousPatterns.push({
                type: pattern.description,
                severity: pattern.severity
            });
            
            // Atualizar severidade máxima
            if (pattern.severity === 'CRITICAL') security.severity = 'CRITICAL';
            else if (pattern.severity === 'HIGH' && security.severity !== 'CRITICAL') security.severity = 'HIGH';
            else if (pattern.severity === 'MEDIUM' && security.severity === 'LOW') security.severity = 'MEDIUM';
        }
    });
    
    // Verificar nomes de funções suspeitas
    const suspiciousNames = [
        'eval', 'execute', 'run', 'inject', 'parse', 'load', 'save',
        'delete', 'remove', 'update', 'create', 'destroy', 'init',
        'start', 'stop', 'config', 'settings', 'admin', 'root',
        'sudo', 'shell', 'command', 'query', 'sql', 'db'
    ];
    
    if (suspiciousNames.includes(functionName.toLowerCase())) {
        security.suspicious = true;
        security.suspiciousName = functionName;
    }
    
    return security;
}

// =============== DEBUG DIRETO NO CONSOLE ===============
export function scanFunctionsDebug(source) {
    console.log("=== SCANNER FUNCTIONS ===");
    const res = scanFunctions(source);
    res.forEach(fn => {
        const securityInfo = fn.security.isDangerous ? 
            ` ⚠️ ${fn.security.severity}: ${fn.security.dangerousPatterns.map(p => p.type).join(', ')}` : 
            '';
        console.log(`[${fn.type}] ${fn.name} (linha ${fn.line}) ${fn.async ? "async" : ""}${securityInfo}`);
    });
    console.log("=========================");
    return res;
}

// Nova função: Análise de segurança geral das funções
export function analyzeFunctionsSecurity(functions) {
    const securityReport = {
        totalFunctions: functions.length,
        dangerousFunctions: 0,
        criticalFunctions: 0,
        highRiskFunctions: 0,
        mediumRiskFunctions: 0,
        suspiciousFunctions: 0,
        securityScore: 100,
        recommendations: []
    };
    
    functions.forEach(fn => {
        if (fn.security.isDangerous) {
            securityReport.dangerousFunctions++;
            
            if (fn.security.severity === 'CRITICAL') securityReport.criticalFunctions++;
            else if (fn.security.severity === 'HIGH') securityReport.highRiskFunctions++;
            else if (fn.security.severity === 'MEDIUM') securityReport.mediumRiskFunctions++;
        }
        
        if (fn.security.suspicious) {
            securityReport.suspiciousFunctions++;
        }
    });
    
    // Calcular score de segurança
    if (securityReport.totalFunctions > 0) {
        let penalty = 0;
        penalty += securityReport.criticalFunctions * 10;
        penalty += securityReport.highRiskFunctions * 5;
        penalty += securityReport.mediumRiskFunctions * 2;
        penalty += securityReport.suspiciousFunctions * 1;
        
        securityReport.securityScore = Math.max(0, 100 - Math.min(penalty, 100));
    }
    
    // Gerar recomendações
    if (securityReport.criticalFunctions > 0) {
        securityReport.recommendations.push(
            `Remover ${securityReport.criticalFunctions} funções com vulnerabilidades CRÍTICAS`
        );
        securityReport.recommendations.push(
            'Revisar uso de eval() e Function()'
        );
    }
    
    if (securityReport.highRiskFunctions > 0) {
        securityReport.recommendations.push(
            `Revisar ${securityReport.highRiskFunctions} funções com vulnerabilidades ALTAS`
        );
        securityReport.recommendations.push(
            'Implementar sanitização para innerHTML/outerHTML'
        );
    }
    
    if (securityReport.suspiciousFunctions > 0) {
        securityReport.recommendations.push(
            `Auditar ${securityReport.suspiciousFunctions} funções com nomes suspeitos`
        );
    }
    
    return securityReport;
}