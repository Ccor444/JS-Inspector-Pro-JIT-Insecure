// scanner-classes.js
// Autor: Cleiton & ChatGPT — Scanner avançado de classes JS
// Versão Elite Security

export function scanClasses(source) {
    const results = [];
    const lines = source.split(/\r?\n/);

    // ===== REGEX AVANÇADAS PARA CAPTURAR CLASSES =====
    const re_class_named = /^\s*class\s+([A-Za-z0-9_$]+)\s*(?:extends\s+([A-Za-z0-9_$\.]+))?\s*\{/;
    const re_class_assigned = /^\s*(const|let|var)\s+([A-Za-z0-9_$]+)\s*=\s*class\s*(?:extends\s+([A-Za-z0-9_$\.]+))?\s*\{/;
    const re_class_property = /^\s*([A-Za-z0-9_$\.]+)\s*=\s*class\s*(?:extends\s+([A-Za-z0-9_$\.]+))?\s*\{/;
    const re_class_method = /^\s*(async\s+)?([A-Za-z0-9_$]+)\s*\(/;

    let insideClass = false;
    let currentClass = null;

    // ===== VARREDURA LINHA POR LINHA =====
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        let match;

        // 1 — class Nome
        if (!insideClass && (match = line.match(re_class_named))) {
            currentClass = {
                type: "class",
                name: match[1],
                extends: match[2] || null,
                line: i + 1,
                methods: [],
                security: {
                    hasDangerousMethods: false,
                    dangerousMethods: []
                }
            };
            insideClass = true;
            continue;
        }

        // 2 — const X = class
        if (!insideClass && (match = line.match(re_class_assigned))) {
            currentClass = {
                type: "class-assigned",
                name: match[2],
                extends: match[3] || null,
                line: i + 1,
                methods: [],
                security: {
                    hasDangerousMethods: false,
                    dangerousMethods: []
                }
            };
            insideClass = true;
            continue;
        }

        // 3 — obj.prop = class
        if (!insideClass && (match = line.match(re_class_property))) {
            currentClass = {
                type: "class-property",
                name: match[1],
                extends: match[2] || null,
                line: i + 1,
                methods: [],
                security: {
                    hasDangerousMethods: false,
                    dangerousMethods: []
                }
            };
            insideClass = true;
            continue;
        }

        // ===== Dentro da classe: capturar métodos =====
        if (insideClass) {
            // fechar classe
            if (line.includes("}")) {
                results.push(currentClass);
                insideClass = false;
                currentClass = null;
                continue;
            }

            // métodos
            if ((match = line.match(re_class_method))) {
                const methodName = match[2];

                // evitar palavras inválidas
                if (!["if", "for", "while", "switch"].includes(methodName)) {
                    const method = {
                        name: methodName,
                        async: !!match[1],
                        line: i + 1,
                        security: checkMethodSecurity(methodName, line)
                    };
                    
                    currentClass.methods.push(method);
                    
                    // Verificar se o método é perigoso
                    if (method.security.isDangerous) {
                        currentClass.security.hasDangerousMethods = true;
                        currentClass.security.dangerousMethods.push({
                            name: methodName,
                            reason: method.security.reason,
                            line: i + 1
                        });
                    }
                }
            }
        }
    }

    return results;
}

// Nova função: Verificar segurança dos métodos
function checkMethodSecurity(methodName, lineContent) {
    const dangerousPatterns = [
        { pattern: /eval\s*\(/, reason: 'Contém eval()' },
        { pattern: /new\s+Function/, reason: 'Usa Function constructor' },
        { pattern: /\.innerHTML\s*=/, reason: 'Atribui innerHTML' },
        { pattern: /\.outerHTML\s*=/, reason: 'Atribui outerHTML' },
        { pattern: /document\.write/, reason: 'Usa document.write()' },
        { pattern: /localStorage/, reason: 'Acessa localStorage' },
        { pattern: /sessionStorage/, reason: 'Acessa sessionStorage' },
        { pattern: /cookie/, reason: 'Manipula cookies' },
        { pattern: /XMLHttpRequest/, reason: 'Faz requisições HTTP' },
        { pattern: /fetch\s*\(/, reason: 'Faz requisições fetch' }
    ];
    
    const result = {
        isDangerous: false,
        reason: '',
        patternsFound: []
    };
    
    dangerousPatterns.forEach(pattern => {
        if (pattern.pattern.test(lineContent)) {
            result.isDangerous = true;
            result.patternsFound.push(pattern.reason);
        }
    });
    
    if (result.patternsFound.length > 0) {
        result.reason = result.patternsFound.join(', ');
    }
    
    // Verificar nomes de métodos suspeitos
    const suspiciousNames = [
        'inject', 'execute', 'run', 'eval', 'parse', 'load', 'save',
        'delete', 'remove', 'update', 'create', 'destroy', 'init',
        'start', 'stop', 'pause', 'resume', 'config', 'settings'
    ];
    
    if (suspiciousNames.includes(methodName.toLowerCase())) {
        result.isSuspicious = true;
        result.suspiciousName = methodName;
    }
    
    return result;
}

// ===== DEBUG PRONTO =====
export function scanClassesDebug(source) {
    console.log("=== SCANNER CLASSES ===");
    const res = scanClasses(source);

    res.forEach(c => {
        console.log(
            `[CLASS] ${c.name}` +
            (c.extends ? ` extends ${c.extends}` : "") +
            ` (linha ${c.line})`
        );
        
        if (c.security.hasDangerousMethods) {
            console.log(`   ⚠️  CLASSE COM MÉTODOS PERIGOSOS!`);
            c.security.dangerousMethods.forEach(m => {
                console.log(`      -> ${m.name}: ${m.reason} (linha ${m.line})`);
            });
        }

        c.methods.forEach(m => {
            const securityInfo = m.security.isDangerous ? ` ⚠️ ${m.security.reason}` : '';
            console.log(
                `   -> método ${m.name} (linha ${m.line}) ${m.async ? "async" : ""}${securityInfo}`
            );
        });
    });

    console.log("=========================");
    return res;
}

// Nova função: Análise de segurança de classes
export function analyzeClassSecurity(classes) {
    const securityReport = {
        totalClasses: classes.length,
        classesWithDangerousMethods: 0,
        totalDangerousMethods: 0,
        securityScore: 100,
        recommendations: []
    };
    
    classes.forEach(cls => {
        if (cls.security.hasDangerousMethods) {
            securityReport.classesWithDangerousMethods++;
            securityReport.totalDangerousMethods += cls.security.dangerousMethods.length;
        }
    });
    
    // Calcular score
    if (securityReport.totalClasses > 0) {
        const dangerRatio = securityReport.classesWithDangerousMethods / securityReport.totalClasses;
        securityReport.securityScore = Math.max(0, 100 - (dangerRatio * 50));
    }
    
    // Gerar recomendações
    if (securityReport.classesWithDangerousMethods > 0) {
        securityReport.recommendations.push(
            `Revisar ${securityReport.totalDangerousMethods} métodos perigosos em ${securityReport.classesWithDangerousMethods} classes`
        );
        securityReport.recommendations.push(
            'Considerar usar sandbox para execução de métodos perigosos'
        );
        securityReport.recommendations.push(
            'Implementar validação de entrada para métodos críticos'
        );
    }
    
    return securityReport;
}