// security-scanner.js - Elite Security Scanner
// Módulo avançado de análise de segurança para JavaScript

export class EliteSecurityScanner {
    constructor(options = {}) {
        this.options = {
            deepScan: true,
            detectXSS: true,
            detectCSRF: true,
            detectCORS: true,
            detectSQLi: true,
            detectRCE: true,
            detectProtoPollution: true,
            detectHardcodedSecrets: true,
            detectInsecureImports: true,
            detectDeprecatedAPIs: true,
            ...options
        };
        
        this.threats = [];
        this.warnings = [];
        this.recommendations = [];
        
        // Banco de dados de vulnerabilidades conhecidas
        this.vulnerabilityDatabase = this.initializeVulnerabilityDatabase();
    }
    
    /**
     * Inicializa o banco de dados de vulnerabilidades
     */
    initializeVulnerabilityDatabase() {
        return {
            critical: [
                { id: 'EVAL-001', pattern: /eval\s*\([^)]*\)/g, description: 'eval() permite execução de código arbitrário' },
                { id: 'FUNC-001', pattern: /new\s+Function\s*\(/g, description: 'Function constructor similar a eval()' },
                { id: 'PROTO-001', pattern: /constructor\.constructor/g, description: 'Constructor chaining pode contornar sandboxes' },
                { id: 'PROTO-002', pattern: /__proto__\s*=/g, description: 'Manipulação direta de __proto__' },
                { id: 'RCE-001', pattern: /child_process\.(exec|execFile|spawn)\(/g, description: 'Execução de comandos do sistema' }
            ],
            high: [
                { id: 'XSS-001', pattern: /\.innerHTML\s*=/g, description: 'innerHTML assignment - risco de XSS' },
                { id: 'XSS-002', pattern: /\.outerHTML\s*=/g, description: 'outerHTML assignment - alto risco de XSS' },
                { id: 'XSS-003', pattern: /document\.write\(/g, description: 'document.write() - vetor de XSS' },
                { id: 'INJ-001', pattern: /setTimeout\s*\([^,)]*\)/g, description: 'setTimeout com string pode executar código' },
                { id: 'INJ-002', pattern: /setInterval\s*\([^,)]*\)/g, description: 'setInterval com string pode executar código' }
            ],
            medium: [
                { id: 'DOM-001', pattern: /location\s*=/g, description: 'Redirecionamento de location pode ser manipulado' },
                { id: 'DOM-002', pattern: /window\.open/g, description: 'window.open() pode abrir popups maliciosos' },
                { id: 'API-001', pattern: /localStorage/g, description: 'localStorage - dados sensíveis podem ser acessados' },
                { id: 'API-002', pattern: /sessionStorage/g, description: 'sessionStorage - dados sensíveis na sessão' },
                { id: 'NET-001', pattern: /XMLHttpRequest/g, description: 'XMLHttpRequest - chamadas não validadas' },
                { id: 'NET-002', pattern: /fetch\s*\(/g, description: 'fetch() - chamadas não validadas' }
            ],
            low: [
                { id: 'COOKIE-001', pattern: /document\.cookie/g, description: 'Manipulação direta de cookies' },
                { id: 'STORAGE-001', pattern: /indexedDB/g, description: 'IndexedDB - armazenamento cliente' },
                { id: 'MISC-001', pattern: /console\.log/g, description: 'console.log() - informação sensível em logs' }
            ]
        };
    }
    
    /**
     * Scaneia código JavaScript em busca de vulnerabilidades
     */
    scan(sourceCode) {
        const results = {
            threats: [],
            warnings: [],
            recommendations: [],
            score: 100,
            grade: 'A+',
            timestamp: new Date().toISOString(),
            stats: {
                totalLines: sourceCode.split('\n').length,
                totalChars: sourceCode.length
            }
        };
        
        // Executar todos os scanners
        this.runBasicSecurityScan(sourceCode, results);
        
        if (this.options.deepScan) {
            this.runDeepSecurityScan(sourceCode, results);
        }
        
        if (this.options.detectXSS) {
            this.detectXSSVectors(sourceCode, results);
        }
        
        if (this.options.detectCSRF) {
            this.detectCSRFPotential(sourceCode, results);
        }
        
        if (this.options.detectCORS) {
            this.detectCORSVulnerabilities(sourceCode, results);
        }
        
        if (this.options.detectSQLi) {
            this.detectSQLInjectionPatterns(sourceCode, results);
        }
        
        if (this.options.detectRCE) {
            this.detectRCEMarkers(sourceCode, results);
        }
        
        if (this.options.detectProtoPollution) {
            this.detectProtoPollution(sourceCode, results);
        }
        
        if (this.options.detectHardcodedSecrets) {
            this.detectHardcodedSecrets(sourceCode, results);
        }
        
        if (this.options.detectInsecureImports) {
            this.analyzeImports(sourceCode, results);
        }
        
        if (this.options.detectDeprecatedAPIs) {
            this.detectDeprecatedAPIs(sourceCode, results);
        }
        
        // Análise final
        this.finalizeAnalysis(results);
        
        return results;
    }
    
    /**
     * Scanner básico de segurança
     */
    runBasicSecurityScan(code, results) {
        // Verificar vulnerabilidades conhecidas
        Object.entries(this.vulnerabilityDatabase).forEach(([severity, patterns]) => {
            patterns.forEach(pattern => {
                const matches = code.match(pattern.pattern);
                if (matches) {
                    results.threats.push({
                        id: pattern.id,
                        type: pattern.id.split('-')[0],
                        severity: severity.toUpperCase(),
                        description: pattern.description,
                        occurrences: matches.length,
                        examples: matches.slice(0, 3),
                        recommendation: this.getRecommendation(pattern.id)
                    });
                }
            });
        });
    }
    
    /**
     * Scanner profundo de segurança
     */
    runDeepSecurityScan(code, results) {
        // Análise de variáveis suspeitas
        this.analyzeSuspiciousVariables(code, results);
        
        // Análise de funções perigosas
        this.analyzeDangerousFunctions(code, results);
        
        // Análise de padrões de injeção
        this.analyzeInjectionPatterns(code, results);
        
        // Análise de código ofuscado
        this.analyzeObfuscatedCode(code, results);
    }
    
    /**
     * Detecção de vetores XSS
     */
    detectXSSVectors(code, results) {
        const xssPatterns = [
            {
                regex: /['"`]\s*\+\s*[^+]+?\s*\+\s*['"`]/g,
                type: 'STRING_CONCAT_XSS',
                severity: 'MEDIUM',
                description: 'Concatenação de strings pode levar a XSS',
                mitigation: 'Usar template literals com escape apropriado'
            },
            {
                regex: /href\s*=\s*['"`]javascript:/gi,
                type: 'JAVASCRIPT_HREF',
                severity: 'HIGH',
                description: 'Protocolo javascript: em href',
                mitigation: 'Nunca usar javascript: em href'
            },
            {
                regex: /src\s*=\s*['"`]javascript:/gi,
                type: 'JAVASCRIPT_SRC',
                severity: 'HIGH',
                description: 'Protocolo javascript: em src',
                mitigation: 'Nunca usar javascript: em src'
            }
        ];
        
        xssPatterns.forEach(pattern => {
            const matches = code.match(pattern.regex);
            if (matches) {
                results.threats.push({
                    type: pattern.type,
                    severity: pattern.severity,
                    description: pattern.description,
                    mitigation: pattern.mitigation,
                    occurrences: matches.length
                });
            }
        });
    }
    
    /**
     * Detecção de potencial CSRF
     */
    detectCSRFPotential(code, results) {
        // Verificar se há chamadas AJAX sem tokens CSRF
        const ajaxPatterns = [
            /XMLHttpRequest/,
            /fetch\s*\(/,
            /\$\.ajax/,
            /axios\s*\./
        ];
        
        const hasAjax = ajaxPatterns.some(pattern => pattern.test(code));
        
        // Procurar por tokens CSRF
        const csrfTokens = [
            /csrf_token/,
            /X-CSRF-Token/,
            /X-XSRF-Token/,
            /anti-forgery/
        ];
        
        const hasCsrfToken = csrfTokens.some(pattern => pattern.test(code));
        
        if (hasAjax && !hasCsrfToken) {
            results.warnings.push({
                type: 'POTENTIAL_CSRF',
                severity: 'MEDIUM',
                description: 'Chamadas AJAX detectadas sem tokens CSRF visíveis',
                recommendation: 'Implementar tokens CSRF para todas as requisições mutáveis'
            });
        }
    }
    
    /**
     * Detecção de vulnerabilidades CORS
     */
    detectCORSVulnerabilities(code, results) {
        const corsPatterns = [
            {
                regex: /Access-Control-Allow-Origin:\s*\*/g,
                type: 'CORS_WILDCARD',
                severity: 'HIGH',
                description: 'CORS configurado com wildcard (*) permite qualquer origem',
                mitigation: 'Restringir origens permitidas'
            },
            {
                regex: /Access-Control-Allow-Credentials:\s*true/g,
                type: 'CORS_CREDENTIALS',
                severity: 'MEDIUM',
                description: 'CORS com credenciais pode ser explorado',
                mitigation: 'Usar com cuidado e apenas quando necessário'
            }
        ];
        
        corsPatterns.forEach(pattern => {
            if (pattern.regex.test(code)) {
                results.threats.push({
                    type: pattern.type,
                    severity: pattern.severity,
                    description: pattern.description,
                    mitigation: pattern.mitigation
                });
            }
        });
    }
    
    /**
     * Detecção de padrões de SQL Injection
     */
    detectSQLInjectionPatterns(code, results) {
        // Padrões comuns em Node.js/Express
        const sqlPatterns = [
            {
                regex: /db\.query\s*\(\s*[^)]*\$\{[^}]*\}[^)]*\)/g,
                type: 'SQL_TEMPLATE_INJECTION',
                severity: 'HIGH',
                description: 'Template strings em queries podem causar SQL Injection',
                mitigation: 'Usar prepared statements ou query builders'
            },
            {
                regex: /['"`]\s*\+\s*[^+]+?\s*\+\s*['"`]/g,
                type: 'SQL_STRING_CONCAT',
                severity: 'HIGH',
                description: 'Concatenação de strings em queries é arriscada',
                mitigation: 'Parâmetros parametrizados são obrigatórios'
            }
        ];
        
        sqlPatterns.forEach(pattern => {
            const matches = code.match(pattern.regex);
            if (matches) {
                results.threats.push({
                    type: pattern.type,
                    severity: pattern.severity,
                    description: pattern.description,
                    mitigation: pattern.mitigation,
                    occurrences: matches.length
                });
            }
        });
    }
    
    /**
     * Detecção de marcadores RCE (Remote Code Execution)
     */
    detectRCEMarkers(code, results) {
        const rcePatterns = [
            {
                regex: /child_process\.(exec|execFile|spawn)\(/g,
                type: 'CHILD_PROCESS_EXEC',
                severity: 'CRITICAL',
                description: 'Execução de comandos do sistema pode levar a RCE',
                mitigation: 'Validar e sanitizar entradas de comando'
            },
            {
                regex: /eval\s*\(.*process\.env/g,
                type: 'ENV_IN_EVAL',
                severity: 'CRITICAL',
                description: 'Variáveis de ambiente em eval() é extremamente perigoso',
                mitigation: 'Nunca usar eval() com dados de ambiente'
            }
        ];
        
        rcePatterns.forEach(pattern => {
            if (pattern.regex.test(code)) {
                results.threats.push({
                    type: pattern.type,
                    severity: pattern.severity,
                    description: pattern.description,
                    mitigation: pattern.mitigation
                });
            }
        });
    }
    
    /**
     * Detecção de Prototype Pollution
     */
    detectProtoPollution(code, results) {
        const pollutionPatterns = [
            {
                regex: /Object\.assign\s*\([^,)]*,/g,
                type: 'OBJECT_ASSIGN_POLLUTION',
                severity: 'HIGH',
                description: 'Object.assign() pode levar a prototype pollution',
                mitigation: 'Validar objetos de entrada ou usar Object.create(null)'
            },
            {
                regex: /__proto__/g,
                type: 'DIRECT_PROTO_ACCESS',
                severity: 'HIGH',
                description: 'Acesso direto a __proto__ é perigoso',
                mitigation: 'Evitar manipulação direta de prototype'
            },
            {
                regex: /constructor\.constructor/g,
                type: 'CONSTRUCTOR_CHAINING',
                severity: 'CRITICAL',
                description: 'Constructor chaining pode contornar sandboxes',
                mitigation: 'Validar entradas de função construtora'
            }
        ];
        
        pollutionPatterns.forEach(pattern => {
            const matches = code.match(pattern.regex);
            if (matches) {
                results.threats.push({
                    type: pattern.type,
                    severity: pattern.severity,
                    description: pattern.description,
                    mitigation: pattern.mitigation,
                    occurrences: matches.length
                });
            }
        });
    }
    
    /**
     * Detecção de segredos hardcoded
     */
    detectHardcodedSecrets(code, results) {
        const secretPatterns = [
            {
                regex: /['"`](?:[A-Za-z0-9+/]{40,}|[A-Fa-f0-9]{64,}|sk_live_[A-Za-z0-9]{24,})['"`]/g,
                type: 'API_KEY_DETECTED',
                severity: 'CRITICAL',
                description: 'Possível chave de API hardcoded',
                mitigation: 'Mover para variáveis de ambiente'
            },
            {
                regex: /['"`]password['"`]\s*:\s*['"`][^'"`]+['"`]/g,
                type: 'HARDCODED_PASSWORD',
                severity: 'CRITICAL',
                description: 'Senha hardcoded no código',
                mitigation: 'Usar variáveis de ambiente ou secret manager'
            },
            {
                regex: /['"`](?:secret|token|auth)['"`]\s*:\s*['"`][^'"`]+['"`]/g,
                type: 'HARDCODED_SECRET',
                severity: 'HIGH',
                description: 'Segredo hardcoded no código',
                mitigation: 'Nunca armazenar segredos no código fonte'
            }
        ];
        
        secretPatterns.forEach(pattern => {
            const matches = code.match(pattern.regex);
            if (matches) {
                results.threats.push({
                    type: pattern.type,
                    severity: pattern.severity,
                    description: pattern.description,
                    mitigation: pattern.mitigation,
                    occurrences: matches.length,
                    warning: '⚠️ REMOVER IMEDIATAMENTE DO CÓDIGO ⚠️'
                });
            }
        });
    }
    
    /**
     * Análise de imports e dependências
     */
    analyzeImports(code, results) {
        const importPatterns = [
            {
                regex: /import\s*\(/g,
                type: 'DYNAMIC_IMPORT',
                severity: 'MEDIUM',
                description: 'Dynamic imports podem carregar código malicioso',
                mitigation: 'Validar caminhos de importação dinâmica'
            },
            {
                regex: /require\s*\(/g,
                type: 'DYNAMIC_REQUIRE',
                severity: 'MEDIUM',
                description: 'Dynamic require() pode carregar módulos arbitrários',
                mitigation: 'Evitar require() com variáveis dinâmicas'
            }
        ];
        
        importPatterns.forEach(pattern => {
            const matches = code.match(pattern.regex);
            if (matches) {
                results.warnings.push({
                    type: pattern.type,
                    severity: pattern.severity,
                    description: pattern.description,
                    recommendation: pattern.mitigation
                });
            }
        });
    }
    
    /**
     * Detecção de APIs descontinuadas
     */
    detectDeprecatedAPIs(code, results) {
        const deprecatedPatterns = [
            {
                regex: /document\.domain/g,
                type: 'DEPRECATED_DOCUMENT_DOMAIN',
                severity: 'LOW',
                description: 'document.domain está descontinuado',
                mitigation: 'Usar postMessage ou outras APIs modernas'
            },
            {
                regex: /showModalDialog/g,
                type: 'DEPRECATED_SHOW_MODAL_DIALOG',
                severity: 'LOW',
                description: 'showModalDialog() está descontinuado',
                mitigation: 'Usar dialog element ou modals customizados'
            }
        ];
        
        deprecatedPatterns.forEach(pattern => {
            if (pattern.regex.test(code)) {
                results.warnings.push({
                    type: pattern.type,
                    severity: pattern.severity,
                    description: pattern.description,
                    recommendation: pattern.mitigation
                });
            }
        });
    }
    
    /**
     * Análise de variáveis suspeitas
     */
    analyzeSuspiciousVariables(code, results) {
        const variablePatterns = [
            {
                regex: /(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=/g,
                type: 'VARIABLE_DECLARATION',
                extractor: (match) => match[1]
            }
        ];
        
        const suspiciousKeywords = [
            'password', 'secret', 'key', 'token', 'auth', 
            'credential', 'private', 'hidden', 'admin', 'root',
            'sudo', 'shell', 'command', 'execute', 'inject'
        ];
        
        variablePatterns.forEach(pattern => {
            let match;
            while ((match = pattern.regex.exec(code)) !== null) {
                const varName = pattern.extractor(match);
                
                suspiciousKeywords.forEach(keyword => {
                    if (varName.toLowerCase().includes(keyword)) {
                        results.warnings.push({
                            type: 'SUSPICIOUS_VARIABLE_NAME',
                            severity: 'MEDIUM',
                            description: `Variável '${varName}' contém palavra-chave suspeita '${keyword}'`,
                            recommendation: 'Revisar se contém informação sensível'
                        });
                    }
                });
            }
        });
    }
    
    /**
     * Análise de funções perigosas
     */
    analyzeDangerousFunctions(code, results) {
        const functionPatterns = [
            {
                regex: /function\s+([A-Za-z_$][\w$]*)\s*\(/g,
                type: 'FUNCTION_DECLARATION',
                extractor: (match) => match[1]
            },
            {
                regex: /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(?[^)]*\)?\s*=>/g,
                type: 'ARROW_FUNCTION',
                extractor: (match) => match[1]
            }
        ];
        
        const dangerousNames = [
            'eval', 'execute', 'run', 'inject', 'parse', 'compile',
            'load', 'save', 'delete', 'remove', 'update', 'create',
            'destroy', 'init', 'start', 'stop', 'config', 'settings'
        ];
        
        functionPatterns.forEach(pattern => {
            let match;
            while ((match = pattern.regex.exec(code)) !== null) {
                const funcName = pattern.extractor(match);
                
                dangerousNames.forEach(name => {
                    if (funcName.toLowerCase().includes(name)) {
                        results.warnings.push({
                            type: 'DANGEROUS_FUNCTION_NAME',
                            severity: 'LOW',
                            description: `Função '${funcName}' tem nome suspeito`,
                            recommendation: 'Auditar função cuidadosamente'
                        });
                    }
                });
            }
        });
    }
    
    /**
     * Análise de padrões de injeção
     */
    analyzeInjectionPatterns(code, results) {
        const injectionPatterns = [
            {
                regex: /\$\{[^}]*\}/g,
                type: 'TEMPLATE_INJECTION',
                severity: 'MEDIUM',
                description: 'Template literals podem ser vetores de injeção',
                context: 'Verificar se templates contêm input não confiável'
            },
            {
                regex: /\/.*\//g,
                type: 'REGEX_INJECTION',
                severity: 'MEDIUM',
                description: 'Regex dinâmico pode causar ReDoS',
                context: 'Validar padrões regex de fontes externas'
            }
        ];
        
        injectionPatterns.forEach(pattern => {
            const matches = code.match(pattern.regex);
            if (matches && matches.length > 5) {
                results.warnings.push({
                    type: pattern.type,
                    severity: pattern.severity,
                    description: `${pattern.description} (${matches.length} ocorrências)`,
                    recommendation: pattern.context
                });
            }
        });
    }
    
    /**
     * Análise de código ofuscado
     */
    analyzeObfuscatedCode(code, results) {
        // Padrões de ofuscação
        const obfuscationPatterns = [
            {
                regex: /\\x[0-9a-f]{2}/gi,
                type: 'HEX_ESCAPES',
                description: 'Escape sequences hexadecimais'
            },
            {
                regex: /\\u[0-9a-f]{4}/gi,
                type: 'UNICODE_ESCAPES',
                description: 'Escape sequences Unicode'
            },
            {
                regex: /eval\(.*atob\(/gi,
                type: 'EVAL_WITH_BASE64',
                description: 'eval() com base64 decoding'
            },
            {
                regex: /\.replace\(/g,
                type: 'STRING_REPLACE_CHAINING',
                description: 'Cadeias de replace()'
            }
        ];
        
        let obfuscationScore = 0;
        
        obfuscationPatterns.forEach(pattern => {
            const matches = code.match(pattern.regex);
            if (matches) {
                obfuscationScore += matches.length;
                
                if (matches.length > 3) {
                    results.warnings.push({
                        type: 'POSSIBLE_OBFUSCATION',
                        severity: 'MEDIUM',
                        description: `Possível ofuscação detectada: ${pattern.description}`,
                        recommendation: 'Revisar código - ofuscação pode esconder malware'
                    });
                }
            }
        });
        
        if (obfuscationScore > 10) {
            results.threats.push({
                type: 'HIGHLY_OBFUSCATED_CODE',
                severity: 'HIGH',
                description: 'Código altamente ofuscado detectado',
                recommendation: 'Analisar cuidadosamente - pode conter código malicioso'
            });
        }
    }
    
    /**
     * Finaliza a análise e calcula scores
     */
    finalizeAnalysis(results) {
        // Calcular score de segurança
        this.calculateSecurityScore(results);
        
        // Gerar recomendações gerais
        this.generateGeneralRecommendations(results);
        
        // Ordenar ameaças por severidade
        results.threats.sort((a, b) => {
            const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
            return severityOrder[a.severity] - severityOrder[b.severity];
        });
    }
    
    /**
     * Calcula score de segurança
     */
    calculateSecurityScore(results) {
        let score = 100;
        
        // Penalidades baseadas em severidade
        results.threats.forEach(threat => {
            switch(threat.severity) {
                case 'CRITICAL':
                    score -= 20;
                    break;
                case 'HIGH':
                    score -= 10;
                    break;
                case 'MEDIUM':
                    score -= 5;
                    break;
                case 'LOW':
                    score -= 2;
                    break;
            }
        });
        
        // Penalidades por quantidade
        if (results.threats.length > 5) score -= 10;
        if (results.threats.length > 10) score -= 15;
        if (results.threats.length > 20) score -= 25;
        
        // Penalidades por warnings
        if (results.warnings.length > 10) score -= 10;
        if (results.warnings.length > 20) score -= 15;
        
        // Garantir que score não seja negativo
        results.score = Math.max(0, Math.min(100, Math.round(score)));
        
        // Determinar classificação
        if (results.score >= 90) results.grade = 'A+';
        else if (results.score >= 80) results.grade = 'A';
        else if (results.score >= 70) results.grade = 'B';
        else if (results.score >= 60) results.grade = 'C';
        else if (results.score >= 50) results.grade = 'D';
        else results.grade = 'F';
        
        // Adicionar estatísticas de score
        results.stats.securityScore = results.score;
        results.stats.grade = results.grade;
        results.stats.totalThreats = results.threats.length;
        results.stats.totalWarnings = results.warnings.length;
    }
    
    /**
     * Gera recomendações gerais
     */
    generateGeneralRecommendations(results) {
        const criticalCount = results.threats.filter(t => t.severity === 'CRITICAL').length;
        const highCount = results.threats.filter(t => t.severity === 'HIGH').length;
        
        if (criticalCount > 0) {
            results.recommendations.push(
                `🚨 Corrigir ${criticalCount} vulnerabilidades CRÍTICAS imediatamente`
            );
            results.recommendations.push(
                '🔒 Implementar Content Security Policy (CSP)'
            );
            results.recommendations.push(
                '🛡️ Usar sandbox para execução de código dinâmico'
            );
        }
        
        if (highCount > 0) {
            results.recommendations.push(
                `⚠️ Corrigir ${highCount} vulnerabilidades ALTAS`
            );
            results.recommendations.push(
                '✅ Validar todas as entradas de usuário'
            );
            results.recommendations.push(
                '🧼 Sanitizar saídas para prevenir XSS'
            );
        }
        
        if (results.threats.length > 10) {
            results.recommendations.push(
                '📋 Realizar revisão de segurança profunda'
            );
            results.recommendations.push(
                '👥 Considerar auditoria de segurança por terceiros'
            );
        }
        
        // Recomendações baseadas no score
        if (results.score < 60) {
            results.recommendations.push(
                '🔴 ALERTA: Score de segurança baixo - ação imediata necessária'
            );
        } else if (results.score < 80) {
            results.recommendations.push(
                '🟡 Atenção: Score moderado - melhorias recomendadas'
            );
        } else {
            results.recommendations.push(
                '🟢 Bom trabalho! Mantenha as boas práticas de segurança'
            );
        }
    }
    
    /**
     * Obtém recomendação específica para vulnerabilidade
     */
    getRecommendation(vulnerabilityId) {
        const recommendations = {
            'EVAL-001': 'Substituir eval() por JSON.parse() ou funções específicas',
            'FUNC-001': 'Evitar Function() constructor - usar funções nomeadas',
            'XSS-001': 'Substituir innerHTML por textContent ou sanitizar com DOMPurify',
            'XSS-002': 'EVITAR outerHTML completamente - risco extremo de XSS',
            'XSS-003': 'Substituir document.write() por métodos DOM seguros',
            'PROTO-001': 'Validar parâmetros de construtores - não confiar em input',
            'PROTO-002': 'Evitar manipulação direta de __proto__',
            'RCE-001': 'Validar e sanitizar comandos do sistema - usar sandbox',
            'SQL-001': 'Usar prepared statements para todas as queries SQL',
            'SQL-002': 'Validar e sanitizar input do usuário antes de queries'
        };
        
        return recommendations[vulnerabilityId] || 'Revisar implementação e seguir boas práticas de segurança';
    }
    
    /**
     * Gera relatório HTML de segurança
     */
    generateHTMLReport(scanResults) {
        const severityColors = {
            'CRITICAL': '#d93025',
            'HIGH': '#f29900',
            'MEDIUM': '#f6bf26',
            'LOW': '#0b8043'
        };
        
        const gradeColors = {
            'A+': '#0b8043',
            'A': '#0b8043',
            'B': '#34a853',
            'C': '#fbbc05',
            'D': '#f29900',
            'F': '#ea4335'
        };
        
        // Gerar HTML do relatório
        const html = this.buildHTMLReport(scanResults, severityColors, gradeColors);
        return html;
    }
    
    /**
     * Constrói o HTML do relatório
     */
    buildHTMLReport(scanResults, severityColors, gradeColors) {
        return `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Relatório de Segurança - JS Inspector Elite</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 0;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #1a237e 0%, #283593 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        
        .security-score {
            font-size: 72px;
            font-weight: bold;
            margin: 20px 0;
        }
        
        .grade-badge {
            display: inline-block;
            padding: 10px 30px;
            border-radius: 50px;
            font-weight: bold;
            font-size: 24px;
            margin: 10px;
        }
        
        .threat-card {
            border-left: 5px solid;
            margin: 15px 0;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 8px;
        }
        
        .critical { border-color: #d93025; background: #ffe6e6; }
        .high { border-color: #f29900; background: #fff3e6; }
        .medium { border-color: #f6bf26; background: #fff9e6; }
        .low { border-color: #0b8043; background: #e6f4ea; }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
        }
        
        .stat-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 25px;
            border-radius: 15px;
            text-align: center;
        }
        
        .stat-value {
            font-size: 42px;
            font-weight: bold;
            margin: 10px 0;
        }
        
        .recommendation {
            background: #e3f2fd;
            border-left: 4px solid #2196f3;
            padding: 15px;
            margin: 10px 0;
            border-radius: 8px;
        }
        
        @media print {
            body { background: white; }
            .container { box-shadow: none; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Relatório de Segurança Avançado</h1>
            <p>JS Inspector Pro Elite Security</p>
            <div class="security-score" style="color: ${gradeColors[scanResults.grade] || '#666'}">
                ${scanResults.score}/100
            </div>
            <div class="grade-badge" style="background: ${gradeColors[scanResults.grade] || '#666'}">
                ${scanResults.grade}
            </div>
            <p>Gerado em: ${new Date(scanResults.timestamp).toLocaleString()}</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <h3>Ameaças Totais</h3>
                <div class="stat-value">${scanResults.threats.length}</div>
            </div>
            <div class="stat-card">
                <h3>Críticas</h3>
                <div class="stat-value" style="color: #ff4444">
                    ${scanResults.threats.filter(t => t.severity === 'CRITICAL').length}
                </div>
            </div>
            <div class="stat-card">
                <h3>Altas</h3>
                <div class="stat-value" style="color: #ff8800">
                    ${scanResults.threats.filter(t => t.severity === 'HIGH').length}
                </div>
            </div>
            <div class="stat-card">
                <h3>Segurança</h3>
                <div class="stat-value">${scanResults.score}%</div>
            </div>
        </div>
        
        <div style="padding: 30px;">
            ${scanResults.threats.length > 0 ? `
            <h2>⚠️ Ameaças Detectadas</h2>
            ${scanResults.threats.map(threat => `
            <div class="threat-card ${threat.severity.toLowerCase()}">
                <h3 style="margin: 0 0 10px 0;">
                    <span style="color: ${severityColors[threat.severity]}; font-weight: bold;">
                        ${threat.severity}
                    </span> - ${threat.type}
                </h3>
                <p><strong>Descrição:</strong> ${threat.description}</p>
                <p><strong>Recomendação:</strong> ${threat.mitigation || threat.recommendation}</p>
                ${threat.occurrences ? `<p><strong>Ocorrências:</strong> ${threat.occurrences}</p>` : ''}
                ${threat.warning ? `<p style="color: #d93025; font-weight: bold;">${threat.warning}</p>` : ''}
            </div>
            `).join('')}
            ` : '<h2 style="color: #0b8043;">✅ Nenhuma ameaça crítica detectada</h2>'}
            
            ${scanResults.warnings.length > 0 ? `
            <h2>📋 Alertas de Segurança</h2>
            ${scanResults.warnings.map(warning => `
            <div class="recommendation">
                <h3 style="margin: 0 0 10px 0;">${warning.type}</h3>
                <p><strong>Descrição:</strong> ${warning.description}</p>
                <p><strong>Ação recomendada:</strong> ${warning.recommendation}</p>
            </div>
            `).join('')}
            ` : ''}
            
            ${scanResults.recommendations.length > 0 ? `
            <h2>💡 Recomendações Gerais</h2>
            ${scanResults.recommendations.map(rec => `
            <div class="recommendation">
                <p>${rec}</p>
            </div>
            `).join('')}
            ` : ''}
        </div>
        
        <div style="background: #f5f5f5; padding: 20px; text-align: center; color: #666;">
            <p>Relatório gerado por JS Inspector Pro Elite Security Scanner</p>
            <p>© ${new Date().getFullYear()} - Google Security Research Division</p>
            <p style="font-size: 12px; margin-top: 20px;">
                Este relatório é confidencial. Não compartilhe informações sensíveis.
            </p>
        </div>
    </div>
</body>
</html>
        `;
    }
}

// Singleton para uso global
export const securityScanner = new EliteSecurityScanner();