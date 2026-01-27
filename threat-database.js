// threat-database.js - Banco de dados de vulnerabilidades conhecidas
// Google Security Research Division

export const THREAT_DATABASE = {
    // Categorias de vulnerabilidades
    categories: {
        xss: {
            name: 'Cross-Site Scripting (XSS)',
            severity: 'HIGH',
            description: 'Permite injetar scripts maliciosos em páginas web',
            cwe: 'CWE-79',
            mitigations: [
                'Sanitizar todas as entradas de usuário',
                'Usar Content Security Policy (CSP)',
                'Escapar caracteres HTML',
                'Usar textContent em vez de innerHTML',
                'Implementar HTTPOnly cookies'
            ],
            references: [
                'https://owasp.org/www-community/attacks/xss/',
                'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'
            ]
        },
        csrf: {
            name: 'Cross-Site Request Forgery',
            severity: 'HIGH',
            description: 'Permite executar ações não autorizadas em nome do usuário',
            cwe: 'CWE-352',
            mitigations: [
                'Implementar tokens CSRF',
                'Validar cabeçalho Origin/Referer',
                'Usar SameSite cookies',
                'Requerer confirmação para ações sensíveis',
                'Implementar captcha para operações críticas'
            ],
            references: [
                'https://owasp.org/www-community/attacks/csrf',
                'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html'
            ]
        },
        injection: {
            name: 'Code Injection',
            severity: 'CRITICAL',
            description: 'Execução de código arbitrário',
            cwe: 'CWE-94',
            mitigations: [
                'Nunca usar eval() ou Function()',
                'Validar e sanitizar todas as entradas',
                'Usar prepared statements para SQL',
                'Implementar sandboxing',
                'Validar serialização de dados'
            ],
            references: [
                'https://owasp.org/www-community/attacks/Code_Injection',
                'https://cwe.mitre.org/data/definitions/94.html'
            ]
        },
        rce: {
            name: 'Remote Code Execution',
            severity: 'CRITICAL',
            description: 'Execução de código no servidor',
            cwe: 'CWE-78',
            mitigations: [
                'Validar comandos do sistema',
                'Usar processos isolados',
                'Implementar limites de recursos',
                'Monitorar atividade suspeita',
                'Usar containers ou VMs para isolamento'
            ],
            references: [
                'https://cwe.mitre.org/data/definitions/78.html',
                'https://owasp.org/www-community/attacks/Command_Injection'
            ]
        },
        protoPollution: {
            name: 'Prototype Pollution',
            severity: 'HIGH',
            description: 'Manipulação de prototypes JavaScript',
            cwe: 'CWE-1321',
            mitigations: [
                'Validar objetos antes de manipulação',
                'Usar Object.create(null) para objetos limpos',
                'Evitar Object.assign com input do usuário',
                'Congelar objetos quando possível',
                'Usar Map/Set em vez de objetos para dados dinâmicos'
            ],
            references: [
                'https://github.com/HoLyVieR/prototype-pollution-nsec18',
                'https://cwe.mitre.org/data/definitions/1321.html'
            ]
        }
    },
    
    // Padrões específicos
    patterns: [
        {
            id: 'EVAL-001',
            name: 'eval() Usage',
            category: 'injection',
            regex: /eval\s*\([^)]*\)/g,
            severity: 'CRITICAL',
            cwe: 'CWE-95',
            description: 'Uso de eval() permite execução de código arbitrário',
            example: 'eval(userInput)',
            remediation: 'Substituir por JSON.parse() ou parser seguro',
            cvss: '9.8'
        },
        {
            id: 'XSS-001',
            name: 'innerHTML Assignment',
            category: 'xss',
            regex: /\.innerHTML\s*=\s*[^;]+;/g,
            severity: 'HIGH',
            cwe: 'CWE-79',
            description: 'Atribuição direta a innerHTML pode causar XSS',
            example: 'element.innerHTML = userContent;',
            remediation: 'Usar textContent ou sanitizar com DOMPurify',
            cvss: '7.5'
        },
        {
            id: 'FUNC-001',
            name: 'Function Constructor',
            category: 'injection',
            regex: /new\s+Function\s*\(/g,
            severity: 'CRITICAL',
            cwe: 'CWE-95',
            description: 'Function constructor similar a eval()',
            example: 'new Function("return " + userInput)',
            remediation: 'Evitar completamente. Usar funções nomeadas.',
            cvss: '9.8'
        },
        {
            id: 'PROTO-001',
            name: 'Constructor Chaining',
            category: 'protoPollution',
            regex: /constructor\.constructor/g,
            severity: 'CRITICAL',
            cwe: 'CWE-1321',
            description: 'Constructor chaining pode contornar sandboxes',
            example: 'obj.constructor.constructor("return process")()',
            remediation: 'Validar parâmetros de construtores',
            cvss: '8.8'
        },
        {
            id: 'SQL-001',
            name: 'SQL Template Injection',
            category: 'injection',
            regex: /db\.query\s*\(\s*[^)]*\$\{[^}]*\}[^)]*\)/g,
            severity: 'HIGH',
            cwe: 'CWE-89',
            description: 'Template strings em queries podem causar SQL Injection',
            example: 'db.query(`SELECT * FROM users WHERE name = ${userInput}`)',
            remediation: 'Usar prepared statements ou query builders',
            cvss: '8.8'
        },
        {
            id: 'SECRET-001',
            name: 'Hardcoded API Key',
            category: 'injection',
            regex: /['"`](?:[A-Za-z0-9+/]{40,}|[A-Fa-f0-9]{64,}|sk_live_[A-Za-z0-9]{24,})['"`]/g,
            severity: 'CRITICAL',
            cwe: 'CWE-798',
            description: 'Chave de API hardcoded no código fonte',
            example: 'const apiKey = "sk_live_1234567890abcdef"',
            remediation: 'Mover para variáveis de ambiente ou secret manager',
            cvss: '9.1'
        },
        {
            id: 'TIMEOUT-001',
            name: 'Dynamic setTimeout',
            category: 'injection',
            regex: /setTimeout\s*\([^,)]*\)/g,
            severity: 'MEDIUM',
            cwe: 'CWE-95',
            description: 'setTimeout com string pode executar código',
            example: 'setTimeout("alert(1)", 1000)',
            remediation: 'Usar funções em vez de strings',
            cvss: '5.9'
        },
        {
            id: 'CORS-001',
            name: 'CORS Wildcard',
            category: 'xss',
            regex: /Access-Control-Allow-Origin:\s*\*/g,
            severity: 'HIGH',
            cwe: 'CWE-942',
            description: 'CORS configurado com wildcard permite qualquer origem',
            example: 'res.setHeader("Access-Control-Allow-Origin", "*")',
            remediation: 'Restringir origens permitidas',
            cvss: '6.5'
        }
    ],
    
    // Frameworks e bibliotecas com vulnerabilidades conhecidas
    frameworkVulnerabilities: {
        react: [
            {
                name: 'dangerouslySetInnerHTML',
                description: 'React prop que permite HTML não sanitizado',
                mitigation: 'Usar sanitização ou alternativas seguras',
                severity: 'HIGH'
            },
            {
                name: 'eval in JSX',
                description: 'Uso de eval() dentro de JSX',
                mitigation: 'Evitar eval() completamente',
                severity: 'CRITICAL'
            }
        ],
        vue: [
            {
                name: 'v-html directive',
                description: 'Renderiza HTML não sanitizado',
                mitigation: 'Usar v-text ou sanitizar manualmente',
                severity: 'HIGH'
            },
            {
                name: 'unsafe eval in computed',
                description: 'eval() em propriedades computadas',
                mitigation: 'Não usar eval() em Vue',
                severity: 'CRITICAL'
            }
        ],
        angular: [
            {
                name: 'bypassSecurityTrustHtml',
                description: 'Método que marca HTML como seguro',
                mitigation: 'Usar apenas com conteúdo confiável',
                severity: 'HIGH'
            },
            {
                name: 'innerHTML binding',
                description: 'Binding direto a innerHTML',
                mitigation: 'Usar sanitização com DomSanitizer',
                severity: 'HIGH'
            }
        ],
        node: [
            {
                name: 'eval in routes',
                description: 'eval() em handlers de rota',
                mitigation: 'Nunca usar eval() com input de rota',
                severity: 'CRITICAL'
            },
            {
                name: 'child_process.exec with user input',
                description: 'Execução de comandos com input do usuário',
                mitigation: 'Validar e sanitizar comandos',
                severity: 'CRITICAL'
            }
        ]
    },
    
    // Recomendações por framework
    frameworkRecommendations: {
        react: [
            'Usar JSX que escapa automaticamente',
            'Evitar dangerouslySetInnerHTML',
            'Validar props com PropTypes ou TypeScript',
            'Usar Context API para estado seguro',
            'Implementar Error Boundaries',
            'Usar React.lazy() para code splitting seguro'
        ],
        vue: [
            'Usar v-text em vez de v-html',
            'Validar props com TypeScript',
            'Implementar Vuex para gerenciamento de estado',
            'Usar composables reutilizáveis',
            'Implementar guards de rota',
            'Usar provide/inject com cuidado'
        ],
        angular: [
            'Usar binding seguro [innerHTML]',
            'Implementar sanitização com DomSanitizer',
            'Usar TypeScript strict mode',
            'Implementar guards de rota',
            'Usar interceptors para segurança HTTP',
            'Implementar change detection OnPush'
        ],
        node: [
            'Usar helmet.js para headers de segurança',
            'Implementar rate limiting',
            'Validar entradas com Joi ou Zod',
            'Usar prepared statements para SQL',
            'Implementar logging de segurança',
            'Usar JWT com expiration curta',
            'Armazenar segredos em variáveis de ambiente'
        ]
    },
    
    // CVEs conhecidos relacionados a JavaScript
    knownCVEs: [
        {
            cve: 'CVE-2021-44228',
            name: 'Log4Shell',
            description: 'RCE em Log4j',
            severity: 'CRITICAL',
            affected: 'Java, mas relevante para integrações JS',
            mitigation: 'Atualizar Log4j, usar versões seguras'
        },
        {
            cve: 'CVE-2021-22931',
            name: 'Node.js ICU vulnerability',
            description: 'Vulnerabilidade no módulo ICU do Node.js',
            severity: 'HIGH',
            affected: 'Node.js < 14.17.0',
            mitigation: 'Atualizar Node.js'
        },
        {
            cve: 'CVE-2020-11022',
            name: 'jQuery XSS',
            description: 'XSS vulnerability em jQuery',
            severity: 'HIGH',
            affected: 'jQuery < 3.5.0',
            mitigation: 'Atualizar jQuery'
        }
    ],
    
    // Métodos de sanitização recomendados
    sanitizationMethods: {
        html: [
            { name: 'DOMPurify', url: 'https://github.com/cure53/DOMPurify' },
            { name: 'sanitize-html', url: 'https://github.com/apostrophecms/sanitize-html' },
            { name: 'xss', url: 'https://github.com/leizongmin/js-xss' }
        ],
        sql: [
            { name: 'parameterized queries', description: 'Usar ? ou $ placeholders' },
            { name: 'knex.js', url: 'https://knexjs.org/' },
            { name: 'sequelize', url: 'https://sequelize.org/' }
        ],
        input: [
            { name: 'validator.js', url: 'https://github.com/validatorjs/validator.js' },
            { name: 'joi', url: 'https://github.com/hapijs/joi' },
            { name: 'yup', url: 'https://github.com/jquense/yup' },
            { name: 'zod', url: 'https://github.com/colinhacks/zod' }
        ]
    }
};

/**
 * Consulta o banco de dados de ameaças
 */
export function queryThreatDatabase(pattern) {
    return THREAT_DATABASE.patterns.filter(p => 
        p.name.toLowerCase().includes(pattern.toLowerCase()) ||
        p.id === pattern ||
        p.category === pattern
    );
}

/**
 * Gera recomendações baseadas no framework detectado
 */
export function getFrameworkRecommendations(framework) {
    return THREAT_DATABASE.frameworkRecommendations[framework] || [];
}

/**
 * Valida código contra o banco de dados de ameaças
 */
export function validateAgainstThreatDB(code) {
    const results = [];
    
    THREAT_DATABASE.patterns.forEach(pattern => {
        const matches = code.match(pattern.regex);
        if (matches) {
            results.push({
                ...pattern,
                occurrences: matches.length,
                matches: matches.slice(0, 5),
                lines: extractLines(code, matches)
            });
        }
    });
    
    return results;
}

/**
 * Extrai linhas onde os padrões foram encontrados
 */
function extractLines(code, matches) {
    const lines = code.split('\n');
    const result = [];
    
    matches.forEach(match => {
        // Encontrar a linha aproximada
        const index = code.indexOf(match);
        let charCount = 0;
        
        for (let i = 0; i < lines.length; i++) {
            charCount += lines[i].length + 1; // +1 para newline
            if (charCount > index) {
                result.push({
                    line: i + 1,
                    content: lines[i].trim(),
                    match: match
                });
                break;
            }
        }
    });
    
    return result.slice(0, 10); // Limitar a 10 linhas
}

/**
 * Obtém vulnerabilidades conhecidas por framework
 */
export function getFrameworkVulnerabilities(framework) {
    return THREAT_DATABASE.frameworkVulnerabilities[framework] || [];
}

/**
 * Gera relatório de segurança baseado no framework
 */
export function generateFrameworkSecurityReport(framework, code) {
    const vulnerabilities = getFrameworkVulnerabilities(framework);
    const recommendations = getFrameworkRecommendations(framework);
    const threatMatches = validateAgainstThreatDB(code);
    
    return {
        framework,
        vulnerabilities,
        recommendations,
        detectedThreats: threatMatches,
        securityScore: calculateFrameworkSecurityScore(threatMatches, vulnerabilities.length),
        timestamp: new Date().toISOString()
    };
}

/**
 * Calcula score de segurança para framework
 */
function calculateFrameworkSecurityScore(threatMatches, vulnerabilityCount) {
    let score = 100;
    
    // Penalizar por ameaças detectadas
    threatMatches.forEach(threat => {
        switch(threat.severity) {
            case 'CRITICAL': score -= 15; break;
            case 'HIGH': score -= 10; break;
            case 'MEDIUM': score -= 5; break;
            case 'LOW': score -= 2; break;
        }
    });
    
    // Penalizar por vulnerabilidades conhecidas no framework
    score -= vulnerabilityCount * 5;
    
    return Math.max(0, Math.min(100, score));
}

/**
 * Obtém métodos de sanitização recomendados
 */
export function getSanitizationMethods(type = 'html') {
    return THREAT_DATABASE.sanitizationMethods[type] || [];
}

/**
 * Gera relatório completo de ameaças
 */
export function generateThreatReport(code) {
    const threats = validateAgainstThreatDB(code);
    const categories = {};
    let totalSeverityScore = 0;
    
    // Agrupar por categoria e calcular scores
    threats.forEach(threat => {
        if (!categories[threat.category]) {
            categories[threat.category] = {
                threats: [],
                count: 0,
                severityScore: 0
            };
        }
        
        categories[threat.category].threats.push(threat);
        categories[threat.category].count++;
        
        // Calcular score de severidade
        let severityValue = 0;
        switch(threat.severity) {
            case 'CRITICAL': severityValue = 10; break;
            case 'HIGH': severityValue = 7; break;
            case 'MEDIUM': severityValue = 4; break;
            case 'LOW': severityValue = 1; break;
        }
        
        categories[threat.category].severityScore += severityValue;
        totalSeverityScore += severityValue;
    });
    
    // Calcular score geral (0-100, onde 100 é perfeito)
    const maxPossibleScore = threats.length * 10;
    const securityScore = maxPossibleScore > 0 
        ? Math.max(0, Math.min(100, 100 - (totalSeverityScore / maxPossibleScore * 100)))
        : 100;
    
    return {
        totalThreats: threats.length,
        categories,
        securityScore: Math.round(securityScore),
        threats,
        timestamp: new Date().toISOString(),
        summary: {
            critical: threats.filter(t => t.severity === 'CRITICAL').length,
            high: threats.filter(t => t.severity === 'HIGH').length,
            medium: threats.filter(t => t.severity === 'MEDIUM').length,
            low: threats.filter(t => t.severity === 'LOW').length
        }
    };
}