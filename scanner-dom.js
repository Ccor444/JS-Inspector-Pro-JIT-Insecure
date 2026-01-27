// scanner-dom.js
// Scanner DOM avançado com suporte a:
//  - AST (Acorn) ultra preciso
//  - Regex fallback (garante compatibilidade total)
//  - Análise de segurança XSS

export function scanDom(code, useAst = true) {
  const acorn = getAcorn();

  if (useAst && acorn) {
    try {
      const ast = acorn.parse(code, {
        ecmaVersion: "latest",
        sourceType: "module",
        locations: true
      });
      return collectDomFromAST(ast, code);
    } catch (e) {
      // Falhou → usa fallback
    }
  }

  return scanDomByRegex(code);
}

/* -----------------------------------------------------------------------
   1) Helper — Detecta Acorn automaticamente (browser ou Node)
------------------------------------------------------------------------ */
function getAcorn() {
  if (typeof window !== "undefined" && window.acorn) return window.acorn;

  try {
    if (typeof require === "function") return require("acorn");
  } catch (e) {}

  return null;
}

/* -----------------------------------------------------------------------
   2) Scanner via AST (o mais preciso que existe) com análise de segurança
------------------------------------------------------------------------ */
function collectDomFromAST(ast, code) {
  const results = [];
  const xssVulnerabilities = [];

  walk(ast, {
    CallExpression(node) {
      if (
        node.callee &&
        node.callee.type === "MemberExpression" &&
        node.callee.object?.name === "document"
      ) {
        const method = node.callee.property?.name;
        const arg = node.arguments?.[0];

        // getElementById("id")
        if (method === "getElementById") {
          const id = extractLiteral(arg);
          if (id) {
            const result = { 
              type: "getElementById", 
              id: id, 
              loc: node.loc,
              security: analyzeDomOperationSecurity(method, id, node, code)
            };
            results.push(result);
            
            if (result.security.isDangerous) {
              xssVulnerabilities.push(result);
            }
          }
        }

        // querySelector('#id')
        if (method === "querySelector") {
          const selector = extractLiteral(arg);
          if (selector?.startsWith("#")) {
            const result = {
              type: "querySelector",
              id: selector.slice(1),
              loc: node.loc,
              security: analyzeDomOperationSecurity(method, selector.slice(1), node, code)
            };
            results.push(result);
            
            if (result.security.isDangerous) {
              xssVulnerabilities.push(result);
            }
          }
        }

        // querySelectorAll('#id')
        if (method === "querySelectorAll") {
          const selector = extractLiteral(arg);
          if (selector?.startsWith("#")) {
            const result = {
              type: "querySelectorAll",
              id: selector.slice(1),
              loc: node.loc,
              security: analyzeDomOperationSecurity(method, selector.slice(1), node, code)
            };
            results.push(result);
            
            if (result.security.isDangerous) {
              xssVulnerabilities.push(result);
            }
          }
        }
      }
      
      // innerHTML assignments
      if (
        node.callee &&
        node.callee.type === "MemberExpression" &&
        node.callee.property?.name === "innerHTML"
      ) {
        const xssAnalysis = analyzeInnerHTMLForXSS(node, code);
        if (xssAnalysis.isDangerous) {
          xssVulnerabilities.push({
            type: "INNERHTML_XSS",
            description: "innerHTML assignment detected",
            severity: "HIGH",
            loc: node.loc,
            analysis: xssAnalysis
          });
        }
      }
    },
    
    AssignmentExpression(node) {
      // innerHTML = ...
      if (
        node.left &&
        node.left.type === "MemberExpression" &&
        node.left.property?.name === "innerHTML"
      ) {
        const xssAnalysis = analyzeInnerHTMLForXSS(node, code);
        if (xssAnalysis.isDangerous) {
          xssVulnerabilities.push({
            type: "INNERHTML_ASSIGNMENT_XSS",
            description: "Direct innerHTML assignment",
            severity: "HIGH",
            loc: node.loc,
            analysis: xssAnalysis
          });
        }
      }
    }
  });

  return {
    domOperations: results,
    xssVulnerabilities: xssVulnerabilities,
    security: {
      totalOperations: results.length,
      xssVulnerabilityCount: xssVulnerabilities.length,
      securityScore: calculateDomSecurityScore(results, xssVulnerabilities)
    }
  };
}

/* -----------------------------------------------------------------------
   3) Análise de segurança de operações DOM
------------------------------------------------------------------------ */
function analyzeDomOperationSecurity(method, elementId, node, code) {
  const security = {
    isDangerous: false,
    isSuspicious: false,
    xssRisk: "LOW",
    reasons: [],
    recommendations: []
  };
  
  // Verificar IDs suspeitos
  const suspiciousIds = [
    'content', 'html', 'body', 'header', 'footer', 'main',
    'script', 'style', 'head', 'title', 'meta', 'link',
    'input', 'form', 'textarea', 'select', 'button',
    'user', 'admin', 'root', 'config', 'settings'
  ];
  
  if (suspiciousIds.includes(elementId.toLowerCase())) {
    security.isSuspicious = true;
    security.reasons.push(`Element ID '${elementId}' é suspeito`);
    security.recommendations.push(`Validar conteúdo atribuído ao elemento #${elementId}`);
  }
  
  // Verificar se há innerHTML/outerHTML assignments para este elemento
  const lines = code.split('\n');
  const lineNumber = node.loc?.start?.line || 0;
  
  for (let i = Math.max(0, lineNumber - 5); i < Math.min(lines.length, lineNumber + 5); i++) {
    const line = lines[i];
    
    // Procurar por innerHTML assignments para este elemento
    if (line.includes(elementId) && line.includes('.innerHTML')) {
      security.isDangerous = true;
      security.xssRisk = "HIGH";
      security.reasons.push(`Elemento #${elementId} tem atribuição innerHTML`);
      security.recommendations.push(`Substituir innerHTML por textContent ou sanitizar`);
      break;
    }
    
    // Procurar por outerHTML assignments
    if (line.includes(elementId) && line.includes('.outerHTML')) {
      security.isDangerous = true;
      security.xssRisk = "CRITICAL";
      security.reasons.push(`Elemento #${elementId} tem atribuição outerHTML`);
      security.recommendations.push(`EVITAR outerHTML - risco extremo de XSS`);
      break;
    }
  }
  
  return security;
}

/* -----------------------------------------------------------------------
   4) Análise de innerHTML para XSS
------------------------------------------------------------------------ */
function analyzeInnerHTMLForXSS(node, code) {
  const analysis = {
    isDangerous: false,
    riskLevel: "LOW",
    patternsFound: [],
    recommendations: []
  };
  
  // Extrair o valor sendo atribuído
  let valueNode = null;
  if (node.type === "CallExpression") {
    // innerHTML.someMethod()
    valueNode = node.arguments?.[0];
  } else if (node.type === "AssignmentExpression") {
    // element.innerHTML = value
    valueNode = node.right;
  }
  
  if (!valueNode) return analysis;
  
  // Converter o node para string aproximada
  const nodeText = code.substring(valueNode.start, valueNode.end);
  
  // Padrões de XSS
  const xssPatterns = [
    { pattern: /<script>/i, risk: "CRITICAL", desc: "Tag script aberta" },
    { pattern: /<\/script>/i, risk: "CRITICAL", desc: "Tag script fechada" },
    { pattern: /javascript:/i, risk: "HIGH", desc: "Protocolo javascript:" },
    { pattern: /on\w+\s*=/i, risk: "HIGH", desc: "Event handler inline" },
    { pattern: /data:/i, risk: "MEDIUM", desc: "Protocolo data:" },
    { pattern: /vbscript:/i, risk: "CRITICAL", desc: "Protocolo vbscript:" },
    { pattern: /expression\s*\(/i, risk: "HIGH", desc: "CSS expression" }
  ];
  
  xssPatterns.forEach(pattern => {
    if (pattern.pattern.test(nodeText)) {
      analysis.isDangerous = true;
      analysis.patternsFound.push(pattern.desc);
      
      if (pattern.risk === "CRITICAL") analysis.riskLevel = "CRITICAL";
      else if (pattern.risk === "HIGH" && analysis.riskLevel !== "CRITICAL") analysis.riskLevel = "HIGH";
      else if (pattern.risk === "MEDIUM" && analysis.riskLevel === "LOW") analysis.riskLevel = "MEDIUM";
    }
  });
  
  // Verificar se é uma variável (dinâmica)
  if (valueNode.type === "Identifier") {
    analysis.isDangerous = true;
    analysis.patternsFound.push("Conteúdo dinâmico de variável");
    if (analysis.riskLevel === "LOW") analysis.riskLevel = "MEDIUM";
  }
  
  // Verificar se é template literal
  if (valueNode.type === "TemplateLiteral") {
    analysis.isDangerous = true;
    analysis.patternsFound.push("Template literal dinâmico");
    if (analysis.riskLevel === "LOW") analysis.riskLevel = "HIGH";
  }
  
  // Gerar recomendações
  if (analysis.isDangerous) {
    analysis.recommendations.push("Substituir innerHTML por textContent");
    analysis.recommendations.push("Se necessário usar HTML, sanitizar com DOMPurify");
    analysis.recommendations.push("Implementar Content Security Policy (CSP)");
    
    if (analysis.riskLevel === "CRITICAL") {
      analysis.recommendations.push("🚨 VULNERABILIDADE CRÍTICA: Revisar imediatamente");
    }
  }
  
  return analysis;
}

/* -----------------------------------------------------------------------
   5) Calcular score de segurança DOM
------------------------------------------------------------------------ */
function calculateDomSecurityScore(operations, vulnerabilities) {
  if (operations.length === 0) return 100;
  
  let score = 100;
  
  // Penalizar operações perigosas
  operations.forEach(op => {
    if (op.security?.isDangerous) {
      if (op.security.xssRisk === "CRITICAL") score -= 15;
      else if (op.security.xssRisk === "HIGH") score -= 10;
      else if (op.security.xssRisk === "MEDIUM") score -= 5;
    }
    if (op.security?.isSuspicious) score -= 2;
  });
  
  // Penalizar vulnerabilidades XSS
  vulnerabilities.forEach(vuln => {
    if (vuln.severity === "CRITICAL") score -= 20;
    else if (vuln.severity === "HIGH") score -= 15;
    else if (vuln.severity === "MEDIUM") score -= 10;
  });
  
  return Math.max(0, Math.min(100, Math.round(score)));
}

/* -----------------------------------------------------------------------
   6) Literal extractor (Literal, TemplateLiteral, etc.)
------------------------------------------------------------------------ */
function extractLiteral(node) {
  if (!node) return null;

  if (node.type === "Literal") return node.value;

  if (node.type === "TemplateLiteral") {
    if (node.quasis?.[0]) return node.quasis[0].value.raw;
  }

  return null;
}

/* -----------------------------------------------------------------------
   7) AST Walker simples (não depende de libs externas)
------------------------------------------------------------------------ */
function walk(node, visitors) {
  if (!node || typeof node.type !== "string") return;

  const fn = visitors[node.type];
  if (fn) fn(node);

  for (const key in node) {
    if (!Object.prototype.hasOwnProperty.call(node, key)) continue;

    const child = node[key];

    if (Array.isArray(child)) {
      child.forEach(c => walk(c, visitors));
    } else if (child && typeof child.type === "string") {
      walk(child, visitors);
    }
  }
}

/* -----------------------------------------------------------------------
   8) Regex Fallback — compatível com qualquer navegador
------------------------------------------------------------------------ */
function scanDomByRegex(code) {
  const results = [];
  const xssVulnerabilities = [];

  // /document.getElementById("id")/
  const re1 = /document\.getElementById\s*\(\s*['"`]([A-Za-z0-9_\-]+)['"`]\s*\)/g;
  let m1;
  while ((m1 = re1.exec(code)) !== null) {
    const security = analyzeDomIdSecurity(m1[1], code, m1.index);
    const result = { 
      type: "getElementById", 
      id: m1[1], 
      index: m1.index,
      security: security
    };
    results.push(result);
    
    if (security.isDangerous) {
      xssVulnerabilities.push({
        type: "DOM_OPERATION",
        description: `getElementById('${m1[1]}') com risco XSS`,
        severity: security.xssRisk === "CRITICAL" ? "CRITICAL" : "HIGH",
        index: m1.index
      });
    }
  }

  // /document.querySelector("#id")/
  const re2 = /document\.querySelector\s*\(\s*['"`]#([A-Za-z0-9_\-]+)['"`]\s*\)/g;
  let m2;
  while ((m2 = re2.exec(code)) !== null) {
    const security = analyzeDomIdSecurity(m2[1], code, m2.index);
    const result = { 
      type: "querySelector", 
      id: m2[1], 
      index: m2.index,
      security: security
    };
    results.push(result);
    
    if (security.isDangerous) {
      xssVulnerabilities.push({
        type: "DOM_OPERATION",
        description: `querySelector('#${m2[1]}') com risco XSS`,
        severity: security.xssRisk === "CRITICAL" ? "CRITICAL" : "HIGH",
        index: m2.index
      });
    }
  }

  // /document.querySelectorAll("#id")/
  const re3 = /document\.querySelectorAll\s*\(\s*['"`]#([A-Za-z0-9_\-]+)['"`]\s*\)/g;
  let m3;
  while ((m3 = re3.exec(code)) !== null) {
    const security = analyzeDomIdSecurity(m3[1], code, m3.index);
    const result = { 
      type: "querySelectorAll", 
      id: m3[1], 
      index: m3.index,
      security: security
    };
    results.push(result);
    
    if (security.isDangerous) {
      xssVulnerabilities.push({
        type: "DOM_OPERATION",
        description: `querySelectorAll('#${m3[1]}') com risco XSS`,
        severity: security.xssRisk === "CRITICAL" ? "CRITICAL" : "HIGH",
        index: m3.index
      });
    }
  }
  
  // innerHTML assignments
  const innerHTMLRe = /\.innerHTML\s*=\s*[^;]+;/g;
  while ((m3 = innerHTMLRe.exec(code)) !== null) {
    xssVulnerabilities.push({
      type: "INNERHTML_XSS",
      description: "innerHTML assignment detected",
      severity: "HIGH",
      index: m3.index
    });
  }

  return {
    domOperations: results,
    xssVulnerabilities: xssVulnerabilities,
    security: {
      totalOperations: results.length,
      xssVulnerabilityCount: xssVulnerabilities.length,
      securityScore: calculateDomSecurityScore(results, xssVulnerabilities)
    }
  };
}

/* -----------------------------------------------------------------------
   9) Análise de segurança para IDs DOM (regex fallback)
------------------------------------------------------------------------ */
function analyzeDomIdSecurity(elementId, code, index) {
  const security = {
    isDangerous: false,
    isSuspicious: false,
    xssRisk: "LOW",
    reasons: [],
    recommendations: []
  };
  
  // Verificar IDs suspeitos
  const suspiciousIds = [
    'content', 'html', 'body', 'header', 'footer', 'main',
    'script', 'style', 'head', 'title', 'meta', 'link',
    'input', 'form', 'textarea', 'select', 'button',
    'user', 'admin', 'root', 'config', 'settings'
  ];
  
  if (suspiciousIds.includes(elementId.toLowerCase())) {
    security.isSuspicious = true;
    security.reasons.push(`Element ID '${elementId}' é suspeito`);
  }
  
  // Verificar innerHTML assignments próximos
  const contextStart = Math.max(0, index - 200);
  const contextEnd = Math.min(code.length, index + 200);
  const context = code.substring(contextStart, contextEnd);
  
  if (context.includes(elementId) && context.includes('.innerHTML')) {
    security.isDangerous = true;
    security.xssRisk = "HIGH";
    security.reasons.push(`Elemento #${elementId} tem atribuição innerHTML próxima`);
    security.recommendations.push(`Substituir innerHTML por textContent`);
  }
  
  if (context.includes(elementId) && context.includes('.outerHTML')) {
    security.isDangerous = true;
    security.xssRisk = "CRITICAL";
    security.reasons.push(`Elemento #${elementId} tem atribuição outerHTML próxima`);
    security.recommendations.push(`EVITAR outerHTML - risco extremo de XSS`);
  }
  
  return security;
}

/* -----------------------------------------------------------------------
   10) Função pública para análise de segurança DOM
------------------------------------------------------------------------ */
export function analyzeDomSecurity(domResult) {
  const operations = domResult.domOperations || domResult || [];
  const vulnerabilities = domResult.xssVulnerabilities || [];
  
  const analysis = {
    totalOperations: operations.length,
    xssVulnerabilities: vulnerabilities.length,
    dangerousOperations: [],
    suspiciousOperations: [],
    securityScore: 100,
    recommendations: []
  };
  
  operations.forEach(op => {
    if (op.security?.isDangerous) {
      analysis.dangerousOperations.push({
        type: op.type,
        id: op.id,
        reasons: op.security.reasons,
        xssRisk: op.security.xssRisk
      });
    }
    
    if (op.security?.isSuspicious) {
      analysis.suspiciousOperations.push({
        type: op.type,
        id: op.id,
        reasons: op.security.reasons
      });
    }
  });
  
  // Calcular score
  if (analysis.totalOperations > 0) {
    let penalty = analysis.dangerousOperations.length * 10;
    penalty += analysis.suspiciousOperations.length * 3;
    penalty += analysis.xssVulnerabilities.length * 15;
    analysis.securityScore = Math.max(0, 100 - Math.min(penalty, 100));
  }
  
  // Gerar recomendações
  if (analysis.dangerousOperations.length > 0) {
    analysis.recommendations.push(
      `Revisar ${analysis.dangerousOperations.length} operações DOM perigosas`
    );
    analysis.recommendations.push(
      'Substituir innerHTML/outerHTML por textContent quando possível'
    );
  }
  
  if (analysis.xssVulnerabilities.length > 0) {
    analysis.recommendations.push(
      `Corrigir ${analysis.xssVulnerabilities.length} vulnerabilidades XSS potenciais`
    );
    analysis.recommendations.push(
      'Implementar sanitização com DOMPurify para conteúdo HTML dinâmico'
    );
  }
  
  return analysis;
}