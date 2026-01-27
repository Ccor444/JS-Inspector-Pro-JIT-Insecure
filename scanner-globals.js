// scanner-globals.js
// Localiza variáveis e funções declaradas no ESCOPO GLOBAL.
// Usa Acorn + walker para precisão total, com fallback em regex.
// Versão Elite Security

export function scanGlobals(code, useAst = true) {
  const acorn = getAcorn();

  if (useAst && acorn) {
    try {
      const ast = acorn.parse(code, {
        ecmaVersion: "latest",
        sourceType: "script", // Script = modo clássico → permite globais reais
        locations: true
      });
      return scanGlobalsFromAST(ast, code);
    } catch (err) {
      console.warn("AST falhou, usando fallback regex:", err);
    }
  }

  return scanGlobalsByRegex(code);
}

/* ------------------------------------------------------
   Carregar Acorn (browser, Node, ou ambiente híbrido)
------------------------------------------------------ */
function getAcorn() {
  if (typeof window !== "undefined" && window.acorn) return window.acorn;

  try {
    if (typeof require === "function") return require("acorn");
  } catch (e) {}

  return null;
}

/* ------------------------------------------------------
   SCAN VIA AST — ultra preciso com análise de segurança
------------------------------------------------------ */
function scanGlobalsFromAST(ast, code) {
  const globals = [];
  const dangerousGlobals = [];

  walk(ast, {
    VariableDeclaration(node, parent) {
      if (parent.type === "Program") {
        for (const d of node.declarations) {
          if (d.id?.name) {
            const global = {
              type: node.kind,
              name: d.id.name,
              loc: node.loc,
              security: analyzeGlobalSecurity(d.id.name, code, node.loc)
            };
            globals.push(global);
            
            if (global.security.isDangerous) {
              dangerousGlobals.push(global);
            }
          }
        }
      }
    },

    FunctionDeclaration(node, parent) {
      if (parent.type === "Program") {
        const global = {
          type: "function",
          name: node.id?.name,
          loc: node.loc,
          security: analyzeGlobalSecurity(node.id?.name, code, node.loc)
        };
        globals.push(global);
        
        if (global.security.isDangerous) {
          dangerousGlobals.push(global);
        }
      }
    },

    AssignmentExpression(node) {
      // window.x = ...
      if (
        node.left?.type === "MemberExpression" &&
        node.left.object?.name === "window"
      ) {
        if (node.left.property?.name) {
          const global = {
            type: "window-property",
            name: node.left.property.name,
            loc: node.loc,
            security: analyzeGlobalSecurity(node.left.property.name, code, node.loc)
          };
          globals.push(global);
          
          if (global.security.isDangerous) {
            dangerousGlobals.push(global);
          }
        }
      }

      // globalThis.x = ...
      if (
        node.left?.type === "MemberExpression" &&
        node.left.object?.name === "globalThis"
      ) {
        if (node.left.property?.name) {
          const global = {
            type: "globalThis-property",
            name: node.left.property.name,
            loc: node.loc,
            security: analyzeGlobalSecurity(node.left.property.name, code, node.loc)
          };
          globals.push(global);
          
          if (global.security.isDangerous) {
            dangerousGlobals.push(global);
          }
        }
      }
      
      // x = ... (assignment global)
      if (node.left?.type === "Identifier") {
        const global = {
          type: "assignment",
          name: node.left.name,
          loc: node.loc,
          security: analyzeGlobalSecurity(node.left.name, code, node.loc)
        };
        globals.push(global);
        
        if (global.security.isDangerous) {
          dangerousGlobals.push(global);
        }
      }
    }
  });

  // Adicionar metadados de segurança
  return {
    globals,
    dangerousGlobals,
    security: {
      totalGlobals: globals.length,
      dangerousCount: dangerousGlobals.length,
      securityScore: calculateGlobalSecurityScore(globals)
    }
  };
}

/* ------------------------------------------------------
   Análise de segurança para variáveis globais
------------------------------------------------------ */
function analyzeGlobalSecurity(name, code, location) {
  const security = {
    isDangerous: false,
    isSuspicious: false,
    reasons: [],
    recommendations: []
  };
  
  // Verificar nomes suspeitos
  const suspiciousPatterns = [
    { pattern: /password/i, reason: 'Contém "password" - pode ser credencial' },
    { pattern: /secret/i, reason: 'Contém "secret" - pode ser informação sensível' },
    { pattern: /key/i, reason: 'Contém "key" - pode ser chave de API' },
    { pattern: /token/i, reason: 'Contém "token" - pode ser token de autenticação' },
    { pattern: /auth/i, reason: 'Contém "auth" - relacionado a autenticação' },
    { pattern: /credential/i, reason: 'Contém "credential" - credenciais' },
    { pattern: /api[_-]?key/i, reason: 'Parece ser chave de API' },
    { pattern: /private/i, reason: 'Contém "private" - informação privada' },
    { pattern: /config/i, reason: 'Contém "config" - configuração sensível' },
    { pattern: /settings/i, reason: 'Contém "settings" - configurações' }
  ];
  
  suspiciousPatterns.forEach(pattern => {
    if (pattern.pattern.test(name)) {
      security.isSuspicious = true;
      security.reasons.push(pattern.reason);
      security.recommendations.push(`Considerar mover '${name}' para variáveis de ambiente`);
    }
  });
  
  // Verificar se contém dados hardcoded no código
  if (location) {
    const startLine = location.start.line - 1;
    const endLine = location.end.line - 1;
    const lines = code.split('\n');
    
    for (let i = startLine; i <= endLine && i < lines.length; i++) {
      const line = lines[i];
      
      // Padrões de segredos hardcoded
      const secretPatterns = [
        /['"`][A-Za-z0-9+/]{40,}['"`]/, // Base64 longo
        /['"`][A-Fa-f0-9]{64,}['"`]/, // Hex longo
        /['"`]sk_live_[A-Za-z0-9]{24,}['"`]/, // Stripe key
        /['"`]AKIA[0-9A-Z]{16}['"`]/, // AWS key
        /['"`]gh[pousr]_[A-Za-z0-9_]{36,}['"`]/, // GitHub token
        /['"`]xox[baprs]-[0-9a-zA-Z]{10,48}['"`]/ // Slack token
      ];
      
      secretPatterns.forEach(pattern => {
        if (pattern.test(line)) {
          security.isDangerous = true;
          security.reasons.push('Possível segredo/chave hardcoded');
          security.recommendations.push(`REMOVER IMEDIATAMENTE: Segredo hardcoded detectado em '${name}'`);
        }
      });
    }
  }
  
  return security;
}

/* ------------------------------------------------------
   Calcular score de segurança para globais
------------------------------------------------------ */
function calculateGlobalSecurityScore(globals) {
  if (globals.length === 0) return 100;
  
  let score = 100;
  let dangerousCount = 0;
  let suspiciousCount = 0;
  
  globals.forEach(global => {
    if (global.security.isDangerous) {
      dangerousCount++;
      score -= 10;
    }
    if (global.security.isSuspicious) {
      suspiciousCount++;
      score -= 2;
    }
  });
  
  return Math.max(0, Math.min(100, Math.round(score)));
}

/* ------------------------------------------------------
   Small AST walker
------------------------------------------------------ */
function walk(node, visitors, parent = null) {
  if (!node || typeof node.type !== "string") return;
  const fn = visitors[node.type];
  if (fn) fn(node, parent);

  for (const key in node) {
    const child = node[key];
    if (Array.isArray(child)) {
      for (const c of child) walk(c, visitors, node);
    } else if (child && typeof child.type === "string") {
      walk(child, visitors, node);
    }
  }
}

/* ------------------------------------------------------
   FALLBACK POR REGEX com análise de segurança
------------------------------------------------------ */
function scanGlobalsByRegex(code) {
  const globals = [];
  const dangerousGlobals = [];

  // var x
  const reVar = /^var\s+([A-Za-z_$][\w$]*)/gm;
  let m;
  while ((m = reVar.exec(code))) {
    const global = createGlobalFromMatch('var', m[1], m.index, code);
    globals.push(global);
    if (global.security.isDangerous) dangerousGlobals.push(global);
  }

  // let x
  const reLet = /^let\s+([A-Za-z_$][\w$]*)/gm;
  while ((m = reLet.exec(code))) {
    const global = createGlobalFromMatch('let', m[1], m.index, code);
    globals.push(global);
    if (global.security.isDangerous) dangerousGlobals.push(global);
  }

  // const x
  const reConst = /^const\s+([A-Za-z_$][\w$]*)/gm;
  while ((m = reConst.exec(code))) {
    const global = createGlobalFromMatch('const', m[1], m.index, code);
    globals.push(global);
    if (global.security.isDangerous) dangerousGlobals.push(global);
  }

  // function x()
  const reFunc = /^function\s+([A-Za-z_$][\w$]*)/gm;
  while ((m = reFunc.exec(code))) {
    const global = createGlobalFromMatch('function', m[1], m.index, code);
    globals.push(global);
    if (global.security.isDangerous) dangerousGlobals.push(global);
  }

  // window.x
  const reWin = /window\.([A-Za-z_$][\w$]*)\s*=/g;
  while ((m = reWin.exec(code))) {
    const global = createGlobalFromMatch('window-property', m[1], m.index, code);
    globals.push(global);
    if (global.security.isDangerous) dangerousGlobals.push(global);
  }

  // globalThis.x
  const reGlobal = /globalThis\.([A-Za-z_$][\w$]*)\s*=/g;
  while ((m = reGlobal.exec(code))) {
    const global = createGlobalFromMatch('globalThis-property', m[1], m.index, code);
    globals.push(global);
    if (global.security.isDangerous) dangerousGlobals.push(global);
  }
  
  // assignment x = ...
  const reAssign = /^\s*([A-Za-z_$][\w$]*)\s*=\s*(?!function|\(|\[|\{)/gm;
  while ((m = reAssign.exec(code))) {
    const global = createGlobalFromMatch('assignment', m[1], m.index, code);
    globals.push(global);
    if (global.security.isDangerous) dangerousGlobals.push(global);
  }

  return {
    globals,
    dangerousGlobals,
    security: {
      totalGlobals: globals.length,
      dangerousCount: dangerousGlobals.length,
      securityScore: calculateGlobalSecurityScore(globals)
    }
  };
}

/* ------------------------------------------------------
   Helper para criar objeto global com análise de segurança
------------------------------------------------------ */
function createGlobalFromMatch(type, name, index, code) {
  // Extrair contexto do código
  const start = Math.max(0, index - 100);
  const end = Math.min(code.length, index + 100);
  const context = code.substring(start, end);
  
  const security = analyzeGlobalSecurity(name, context, {
    start: { line: 0, column: 0 },
    end: { line: 0, column: 0 }
  });
  
  return {
    type: type,
    name: name,
    index: index,
    security: security
  };
}

/* ------------------------------------------------------
   Função pública para análise de segurança de globais
------------------------------------------------------ */
export function analyzeGlobalsSecurity(globalsResult) {
  const globals = Array.isArray(globalsResult) ? globalsResult : globalsResult.globals || [];
  
  const analysis = {
    totalGlobals: globals.length,
    dangerousGlobals: [],
    suspiciousGlobals: [],
    securityScore: 100,
    recommendations: []
  };
  
  globals.forEach(global => {
    if (global.security?.isDangerous) {
      analysis.dangerousGlobals.push({
        name: global.name,
        type: global.type,
        reasons: global.security.reasons
      });
    }
    
    if (global.security?.isSuspicious) {
      analysis.suspiciousGlobals.push({
        name: global.name,
        type: global.type,
        reasons: global.security.reasons
      });
    }
  });
  
  // Calcular score
  if (analysis.totalGlobals > 0) {
    let penalty = analysis.dangerousGlobals.length * 15;
    penalty += analysis.suspiciousGlobals.length * 5;
    analysis.securityScore = Math.max(0, 100 - Math.min(penalty, 100));
  }
  
  // Gerar recomendações
  if (analysis.dangerousGlobals.length > 0) {
    analysis.recommendations.push(
      `Remover ${analysis.dangerousGlobals.length} variáveis globais com segredos hardcoded`
    );
    analysis.recommendations.push(
      'Mover todas as chaves e segredos para variáveis de ambiente'
    );
  }
  
  if (analysis.suspiciousGlobals.length > 0) {
    analysis.recommendations.push(
      `Revisar ${analysis.suspiciousGlobals.length} variáveis globais com nomes suspeitos`
    );
    analysis.recommendations.push(
      'Evitar nomes que indiquem informações sensíveis em variáveis globais'
    );
  }
  
  return analysis;
}