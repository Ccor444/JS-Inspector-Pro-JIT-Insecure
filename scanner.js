
const DEFAULT_OPTIONS = {
  useAcorn: true,
  ecmaVersion: 'latest',
  sourceType: 'module',
  includeLocations: true,
  regexFallback: true,
  securityScan: true // Nova opção para análise de segurança
};

// Utility: safe access to acorn
function getAcorn() {
  if (typeof window !== 'undefined' && window.acorn) return window.acorn;
  try {
    if (typeof require === 'function') {
      return require('acorn');
    }
  } catch (e) {}
  return null;
}

// Lightweight AST walker (recursive). Calls visitor[type](node, parent)
function walk(node, visitors, parent = null) {
  if (!node || typeof node.type !== 'string') return;
  const fn = visitors[node.type];
  if (fn) {
    try { fn(node, parent); } catch (e) { /* visitor error should not stop walk */ }
  }
  for (const k in node) {
    if (!Object.prototype.hasOwnProperty.call(node, k)) continue;
    const child = node[k];
    if (Array.isArray(child)) {
      for (const c of child) walk(c, visitors, node);
    } else if (child && typeof child.type === 'string') {
      walk(child, visitors, node);
    }
  }
}

// Nova função: Detectar vulnerabilidades de segurança
function detectSecurityVulnerabilities(ast, sourceCode) {
  const vulnerabilities = [];
  
  const securityVisitors = {
    CallExpression(node) {
      // Detectar eval()
      if (node.callee && node.callee.type === 'Identifier' && node.callee.name === 'eval') {
        vulnerabilities.push({
          type: 'EVAL_USAGE',
          severity: 'CRITICAL',
          description: 'eval() permite execução arbitrária de código',
          location: node.loc,
          mitigation: 'Substituir por JSON.parse() ou evitar completamente'
        });
      }
      
      // Detectar new Function()
      if (node.callee && 
          node.callee.type === 'NewExpression' && 
          node.callee.callee && 
          node.callee.callee.name === 'Function') {
        vulnerabilities.push({
          type: 'FUNCTION_CONSTRUCTOR',
          severity: 'HIGH',
          description: 'Function constructor similar a eval()',
          location: node.loc,
          mitigation: 'Evitar construtores dinâmicos de função'
        });
      }
      
      // Detectar innerHTML assignments
      if (node.callee && node.callee.type === 'MemberExpression') {
        if (node.callee.property && 
            (node.callee.property.name === 'innerHTML' || 
             node.callee.property.name === 'outerHTML')) {
          vulnerabilities.push({
            type: 'INNERHTML_ASSIGNMENT',
            severity: 'HIGH',
            description: 'innerHTML/outerHTML pode causar XSS',
            location: node.loc,
            mitigation: 'Usar textContent ou sanitizar com DOMPurify'
          });
        }
      }
    },
    
    AssignmentExpression(node) {
      // Detectar prototype pollution
      if (node.left && 
          node.left.type === 'MemberExpression' &&
          node.left.property &&
          (node.left.property.name === '__proto__' || 
           node.left.property.name === 'constructor' ||
           node.left.property.name === 'prototype')) {
        vulnerabilities.push({
          type: 'PROTOTYPE_POLLUTION',
          severity: 'CRITICAL',
          description: 'Manipulação de prototype pode levar a RCE',
          location: node.loc,
          mitigation: 'Validar objetos antes de manipular prototypes'
        });
      }
    },
    
    TemplateLiteral(node) {
      // Detectar possíveis SQL injection patterns
      const templateText = sourceCode.slice(node.start, node.end);
      if (templateText.includes('SELECT') && 
          templateText.includes('${') &&
          !templateText.includes('?')) {
        vulnerabilities.push({
          type: 'SQL_INJECTION_PATTERN',
          severity: 'HIGH',
          description: 'Template strings em queries podem causar SQL Injection',
          location: node.loc,
          mitigation: 'Usar prepared statements ou query builders'
        });
      }
    }
  };
  
  walk(ast, securityVisitors);
  return vulnerabilities;
}

/* -------------------------
   CORE COLLECTORS (AST)
   ------------------------- */
function collectFromAST(ast, sourceCode, options) {
  const res = {
    classes: [],
    functions: [],
    arrows: [],
    globals: [],
    domIds: [],
    imports: [],
    exports: [],
    vulnerabilities: [],
    ast
  };

  const visitors = {
    ClassDeclaration(node) {
      res.classes.push({ 
        name: node.id ? node.id.name : '(anonymous)', 
        loc: node.loc && node.loc.start ? node.loc.start : null 
      });
      
      // collect methods
      if (node.body && node.body.body) {
        for (const m of node.body.body) {
          if (m.type === 'MethodDefinition') {
            const methodName = (m.key && (m.key.name || (m.key.value))) || '(computed)';
            res.functions.push({ 
              name: `${node.id ? node.id.name : '(class)'}::${methodName}`, 
              loc: m.loc && m.loc.start ? m.loc.start : null, 
              method: true 
            });
          }
        }
      }
    },

    FunctionDeclaration(node) {
      if (node.id && node.id.name) res.functions.push({ 
        name: node.id.name, 
        loc: node.loc && node.loc.start ? node.loc.start : null 
      });
    },

    VariableDeclaration(node) {
      for (const decl of node.declarations || []) {
        if (decl.id && decl.id.type === 'Identifier') {
          const name = decl.id.name;
          if (decl.init && decl.init.type === 'ArrowFunctionExpression') {
            res.arrows.push({ 
              name, 
              loc: decl.loc && decl.loc.start ? decl.loc.start : null 
            });
          } else {
            res.globals.push({ 
              name, 
              kind: node.kind, 
              loc: decl.loc && decl.loc.start ? decl.loc.start : null 
            });
          }
        }
      }
    },

    AssignmentExpression(node) {
      // capture window.X = ... or globalThis.X = ...
      if (node.left && node.left.type === 'MemberExpression') {
        const obj = node.left.object;
        const prop = node.left.property;
        if (obj && obj.type === 'Identifier' && (obj.name === 'window' || obj.name === 'globalThis')) {
          res.globals.push({ 
            name: prop && (prop.name || prop.value) || '(computed)', 
            kind: 'assignment', 
            loc: node.loc && node.loc.start ? node.loc.start : null 
          });
        }
      }
      
      // capture plain assignment to identifier at top-level (simple heuristic)
      if (node.left && node.left.type === 'Identifier') {
        res.globals.push({ 
          name: node.left.name, 
          kind: 'assignment', 
          loc: node.left.loc && node.left.loc.start ? node.loc.start : null 
        });
      }
    },

    CallExpression(node) {
      // document.getElementById('id')
      if (node.callee && node.callee.type === 'MemberExpression') {
        const obj = node.callee.object;
        const prop = node.callee.property;
        if (obj && obj.type === 'Identifier' && obj.name === 'document' &&
            prop && (prop.name === 'getElementById')) {
          const arg = node.arguments && node.arguments[0];
          if (arg) {
            if (arg.type === 'Literal') {
              res.domIds.push({ 
                id: arg.value, 
                loc: node.loc && node.loc.start ? node.loc.start : null 
              });
            } else if (arg.type === 'TemplateLiteral' && arg.quasis && arg.quasis[0]) {
              res.domIds.push({ 
                id: arg.quasis[0].value.raw, 
                loc: node.loc && node.loc.start ? node.loc.start : null 
              });
            }
          }
        }
      }
    },

    ImportDeclaration(node) {
      if (node.source && node.source.value) res.imports.push(node.source.value);
    },

    ExportNamedDeclaration(node) {
      if (node.source && node.source.value) res.exports.push(node.source.value);
      if (node.declaration && node.declaration.declarations) {
        for (const d of node.declaration.declarations) if (d.id && d.id.name) res.exports.push(d.id.name);
      }
    },

    ExportDefaultDeclaration(node) {
      res.exports.push('default');
    }
  };

  try {
    walk(ast, visitors);
    
    // Adicionar análise de segurança se habilitado
    if (options.securityScan) {
      res.vulnerabilities = detectSecurityVulnerabilities(ast, sourceCode);
    }
  } catch (e) {
    console.warn('collector walk error', e);
  }

  return res;
}

/* -------------------------
   REGEX FALLBACK COLLECTORS
   ------------------------- */
function scanClassesByRegex(code) {
  const results = [];
  const re = /\bclass\s+([A-Za-z_$][\w$]*)/g;
  let m;
  while ((m = re.exec(code)) !== null) {
    results.push({ name: m[1], index: m.index });
  }
  return results;
}

function scanFunctionsByRegex(code) {
  const results = [];
  const re = /\bfunction\s+([A-Za-z_$][\w$]*)\s*\(/g;
  let m;
  while ((m = re.exec(code)) !== null) {
    results.push({ name: m[1], index: m.index });
  }
  return results;
}

function scanArrowsByRegex(code) {
  const results = [];
  const re = /([A-Za-z_$][\w$]*)\s*=\s*\([^)]*\)\s*=>/g;
  let m;
  while ((m = re.exec(code)) !== null) {
    results.push({ name: m[1], index: m.index });
  }
  return results;
}

function scanGlobalsByRegex(code) {
  const results = [];
  const re = /^(?:var|let|const)\s+([A-Za-z_$][\w$]*)/gm;
  let m;
  while ((m = re.exec(code)) !== null) {
    results.push({ name: m[1], kind: (m[0].split(/\s+/)[0] || 'var'), index: m.index });
  }
  // also assignment style
  const reAssign = /^\s*([A-Za-z_$][\w$]*)\s*=/gm;
  while ((m = reAssign.exec(code)) !== null) {
    results.push({ name: m[1], kind: 'assignment', index: m.index });
  }
  return results;
}

function scanDomByRegex(code) {
  const results = [];
  const re = /document\.getElementById\s*\(\s*['"`]([A-Za-z0-9_\-]+)['"`]\s*\)/g;
  let m;
  while ((m = re.exec(code)) !== null) {
    results.push({ id: m[1], index: m.index });
  }
  return results;
}

// Nova função: Detectar vulnerabilidades por regex (fallback)
function detectVulnerabilitiesByRegex(code) {
  const vulnerabilities = [];
  
  // Detectar eval()
  const evalRe = /eval\s*\([^)]*\)/g;
  let m;
  while ((m = evalRe.exec(code)) !== null) {
    vulnerabilities.push({
      type: 'EVAL_USAGE',
      severity: 'CRITICAL',
      description: 'eval() permite execução arbitrária de código',
      index: m.index,
      mitigation: 'Substituir por JSON.parse() ou evitar completamente'
    });
  }
  
  // Detectar new Function()
  const funcRe = /new\s+Function\s*\(/g;
  while ((m = funcRe.exec(code)) !== null) {
    vulnerabilities.push({
      type: 'FUNCTION_CONSTRUCTOR',
      severity: 'HIGH',
      description: 'Function constructor similar a eval()',
      index: m.index,
      mitigation: 'Evitar construtores dinâmicos de função'
    });
  }
  
  // Detectar innerHTML
  const innerHtmlRe = /\.innerHTML\s*=/g;
  while ((m = innerHtmlRe.exec(code)) !== null) {
    vulnerabilities.push({
      type: 'INNERHTML_ASSIGNMENT',
      severity: 'HIGH',
      description: 'innerHTML pode causar XSS',
      index: m.index,
      mitigation: 'Usar textContent ou sanitizar com DOMPurify'
    });
  }
  
  // Detectar hardcoded secrets (padrões simples)
  const secretRe = /['"`](?:[A-Za-z0-9+/]{40,}|[A-Fa-f0-9]{64,}|sk_live_[A-Za-z0-9]{24,})['"`]/g;
  while ((m = secretRe.exec(code)) !== null) {
    vulnerabilities.push({
      type: 'HARDCODED_SECRET',
      severity: 'CRITICAL',
      description: 'Possível segredo/chave de API hardcoded',
      index: m.index,
      mitigation: 'Mover para variáveis de ambiente ou secret manager'
    });
  }
  
  return vulnerabilities;
}

/* -------------------------
   PUBLIC API
   ------------------------- */

// scans using AST when possible, otherwise regex fallback
export function runScanner(code, opts = {}) {
  const options = Object.assign({}, DEFAULT_OPTIONS, opts || {});
  const acorn = options.useAcorn ? getAcorn() : null;

  if (!code || typeof code !== 'string') {
    throw new TypeError('runScanner expects `code` string');
  }

  // Try AST parse if acorn present
  if (acorn) {
    try {
      const parseOpts = {
        ecmaVersion: options.ecmaVersion === 'latest' ? 'latest' : options.ecmaVersion,
        sourceType: options.sourceType || 'module',
        locations: !!options.includeLocations,
        ranges: false
      };
      const ast = acorn.parse(code, parseOpts);
      const collected = collectFromAST(ast, code, options);
      return { 
        success: true, 
        engine: 'acorn', 
        ast, 
        result: collected,
        security: {
          vulnerabilities: collected.vulnerabilities,
          vulnerabilityCount: collected.vulnerabilities.length,
          criticalCount: collected.vulnerabilities.filter(v => v.severity === 'CRITICAL').length
        }
      };
    } catch (err) {
      if (!options.regexFallback) {
        return { success: false, engine: 'acorn', error: err.toString() };
      }
    }
  }

  // Regex fallback collectors
  const classes = scanClassesByRegex(code);
  const funcs = scanFunctionsByRegex(code);
  const arrows = scanArrowsByRegex(code);
  const globals = scanGlobalsByRegex(code);
  const domIds = scanDomByRegex(code);
  
  // Detectar vulnerabilidades por regex
  const vulnerabilities = options.securityScan ? detectVulnerabilitiesByRegex(code) : [];

  const result = {
    classes: classes.map(c => ({ name: c.name, index: c.index })),
    functions: funcs.map(f => ({ name: f.name, index: f.index })),
    arrows: arrows.map(a => ({ name: a.name, index: a.index })),
    globals: globals.map(g => ({ name: g.name, kind: g.kind, index: g.index })),
    domIds: domIds.map(d => ({ id: d.id, index: d.index })),
    imports: [],
    exports: [],
    vulnerabilities: vulnerabilities
  };

  return { 
    success: true, 
    engine: 'regex', 
    result,
    security: {
      vulnerabilities: vulnerabilities,
      vulnerabilityCount: vulnerabilities.length,
      criticalCount: vulnerabilities.filter(v => v.severity === 'CRITICAL').length
    }
  };
}

// Individual exports (useful if you want to split files later)
export function scanClasses(code, useAst = true) {
  const acorn = getAcorn();
  if (useAst && acorn) {
    try {
      const ast = acorn.parse(code, { ecmaVersion: 'latest', sourceType: 'module', locations: true });
      const c = collectFromAST(ast, code, { securityScan: false });
      return c.classes || [];
    } catch (e) { /* ignore and fallback */ }
  }
  return scanClassesByRegex(code);
}

export function scanFunctions(code, useAst = true) {
  const acorn = getAcorn();
  if (useAst && acorn) {
    try {
      const ast = acorn.parse(code, { ecmaVersion: 'latest', sourceType: 'module', locations: true });
      const c = collectFromAST(ast, code, { securityScan: false });
      return c.functions || [];
    } catch (e) { /* ignore and fallback */ }
  }
  return scanFunctionsByRegex(code);
}

export function scanGlobals(code, useAst = true) {
  const acorn = getAcorn();
  if (useAst && acorn) {
    try {
      const ast = acorn.parse(code, { ecmaVersion: 'latest', sourceType: 'module', locations: true });
      const c = collectFromAST(ast, code, { securityScan: false });
      return c.globals || [];
    } catch (e) { /* ignore and fallback */ }
  }
  return scanGlobalsByRegex(code);
}

export function scanDom(code, useAst = true) {
  const acorn = getAcorn();
  if (useAst && acorn) {
    try {
      const ast = acorn.parse(code, { ecmaVersion: 'latest', sourceType: 'module', locations: true });
      const c = collectFromAST(ast, code, { securityScan: false });
      return c.domIds || [];
    } catch (e) { /* ignore and fallback */ }
  }
  return scanDomByRegex(code);
}

// Nova função: Scanner de segurança dedicado
export function scanSecurity(code) {
  const vulnerabilities = detectVulnerabilitiesByRegex(code);
  
  // Análise adicional de padrões perigosos
  const dangerousPatterns = [
    { pattern: /document\.write/, name: 'DOCUMENT_WRITE', severity: 'MEDIUM' },
    { pattern: /setTimeout\s*\([^,)]*\)/, name: 'DYNAMIC_TIMEOUT', severity: 'MEDIUM' },
    { pattern: /setInterval\s*\([^,)]*\)/, name: 'DYNAMIC_INTERVAL', severity: 'MEDIUM' },
    { pattern: /location\s*=/, name: 'LOCATION_REDIRECT', severity: 'MEDIUM' },
    { pattern: /window\.open/, name: 'WINDOW_OPEN', severity: 'MEDIUM' },
    { pattern: /postMessage/, name: 'POST_MESSAGE', severity: 'MEDIUM' },
    { pattern: /localStorage/, name: 'LOCAL_STORAGE', severity: 'LOW' },
    { pattern: /sessionStorage/, name: 'SESSION_STORAGE', severity: 'LOW' },
    { pattern: /cookie/, name: 'COOKIE_ACCESS', severity: 'LOW' }
  ];
  
  dangerousPatterns.forEach(pattern => {
    if (pattern.pattern.test(code)) {
      vulnerabilities.push({
        type: pattern.name,
        severity: pattern.severity,
        description: `Uso de ${pattern.name.toLowerCase()} detectado`,
        mitigation: 'Validar e sanitizar entradas/saídas'
      });
    }
  });
  
  // Calcular score de segurança (0-100)
  let score = 100;
  vulnerabilities.forEach(v => {
    switch(v.severity) {
      case 'CRITICAL': score -= 20; break;
      case 'HIGH': score -= 10; break;
      case 'MEDIUM': score -= 5; break;
      case 'LOW': score -= 2; break;
    }
  });
  score = Math.max(0, Math.min(100, score));
  
  // Determinar classificação
  let grade = 'A';
  if (score >= 90) grade = 'A';
  else if (score >= 80) grade = 'B';
  else if (score >= 70) grade = 'C';
  else if (score >= 60) grade = 'D';
  else grade = 'F';
  
  return {
    vulnerabilities,
    score,
    grade,
    criticalCount: vulnerabilities.filter(v => v.severity === 'CRITICAL').length,
    highCount: vulnerabilities.filter(v => v.severity === 'HIGH').length,
    mediumCount: vulnerabilities.filter(v => v.severity === 'MEDIUM').length,
    lowCount: vulnerabilities.filter(v => v.severity === 'LOW').length
  };
}

