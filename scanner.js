// src/scanner/scanner.js
// ES module — Orquestrador e coletores principais do scanner
// Usa Acorn (se disponível no ambiente) para gerar AST; tem fallback por regex.
// Exports: runScanner, scanClasses, scanFunctions, scanGlobals, scanDom

// USO:
// import { runScanner } from './scanner.js';
// const result = runScanner(code); // { ast, classes, functions, arrows, globals, domIds, imports, exports }

const DEFAULT_OPTIONS = {
  useAcorn: true,     // tenta usar acorn.parse se presente
  ecmaVersion: 'latest',
  sourceType: 'module',
  includeLocations: true,
  regexFallback: true // se parser falhar, tenta análise por regex
};

// Utility: safe access to acorn
function getAcorn() {
  if (typeof window !== 'undefined' && window.acorn) return window.acorn;
  try {
    // In Node, user may have acorn installed
    // NOTE: dynamic require only works in CommonJS; we try-catch for safety.
    // If running as pure ES module in Node, user should provide acorn via global or pre-import.
    // We avoid throwing if not present.
    // eslint-disable-next-line no-undef
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

/* -------------------------
   CORE COLLECTORS (AST)
   ------------------------- */
function collectFromAST(ast) {
  const res = {
    classes: [],     // { name, loc }
    functions: [],   // { name, loc }
    arrows: [],      // { name, loc }
    globals: [],     // { name, kind, loc }  kind: var|let|const|assignment
    domIds: [],      // { id, loc }
    imports: [],     // strings
    exports: [],     // strings
    ast // include AST for reference
  };

  const visitors = {
    ClassDeclaration(node) {
      res.classes.push({ name: node.id ? node.id.name : '(anonymous)', loc: node.loc && node.loc.start ? node.loc.start : null });
      // collect methods
      if (node.body && node.body.body) {
        for (const m of node.body.body) {
          if (m.type === 'MethodDefinition') {
            const methodName = (m.key && (m.key.name || (m.key.value))) || '(computed)';
            res.functions.push({ name: `${node.id ? node.id.name : '(class)'}::${methodName}`, loc: m.loc && m.loc.start ? m.loc.start : null, method: true });
          }
        }
      }
    },

    FunctionDeclaration(node) {
      if (node.id && node.id.name) res.functions.push({ name: node.id.name, loc: node.loc && node.loc.start ? node.loc.start : null });
    },

    VariableDeclaration(node) {
      // Note: we do not try to perfectly decide scope here in this collector;
      // more advanced scope analysis would be required to only list true top-level globals.
      for (const decl of node.declarations || []) {
        // simple identifier
        if (decl.id && decl.id.type === 'Identifier') {
          const name = decl.id.name;
          if (decl.init && decl.init.type === 'ArrowFunctionExpression') {
            res.arrows.push({ name, loc: decl.loc && decl.loc.start ? decl.loc.start : null });
          } else {
            res.globals.push({ name, kind: node.kind, loc: decl.loc && decl.loc.start ? decl.loc.start : null });
          }
        }
        // skip patterns (destructuring) for now
      }
    },

    AssignmentExpression(node) {
      // capture window.X = ... or globalThis.X = ...
      if (node.left && node.left.type === 'MemberExpression') {
        const obj = node.left.object;
        const prop = node.left.property;
        if (obj && obj.type === 'Identifier' && (obj.name === 'window' || obj.name === 'globalThis')) {
          res.globals.push({ name: prop && (prop.name || prop.value) || '(computed)', kind: 'assignment', loc: node.loc && node.loc.start ? node.loc.start : null });
        }
      }
      // capture plain assignment to identifier at top-level (simple heuristic)
      if (node.left && node.left.type === 'Identifier') {
        res.globals.push({ name: node.left.name, kind: 'assignment', loc: node.left.loc && node.left.loc.start ? node.left.loc.start : null });
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
              res.domIds.push({ id: arg.value, loc: node.loc && node.loc.start ? node.loc.start : null });
            } else if (arg.type === 'TemplateLiteral' && arg.quasis && arg.quasis[0]) {
              res.domIds.push({ id: arg.quasis[0].value.raw, loc: node.loc && node.loc.start ? node.loc.start : null });
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
  } catch (e) {
    // shouldn't happen, but keep safe
    console.warn('collector walk error', e);
  }

  return res;
}

/* -------------------------
   REGEX FALLBACK COLLECTORS
   (less precise, kept for environments without acorn)
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
      // acorn.parse may be available under different names in some builds (acorn.parse)
      const parseOpts = {
        ecmaVersion: options.ecmaVersion === 'latest' ? 'latest' : options.ecmaVersion,
        sourceType: options.sourceType || 'module',
        locations: !!options.includeLocations,
        ranges: false
      };
      const ast = acorn.parse(code, parseOpts);
      const collected = collectFromAST(ast);
      return { success: true, engine: 'acorn', ast, result: collected };
    } catch (err) {
      // parsing failed: fall back to regex if allowed
      if (!options.regexFallback) {
        return { success: false, engine: 'acorn', error: err.toString() };
      }
      // continue to regex fallback below
    }
  }

  // Regex fallback collectors
  const classes = scanClassesByRegex(code);
  const funcs = scanFunctionsByRegex(code);
  const arrows = scanArrowsByRegex(code);
  const globals = scanGlobalsByRegex(code);
  const domIds = scanDomByRegex(code);

  const result = {
    classes: classes.map(c => ({ name: c.name, index: c.index })),
    functions: funcs.map(f => ({ name: f.name, index: f.index })),
    arrows: arrows.map(a => ({ name: a.name, index: a.index })),
    globals: globals.map(g => ({ name: g.name, kind: g.kind, index: g.index })),
    domIds: domIds.map(d => ({ id: d.id, index: d.index })),
    imports: [],
    exports: []
  };

  return { success: true, engine: 'regex', result };
}

// Individual exports (useful if you want to split files later)
export function scanClasses(code, useAst = true) {
  const acorn = getAcorn();
  if (useAst && acorn) {
    try {
      const ast = acorn.parse(code, { ecmaVersion: 'latest', sourceType: 'module', locations: true });
      const c = collectFromAST(ast);
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
      const c = collectFromAST(ast);
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
      const c = collectFromAST(ast);
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
      const c = collectFromAST(ast);
      return c.domIds || [];
    } catch (e) { /* ignore and fallback */ }
  }
  return scanDomByRegex(code);
}

/* -------------------------
   END OF FILE
   ------------------------- */