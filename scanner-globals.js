// scanner-globals.js
// Localiza variáveis e funções declaradas no ESCOPO GLOBAL.
// Usa Acorn + walker para precisão total, com fallback em regex.

export function scanGlobals(code, useAst = true) {
  const acorn = getAcorn();

  if (useAst && acorn) {
    try {
      const ast = acorn.parse(code, {
        ecmaVersion: "latest",
        sourceType: "script", // Script = modo clássico → permite globais reais
        locations: true
      });
      return scanGlobalsFromAST(ast);
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
    // eslint-disable-next-line no-undef
    if (typeof require === "function") return require("acorn");
  } catch (e) {}

  return null;
}

/* ------------------------------------------------------
   SCAN VIA AST — ultra preciso
------------------------------------------------------ */
function scanGlobalsFromAST(ast) {
  const globals = [];

  walk(ast, {
    VariableDeclaration(node, parent) {
      // var / let / const no topo do arquivo = global real
      if (parent.type === "Program") {
        for (const d of node.declarations) {
          if (d.id?.name) {
            globals.push({
              type: node.kind,        // var | let | const
              name: d.id.name,
              loc: node.loc
            });
          }
        }
      }
    },

    FunctionDeclaration(node, parent) {
      if (parent.type === "Program") {
        globals.push({
          type: "function",
          name: node.id?.name,
          loc: node.loc
        });
      }
    },

    // window.x = ...
    AssignmentExpression(node) {
      if (
        node.left?.type === "MemberExpression" &&
        node.left.object?.name === "window"
      ) {
        if (node.left.property?.name) {
          globals.push({
            type: "window-property",
            name: node.left.property.name,
            loc: node.loc
          });
        }
      }

      // globalThis.x = ...
      if (
        node.left?.type === "MemberExpression" &&
        node.left.object?.name === "globalThis"
      ) {
        if (node.left.property?.name) {
          globals.push({
            type: "globalThis-property",
            name: node.left.property.name,
            loc: node.loc
          });
        }
      }
    }
  });

  return globals;
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
   FALLBACK POR REGEX
   — funciona mesmo sem AST
------------------------------------------------------ */
function scanGlobalsByRegex(code) {
  const globals = [];

  // var x
  const reVar = /^var\s+([A-Za-z_$][\w$]*)/gm;
  let m;
  while ((m = reVar.exec(code))) {
    globals.push({ type: "var", name: m[1], index: m.index });
  }

  // let x
  const reLet = /^let\s+([A-Za-z_$][\w$]*)/gm;
  while ((m = reLet.exec(code))) {
    globals.push({ type: "let", name: m[1], index: m.index });
  }

  // const x
  const reConst = /^const\s+([A-Za-z_$][\w$]*)/gm;
  while ((m = reConst.exec(code))) {
    globals.push({ type: "const", name: m[1], index: m.index });
  }

  // function x()
  const reFunc = /^function\s+([A-Za-z_$][\w$]*)/gm;
  while ((m = reFunc.exec(code))) {
    globals.push({ type: "function", name: m[1], index: m.index });
  }

  // window.x
  const reWin = /window\.([A-Za-z_$][\w$]*)\s*=/g;
  while ((m = reWin.exec(code))) {
    globals.push({ type: "window-property", name: m[1], index: m.index });
  }

  // globalThis.x
  const reGlobal = /globalThis\.([A-Za-z_$][\w$]*)\s*=/g;
  while ((m = reGlobal.exec(code))) {
    globals.push({ type: "globalThis-property", name: m[1], index: m.index });
  }

  return globals;
}