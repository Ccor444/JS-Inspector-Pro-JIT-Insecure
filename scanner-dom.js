// scanner-dom.js
// Scanner DOM avançado com suporte a:
//  - AST (Acorn) ultra preciso
//  - Regex fallback (garante compatibilidade total)

export function scanDom(code, useAst = true) {
  const acorn = getAcorn();

  if (useAst && acorn) {
    try {
      const ast = acorn.parse(code, {
        ecmaVersion: "latest",
        sourceType: "module",
        locations: true
      });
      return collectDomFromAST(ast);
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
   2) Scanner via AST (o mais preciso que existe)
------------------------------------------------------------------------ */
function collectDomFromAST(ast) {
  const results = [];

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
          if (id) results.push({ type: "getElementById", id, loc: node.loc });
        }

        // querySelector('#id')
        if (method === "querySelector") {
          const selector = extractLiteral(arg);
          if (selector?.startsWith("#")) {
            results.push({
              type: "querySelector",
              id: selector.slice(1),
              loc: node.loc
            });
          }
        }

        // querySelectorAll('#id')
        if (method === "querySelectorAll") {
          const selector = extractLiteral(arg);
          if (selector?.startsWith("#")) {
            results.push({
              type: "querySelectorAll",
              id: selector.slice(1),
              loc: node.loc
            });
          }
        }
      }
    }
  });

  return results;
}

/* -----------------------------------------------------------------------
   3) Literal extractor (Literal, TemplateLiteral, etc.)
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
   4) AST Walker simples (não depende de libs externas)
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
   5) Regex Fallback — compatível com qualquer navegador
------------------------------------------------------------------------ */
function scanDomByRegex(code) {
  const results = [];

  // /document.getElementById("id")/
  const re1 = /document\.getElementById\s*\(\s*['"`]([A-Za-z0-9_\-]+)['"`]\s*\)/g;
  let m1;
  while ((m1 = re1.exec(code)) !== null) {
    results.push({ type: "getElementById", id: m1[1], index: m1.index });
  }

  // /document.querySelector("#id")/
  const re2 = /document\.querySelector\s*\(\s*['"`]#([A-Za-z0-9_\-]+)['"`]\s*\)/g;
  let m2;
  while ((m2 = re2.exec(code)) !== null) {
    results.push({ type: "querySelector", id: m2[1], index: m2.index });
  }

  // /document.querySelectorAll("#id")/
  const re3 = /document\.querySelectorAll\s*\(\s*['"`]#([A-Za-z0-9_\-]+)['"`]\s*\)/g;
  let m3;
  while ((m3 = re3.exec(code)) !== null) {
    results.push({ type: "querySelectorAll", id: m3[1], index: m3.index });
  }

  return results;
}