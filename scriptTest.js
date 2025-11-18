// scriptTest.js — Ultra DEV (versão completa e integrada)
// Usa todos os scanners: scanner-globals, scanner-functions, scanner-classes, scanner-dom, scanner.js
// Fornece análise completa + sandbox virtual + execução simulada.

// IMPORTS (garanta que os arquivos existam e exportem os nomes abaixo)
import { scanGlobals } from "./scanner-globals.js";
import { scanFunctions } from "./scanner-functions.js";
import { scanClasses } from "./scanner-classes.js";
import { scanDom } from "./scanner-dom.js";
import { runScanner } from "./scanner.js"; // master scanner (AST-capable)

// ----------------------------
// 1) DETECÇÃO AVANÇADA DE FUNÇÕES
// ----------------------------
export function analyzeExecutableFunctions(src) {
  const functions = [];

  // regexes para capturar várias formas de definição
  const fnRegex = /function\s+([A-Za-z$_][\w$]*)\s*\(([^)]*)\)\s*{/g;
  const arrowRegex = /(?:const|let|var)\s+([A-Za-z$_][\w$]*)\s*=\s*\(?([^)]*)\)?\s*=>/g;
  const assignedRegex = /(?:const|let|var)\s+([A-Za-z$_][\w$]*)\s*=\s*function\s*\(([^)]*)\)/g;
  const methodRegex = /(?:^|[\s{;])([A-Za-z$_][\w$]*)\s*\(([^)]*)\)\s*{/gm; // methods in classes/objects
  const asyncFnRegex = /async\s+function\s+([A-Za-z$_][\w$]*)\s*\(([^)]*)\)/g;

  let m;

  while ((m = fnRegex.exec(src))) {
    functions.push({ name: m[1], params: splitParams(m[2]), type: "function", index: m.index });
  }
  while ((m = arrowRegex.exec(src))) {
    functions.push({ name: m[1], params: splitParams(m[2]), type: "arrow", index: m.index });
  }
  while ((m = assignedRegex.exec(src))) {
    functions.push({ name: m[1], params: splitParams(m[2]), type: "assigned", index: m.index });
  }
  // methods (careful with false positives; filter keywords)
  while ((m = methodRegex.exec(src))) {
    const name = m[1];
    if (!isReservedKeyword(name)) {
      functions.push({ name, params: splitParams(m[2]), type: "method", index: m.index });
    }
  }
  while ((m = asyncFnRegex.exec(src))) {
    functions.push({ name: m[1], params: splitParams(m[2]), type: "async", index: m.index });
  }

  return dedupeByName(functions);
}

// ----------------------------
// helpers used above
// ----------------------------
function splitParams(paramStr) {
  if (!paramStr) return [];
  // handle default values, rest params naively
  return paramStr.split(",").map(p => p.trim()).filter(Boolean);
}
function isReservedKeyword(name) {
  return ["if", "for", "while", "switch", "catch", "try", "return", "class", "new"].includes(name);
}
function dedupeByName(arr) {
  const seen = new Map();
  for (const it of arr) {
    if (!seen.has(it.name)) seen.set(it.name, it);
    else {
      // keep the earliest (lowest index)
      const prev = seen.get(it.name);
      if ((it.index || 0) < (prev.index || 1e9)) seen.set(it.name, it);
    }
  }
  return Array.from(seen.values());
}

// ----------------------------
// 2) ATRIBUTOS AVANÇADOS POR FUNÇÃO (usa snippet da fonte)
// ----------------------------
export function analyzeFunctionAttributes(src, functions) {
  // Accepts functions either as array of names or objects {name,...}
  const funcs = functions.map(f => (typeof f === "string" ? { name: f } : f));
  return funcs.map(fn => {
    const name = fn.name;
    // find index of declaration / first occurrence
    const re = new RegExp(`\\b${escapeRegexSafe(name)}\\b`, "g");
    const idx = src.search(re);
    if (idx === -1) {
      return { ...fn, usesDOM: false, isAsync: false, returnsPromise: false, usesTryCatch: false, callsOtherFunctions: [] };
    }
    const snippet = src.slice(Math.max(0, idx - 40), Math.min(src.length, idx + 800));
    return {
      ...fn,
      usesDOM: /document\./.test(snippet) || /window\./.test(snippet),
      isAsync: /async/.test(snippet) || /\bawait\b/.test(snippet),
      returnsPromise: /new\s+Promise/.test(snippet) || /\bthen\(/.test(snippet),
      usesTryCatch: /try\s*{/.test(snippet),
      callsOtherFunctions: extractCalledFunctions(snippet).filter(n => n !== name)
    };
  });
}

function extractCalledFunctions(snippet) {
  const calls = new Set();
  const callRe = /([A-Za-z$_][\w$]*)\s*\(/g;
  let mm;
  while ((mm = callRe.exec(snippet))) {
    const n = mm[1];
    if (!isReservedKeyword(n)) calls.add(n);
  }
  return Array.from(calls);
}

// ----------------------------
// SAFE regex escape
// ----------------------------
function escapeRegexSafe(s) {
  if (typeof s !== 'string') return '';
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// ----------------------------
// 3) INTEGRATED FULL ANALYSIS (uses all scanners)
// ----------------------------
export function analyzeFullJS(sourceCode) {
  let master = null;
  try {
    if (typeof runScanner === "function") {
      const r = runScanner(sourceCode);
      if (r && r.success && r.result) {
        master = r.result;
      }
    }
  } catch (e) {
    master = null;
  }

  const classes = (master && master.classes) ? master.classes : scanClasses(sourceCode);
  const functions = (master && master.functions) ? master.functions : scanFunctions(sourceCode);
  const globals = (master && master.globals) ? master.globals : scanGlobals(sourceCode);
  const dom = (master && master.domIds) ? master.domIds : scanDom(sourceCode);

  const execFuncs = analyzeExecutableFunctions(sourceCode);
  const execAttrs = analyzeFunctionAttributes(sourceCode, execFuncs);

  return {
    classes,
    functions,
    globals,
    dom,
    execFunctions: execAttrs,
    meta: {
      engine: (master && master.ast) ? "acorn" : "regex",
      timestamp: Date.now()
    }
  };
}

// ----------------------------
// 4) SMART SANDBOX CREATION
// ----------------------------
export function createSmartSandbox(analysis) {
  const sandbox = {};

  const execList = (analysis.execFunctions || []).map(f => (typeof f === "string" ? { name: f } : f));
  execList.forEach(fn => {
    sandbox[fn.name] = (...args) => ({
      result: `Simulação: função '${fn.name}' executada (sandbox).`,
      args,
      meta: fn,
      timestamp: Date.now()
    });
  });

  (analysis.classes || []).forEach(cls => {
    const clsName = (cls && (cls.name || cls.id && cls.id.name)) || (typeof cls === 'string' ? cls : null);
    const methods = cls && cls.methods ? cls.methods : (cls && cls.body && cls.body.methods ? cls.body.methods : []);
    (methods || []).forEach(m => {
      const mName = (typeof m === 'string') ? m : (m && (m.name || (m.key && m.key.name)));
      if (!mName) return;
      sandbox[`${clsName}.${mName}`] = (...args) => ({
        result: `Simulação: método '${clsName}.${mName}' executado (sandbox).`,
        args, timestamp: Date.now()
      });
    });
  });

  (analysis.dom || []).forEach(d => {
    const id = d.id || d.element || d.name;
    const t = d.type || d.method || 'dom';
    if (!id) return;
    sandbox[`DOM:${t}:${id}`] = () => ({ result: `Simulação: evento '${t}' no elemento '#${id}'`, timestamp: Date.now() });
  });

  (analysis.globals || []).forEach(g => {
    const name = (g && (g.name || g.id)) || (typeof g === 'string' ? g : null);
    if (!name) return;
    sandbox[name] = sandbox[name] || (() => ({ result: `stub global '${name}' (sandbox)`, timestamp: Date.now() }));
  });

  return sandbox;
}

// ----------------------------
// 5) HIGH-LEVEL TEST RUN
// ----------------------------
export async function testScript(sourceOrPath) {
  let source = sourceOrPath;

  if (typeof sourceOrPath === "string" && /^(https?:\/\/|\/|\.\/|\.\.\/|[A-Za-z]:\\)/.test(sourceOrPath)) {
    try {
      const res = await fetch(sourceOrPath);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      source = await res.text();
    } catch (e) {
      source = sourceOrPath;
    }
  }

  if (typeof sourceOrPath === 'object' && sourceOrPath !== null && sourceOrPath.source) {
    source = sourceOrPath.source;
  }

  const analysis = analyzeFullJS(source);
  const sandbox = createSmartSandbox(analysis);
  const execList = (analysis.execFunctions || []).map(f => f.name || f);
  const deepReport = generateDeepReport(analyzeFunctionAttributes(source, analysis.execFunctions || execList));

  return {
    source,
    analysis,
    sandbox,
    execList,
    deepReport
  };
}

// ----------------------------
// 6) RUN VIRTUAL
// ----------------------------
export function runVirtual(sandbox, name, ...args) {
  if (!sandbox || typeof sandbox[name] !== "function") {
    return { error: `Entrada '${name}' não encontrada no sandbox.` };
  }
  try {
    return sandbox[name](...args);
  } catch (e) {
    return { error: `Erro ao executar virtualmente '${name}': ${e.message}` };
  }
}

// ----------------------------
// 7) DEEP REPORT MERGER
// ----------------------------
export function generateDeepReport(funcAttrs) {
  return (funcAttrs || []).map(f => ({
    name: f.name,
    type: f.type || 'function',
    params: f.params || [],
    isAsync: !!f.isAsync,
    usesDOM: !!f.usesDOM,
    returnsPromise: !!f.returnsPromise,
    usesTryCatch: !!f.usesTryCatch,
    calls: f.callsOtherFunctions || []
  }));
}

// ----------------------------
// 8) UTILITIES (exported for convenience)
// ----------------------------
export { splitParams, dedupeByName as dedupeFunctions };

// End of file