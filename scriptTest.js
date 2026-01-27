// scriptTest.js — Ultra DEV (versão completa e integrada)
// Versão Elite Security com análise de vulnerabilidades

// IMPORTS (garanta que os arquivos existam e exportem os nomes abaixo)
import { scanGlobals } from "./scanner-globals.js";
import { scanFunctions } from "./scanner-functions.js";
import { scanClasses } from "./scanner-classes.js";
import { scanDom } from "./scanner-dom.js";
import { runScanner } from "./scanner.js"; // master scanner (AST-capable)

// ----------------------------
// 1) DETECÇÃO AVANÇADA DE FUNÇÕES COM ANÁLISE DE SEGURANÇA
// ----------------------------
export function analyzeExecutableFunctions(src) {
  const functions = [];

  // regexes para capturar várias formas de definição
  const fnRegex = /function\s+([A-Za-z$_][\w$]*)\s*\(([^)]*)\)\s*\{/g;
  const arrowRegex = /(?:const|let|var)\s+([A-Za-z$_][\w$]*)\s*=\s*\(?([^)]*)\)?\s*=>/g;
  const assignedRegex = /(?:const|let|var)\s+([A-Za-z$_][\w$]*)\s*=\s*function\s*\(([^)]*)\)/g;
  const methodRegex = /(?:^|[\s{;])([A-Za-z$_][\w$]*)\s*\(([^)]*)\)\s*{/gm; // methods in classes/objects
  const asyncFnRegex = /async\s+function\s+([A-Za-z$_][\w$]*)\s*\(([^)]*)\)/g;

  let m;

  while ((m = fnRegex.exec(src))) {
    const security = analyzeFunctionSecurity(src, m[1], m.index);
    functions.push({ 
      name: m[1], 
      params: splitParams(m[2]), 
      type: "function", 
      index: m.index,
      security: security
    });
  }
  while ((m = arrowRegex.exec(src))) {
    const security = analyzeFunctionSecurity(src, m[1], m.index);
    functions.push({ 
      name: m[1], 
      params: splitParams(m[2]), 
      type: "arrow", 
      index: m.index,
      security: security
    });
  }
  while ((m = assignedRegex.exec(src))) {
    const security = analyzeFunctionSecurity(src, m[1], m.index);
    functions.push({ 
      name: m[1], 
      params: splitParams(m[2]), 
      type: "assigned", 
      index: m.index,
      security: security
    });
  }
  // methods (careful with false positives; filter keywords)
  while ((m = methodRegex.exec(src))) {
    const name = m[1];
    if (!isReservedKeyword(name)) {
      const security = analyzeFunctionSecurity(src, name, m.index);
      functions.push({ 
        name, 
        params: splitParams(m[2]), 
        type: "method", 
        index: m.index,
        security: security
      });
    }
  }
  while ((m = asyncFnRegex.exec(src))) {
    const security = analyzeFunctionSecurity(src, m[1], m.index);
    functions.push({ 
      name: m[1], 
      params: splitParams(m[2]), 
      type: "async", 
      index: m.index,
      security: security
    });
  }

  return dedupeByName(functions);
}

// Nova função: Análise de segurança de função
function analyzeFunctionSecurity(src, functionName, index) {
  const security = {
    isDangerous: false,
    vulnerabilities: [],
    riskLevel: "LOW",
    recommendations: []
  };
  
  // Extrair contexto da função
  const contextStart = Math.max(0, index - 50);
  const contextEnd = Math.min(src.length, index + 500);
  const context = src.substring(contextStart, contextEnd);
  
  // Padrões perigosos
  const dangerousPatterns = [
    { pattern: /eval\s*\(/, type: "EVAL_USAGE", risk: "CRITICAL" },
    { pattern: /new\s+Function/, type: "FUNCTION_CONSTRUCTOR", risk: "HIGH" },
    { pattern: /\.innerHTML\s*=/, type: "INNERHTML_ASSIGNMENT", risk: "HIGH" },
    { pattern: /\.outerHTML\s*=/, type: "OUTERHTML_ASSIGNMENT", risk: "CRITICAL" },
    { pattern: /document\.write/, type: "DOCUMENT_WRITE", risk: "MEDIUM" },
    { pattern: /setTimeout\s*\([^,)]*\)/, type: "DYNAMIC_TIMEOUT", risk: "MEDIUM" },
    { pattern: /setInterval\s*\([^,)]*\)/, type: "DYNAMIC_INTERVAL", risk: "MEDIUM" }
  ];
  
  dangerousPatterns.forEach(pattern => {
    if (pattern.pattern.test(context)) {
      security.isDangerous = true;
      security.vulnerabilities.push({
        type: pattern.type,
        risk: pattern.risk
      });
      
      if (pattern.risk === "CRITICAL") security.riskLevel = "CRITICAL";
      else if (pattern.risk === "HIGH" && security.riskLevel !== "CRITICAL") security.riskLevel = "HIGH";
      else if (pattern.risk === "MEDIUM" && security.riskLevel === "LOW") security.riskLevel = "MEDIUM";
    }
  });
  
  // Verificar nomes suspeitos
  const suspiciousNames = [
    'eval', 'execute', 'run', 'inject', 'parse', 'compile',
    'load', 'save', 'delete', 'remove', 'update', 'create',
    'destroy', 'init', 'start', 'stop', 'config', 'settings'
  ];
  
  if (suspiciousNames.includes(functionName.toLowerCase())) {
    security.isSuspicious = true;
    security.recommendations.push(`Função '${functionName}' tem nome suspeito - auditar cuidadosamente`);
  }
  
  // Gerar recomendações baseadas nos riscos
  if (security.riskLevel === "CRITICAL") {
    security.recommendations.push("🚨 REMOVER eval() ou Function() imediatamente");
    security.recommendations.push("Implementar sandbox para execução de código");
  }
  
  if (security.riskLevel === "HIGH") {
    security.recommendations.push("Substituir innerHTML/outerHTML por textContent");
    security.recommendations.push("Sanitizar todas as entradas de usuário");
  }
  
  if (security.riskLevel === "MEDIUM") {
    security.recommendations.push("Validar parâmetros de setTimeout/setInterval");
    security.recommendations.push("Evitar document.write()");
  }
  
  return security;
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
      return { 
        ...fn, 
        usesDOM: false, 
        isAsync: false, 
        returnsPromise: false, 
        usesTryCatch: false, 
        callsOtherFunctions: [],
        security: {
          isDangerous: false,
          vulnerabilities: []
        }
      };
    }
    const snippet = src.slice(Math.max(0, idx - 40), Math.min(src.length, idx + 800));
    
    // Análise de segurança no snippet
    const security = analyzeSnippetSecurity(snippet, name);
    
    return {
      ...fn,
      usesDOM: /document\./.test(snippet) || /window\./.test(snippet),
      isAsync: /async/.test(snippet) || /\bawait\b/.test(snippet),
      returnsPromise: /new\s+Promise/.test(snippet) || /\bthen\(/.test(snippet),
      usesTryCatch: /try\s*{/.test(snippet),
      callsOtherFunctions: extractCalledFunctions(snippet).filter(n => n !== name),
      security: security
    };
  });
}

// Nova função: Análise de segurança de snippet
function analyzeSnippetSecurity(snippet, functionName) {
  const security = {
    isDangerous: false,
    vulnerabilities: [],
    riskLevel: "LOW",
    recommendations: []
  };
  
  const dangerousPatterns = [
    { pattern: /eval\s*\(/, type: "EVAL_USAGE", risk: "CRITICAL" },
    { pattern: /new\s+Function/, type: "FUNCTION_CONSTRUCTOR", risk: "HIGH" },
    { pattern: /\.innerHTML\s*=/, type: "INNERHTML_ASSIGNMENT", risk: "HIGH" },
    { pattern: /\.outerHTML\s*=/, type: "OUTERHTML_ASSIGNMENT", risk: "CRITICAL" },
    { pattern: /document\.write/, type: "DOCUMENT_WRITE", risk: "MEDIUM" },
    { pattern: /localStorage/, type: "LOCAL_STORAGE_ACCESS", risk: "LOW" },
    { pattern: /sessionStorage/, type: "SESSION_STORAGE_ACCESS", risk: "LOW" },
    { pattern: /cookie/, type: "COOKIE_ACCESS", risk: "LOW" },
    { pattern: /XMLHttpRequest/, type: "XHR_REQUEST", risk: "MEDIUM" },
    { pattern: /fetch\s*\(/, type: "FETCH_REQUEST", risk: "MEDIUM" },
    { pattern: /postMessage/, type: "POST_MESSAGE", risk: "MEDIUM" }
  ];
  
  dangerousPatterns.forEach(pattern => {
    if (pattern.pattern.test(snippet)) {
      security.isDangerous = true;
      security.vulnerabilities.push({
        type: pattern.type,
        risk: pattern.risk
      });
      
      if (pattern.risk === "CRITICAL") security.riskLevel = "CRITICAL";
      else if (pattern.risk === "HIGH" && security.riskLevel !== "CRITICAL") security.riskLevel = "HIGH";
      else if (pattern.risk === "MEDIUM" && security.riskLevel === "LOW") security.riskLevel = "MEDIUM";
    }
  });
  
  // Verificar chamadas a funções perigosas
  const dangerousCalls = extractCalledFunctions(snippet).filter(name => 
    ['eval', 'Function', 'setTimeout', 'setInterval', 'document.write'].includes(name.toLowerCase())
  );
  
  if (dangerousCalls.length > 0) {
    security.isDangerous = true;
    security.vulnerabilities.push({
      type: "DANGEROUS_FUNCTION_CALL",
      risk: "HIGH",
      functions: dangerousCalls
    });
    if (security.riskLevel === "LOW") security.riskLevel = "MEDIUM";
  }
  
  return security;
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
      const r = runScanner(sourceCode, { securityScan: true });
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
  const vulnerabilities = (master && master.vulnerabilities) ? master.vulnerabilities : [];

  const execFuncs = analyzeExecutableFunctions(sourceCode);
  const execAttrs = analyzeFunctionAttributes(sourceCode, execFuncs);

  // Análise de segurança consolidada
  const securityAnalysis = {
    vulnerabilities: vulnerabilities,
    functionsSecurity: analyzeFunctionsSecurity(execAttrs),
    overallSecurityScore: calculateOverallSecurityScore(vulnerabilities, execAttrs)
  };

  return {
    classes,
    functions,
    globals,
    dom,
    execFunctions: execAttrs,
    vulnerabilities: vulnerabilities,
    security: securityAnalysis,
    meta: {
      engine: (master && master.ast) ? "acorn" : "regex",
      timestamp: Date.now(),
      securityLevel: getSecurityLevel(securityAnalysis.overallSecurityScore)
    }
  };
}

// Nova função: Análise de segurança de funções
function analyzeFunctionsSecurity(funcAttrs) {
  const analysis = {
    totalFunctions: funcAttrs.length,
    dangerousFunctions: 0,
    criticalFunctions: 0,
    highRiskFunctions: 0,
    mediumRiskFunctions: 0,
    securityScore: 100
  };
  
  funcAttrs.forEach(func => {
    if (func.security?.isDangerous) {
      analysis.dangerousFunctions++;
      
      if (func.security.riskLevel === "CRITICAL") analysis.criticalFunctions++;
      else if (func.security.riskLevel === "HIGH") analysis.highRiskFunctions++;
      else if (func.security.riskLevel === "MEDIUM") analysis.mediumRiskFunctions++;
    }
  });
  
  // Calcular score
  if (analysis.totalFunctions > 0) {
    let penalty = analysis.criticalFunctions * 10;
    penalty += analysis.highRiskFunctions * 5;
    penalty += analysis.mediumRiskFunctions * 2;
    analysis.securityScore = Math.max(0, 100 - Math.min(penalty, 100));
  }
  
  return analysis;
}

// Nova função: Calcular score geral de segurança
function calculateOverallSecurityScore(vulnerabilities, funcAttrs) {
  let score = 100;
  
  // Penalizar vulnerabilidades
  vulnerabilities.forEach(vuln => {
    switch(vuln.severity) {
      case 'CRITICAL': score -= 10; break;
      case 'HIGH': score -= 5; break;
      case 'MEDIUM': score -= 2; break;
      case 'LOW': score -= 1; break;
    }
  });
  
  // Penalizar funções perigosas
  const dangerousFuncs = funcAttrs.filter(f => f.security?.isDangerous);
  dangerousFuncs.forEach(func => {
    switch(func.security.riskLevel) {
      case 'CRITICAL': score -= 5; break;
      case 'HIGH': score -= 3; break;
      case 'MEDIUM': score -= 1; break;
    }
  });
  
  return Math.max(0, Math.min(100, score));
}

// Nova função: Determinar nível de segurança
function getSecurityLevel(score) {
  if (score >= 90) return 'VERY_SECURE';
  if (score >= 70) return 'SECURE';
  if (score >= 50) return 'MODERATE';
  if (score >= 30) return 'RISKY';
  return 'CRITICAL';
}

// ----------------------------
// 4) SMART SANDBOX CREATION COM SEGURANÇA
// ----------------------------
export function createSmartSandbox(analysis) {
  const sandbox = {};

  const execList = (analysis.execFunctions || []).map(f => (typeof f === "string" ? { name: f } : f));
  execList.forEach(fn => {
    sandbox[fn.name] = (...args) => {
      // Verificar segurança antes de executar
      if (fn.security?.isDangerous) {
        return {
          error: `⚠️ FUNÇÃO PERIGOSA: '${fn.name}' tem vulnerabilidades de segurança`,
          security: fn.security,
          blocked: true,
          timestamp: Date.now()
        };
      }
      
      return {
        result: `Simulação: função '${fn.name}' executada (sandbox).`,
        args,
        meta: fn,
        timestamp: Date.now(),
        security: fn.security || { isDangerous: false }
      };
    };
  });

  (analysis.classes || []).forEach(cls => {
    const clsName = (cls && (cls.name || cls.id && cls.id.name)) || (typeof cls === 'string' ? cls : null);
    const methods = cls && cls.methods ? cls.methods : (cls && cls.body && cls.body.methods ? cls.body.methods : []);
    (methods || []).forEach(m => {
      const mName = (typeof m === 'string') ? m : (m && (m.name || (m.key && m.key.name)));
      if (!mName) return;
      
      const fullName = `${clsName}.${mName}`;
      sandbox[fullName] = (...args) => {
        // Verificar se o método é perigoso
        if (m.security?.isDangerous) {
          return {
            error: `⚠️ MÉTODO PERIGOSO: '${fullName}' tem vulnerabilidades`,
            security: m.security,
            blocked: true,
            timestamp: Date.now()
          };
        }
        
        return {
          result: `Simulação: método '${fullName}' executado (sandbox).`,
          args, 
          timestamp: Date.now()
        };
      };
    });
  });

  (analysis.dom || []).forEach(d => {
    const id = d.id || d.element || d.name;
    const t = d.type || d.method || 'dom';
    if (!id) return;
    
    const fullName = `DOM:${t}:${id}`;
    sandbox[fullName] = () => {
      // Verificar segurança da operação DOM
      if (d.security?.isDangerous) {
        return {
          error: `⚠️ OPERAÇÃO DOM PERIGOSA: '${fullName}' tem risco XSS`,
          security: d.security,
          blocked: true,
          timestamp: Date.now()
        };
      }
      
      return { 
        result: `Simulação: evento '${t}' no elemento '#${id}'`, 
        timestamp: Date.now() 
      };
    };
  });

  (analysis.globals || []).forEach(g => {
    const name = (g && (g.name || g.id)) || (typeof g === 'string' ? g : null);
    if (!name) return;
    
    if (!sandbox[name]) {
      sandbox[name] = () => {
        // Verificar segurança da variável global
        if (g.security?.isDangerous) {
          return {
            error: `⚠️ VARIÁVEL GLOBAL PERIGOSA: '${name}' contém segredos`,
            security: g.security,
            blocked: true,
            timestamp: Date.now()
          };
        }
        
        return { 
          result: `stub global '${name}' (sandbox)`, 
          timestamp: Date.now() 
        };
      };
    }
  });

  return sandbox;
}

// ----------------------------
// 5) HIGH-LEVEL TEST RUN COM SEGURANÇA
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
    deepReport,
    security: {
      score: analysis.security.overallSecurityScore,
      level: analysis.meta.securityLevel,
      vulnerabilities: analysis.vulnerabilities.length,
      criticalVulnerabilities: analysis.vulnerabilities.filter(v => v.severity === 'CRITICAL').length
    }
  };
}

// ----------------------------
// 6) RUN VIRTUAL COM VERIFICAÇÃO DE SEGURANÇA
// ----------------------------
export function runVirtual(sandbox, name, ...args) {
  if (!sandbox || typeof sandbox[name] !== "function") {
    return { 
      error: `Entrada '${name}' não encontrada no sandbox.`,
      security: { isDangerous: false }
    };
  }
  try {
    const result = sandbox[name](...args);
    
    // Adicionar verificação de segurança ao resultado
    if (result.security?.isDangerous) {
      result.securityWarning = `⚠️ AVISO DE SEGURANÇA: ${name} contém vulnerabilidades`;
    }
    
    return result;
  } catch (e) {
    return { 
      error: `Erro ao executar virtualmente '${name}': ${e.message}`,
      security: { isDangerous: false }
    };
  }
}

// ----------------------------
// 7) DEEP REPORT MERGER COM SEGURANÇA
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
    calls: f.callsOtherFunctions || [],
    security: f.security || {
      isDangerous: false,
      vulnerabilities: [],
      riskLevel: "LOW"
    }
  }));
}

// ----------------------------
// 8) UTILITIES (exported for convenience)
// ----------------------------
export { splitParams, dedupeByName as dedupeFunctions };

// Nova função: Gerar relatório de segurança
export function generateSecurityReport(analysis) {
  const vulnerabilities = analysis.vulnerabilities || [];
  const funcAttrs = analysis.execFunctions || [];
  
  const report = {
    summary: {
      totalVulnerabilities: vulnerabilities.length,
      criticalVulnerabilities: vulnerabilities.filter(v => v.severity === 'CRITICAL').length,
      highVulnerabilities: vulnerabilities.filter(v => v.severity === 'HIGH').length,
      dangerousFunctions: funcAttrs.filter(f => f.security?.isDangerous).length,
      securityScore: analysis.security?.overallSecurityScore || 100,
      securityLevel: analysis.meta?.securityLevel || 'UNKNOWN'
    },
    vulnerabilities: vulnerabilities,
    dangerousFunctions: funcAttrs
      .filter(f => f.security?.isDangerous)
      .map(f => ({
        name: f.name,
        type: f.type,
        riskLevel: f.security.riskLevel,
        vulnerabilities: f.security.vulnerabilities,
        recommendations: f.security.recommendations || []
      })),
    recommendations: []
  };
  
  // Gerar recomendações
  if (report.summary.criticalVulnerabilities > 0) {
    report.recommendations.push(
      `Corrigir ${report.summary.criticalVulnerabilities} vulnerabilidades CRÍTICAS imediatamente`
    );
    report.recommendations.push(
      'Remover todo uso de eval() e Function()'
    );
  }
  
  if (report.summary.highVulnerabilities > 0) {
    report.recommendations.push(
      `Corrigir ${report.summary.highVulnerabilities} vulnerabilidades ALTAS`
    );
    report.recommendations.push(
      'Implementar sanitização para innerHTML/outerHTML'
    );
  }
  
  if (report.summary.dangerousFunctions > 0) {
    report.recommendations.push(
      `Auditar ${report.summary.dangerousFunctions} funções perigosas`
    );
  }
  
  return report;
}

// End of file