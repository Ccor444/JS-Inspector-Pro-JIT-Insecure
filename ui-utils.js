// ui-utils.js - Elite Security Edition
// Ferramentas de UI com análise de segurança avançada

/**
 * Exporta um objeto de dados como um arquivo JSON para download.
 * @param {object} data - Os dados de análise a serem exportados.
 * @param {string} filename - O nome do arquivo a ser baixado.
 * @param {function} stringifyFn - A função para serializar o objeto (safeStringify).
 */
export function exportJson(data, filename = 'js_inspector_analysis.json', stringifyFn) {
  if (!data) {
    alert('Nenhum dado de análise disponível para exportar.');
    return;
  }
  
  // Gerar relatório de segurança
  const securityReport = generateSecurityReport(data);
  
  // Dados aprimorados com análise de segurança
  const enhancedData = {
    ...data,
    security: securityReport,
    metadata: {
      scannedAt: new Date().toISOString(),
      scannerVersion: '2.0.0',
      scannerMode: 'ELITE_SECURITY',
      userAgent: navigator.userAgent,
      url: window.location.href
    }
  };
  
  const jsonString = typeof stringifyFn === 'function' 
    ? stringifyFn(enhancedData) 
    : JSON.stringify(enhancedData, null, 2);
  
  // Adicionar marca d'água de segurança - CORRIGIDO
  const securityScore = securityReport.securityScore || 100;
  const threatLevel = securityReport.threatLevel || 'UNKNOWN';
  const criticalCount = securityReport.stats?.critical || 0;
  
  const watermarkedString = `// ============================================
// JS INSPECTOR PRO ELITE SECURITY - EXPORT
// Generated: ${new Date().toISOString()}
// Security Score: ${securityScore}/100
// Security Level: ${threatLevel}
// Critical Vulnerabilities: ${criticalCount}
// WARNING: Contains security analysis - Handle with care
// ============================================\n\n${jsonString}`;
  
  const blob = new Blob([watermarkedString], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.style.display = 'none';
  document.body.appendChild(a);
  a.click();
  
  // Limpeza segura
  setTimeout(() => {
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, 1000);
  
  // Log de auditoria
  logSecurityEvent('export', filename, threatLevel);
  
  // Feedback ao usuário
  const threatCategory = getThreatCategory(securityScore);
  if (threatCategory === 'CRITICAL') {
    alert(`⚠️ EXPORT COMPLETO COM ALERTA DE SEGURANÇA\n\nScore: ${securityScore}/100\nNível: ${threatCategory}\n\n${criticalCount} vulnerabilidades críticas detectadas.`);
  } else {
    alert(`✅ Export completed!\nSecurity Score: ${securityScore}/100\nLevel: ${threatCategory}`);
  }
}

/**
 * Copia JSON com validação de segurança - CORRIGIDO
 */
export function copyJson(data, stringifyFn) {
  if (!data) {
    alert('Nenhum dado de análise disponível para copiar.');
    return;
  }

  // Gerar relatório de segurança
  const securityReport = generateSecurityReport(data);
  
  // VERIFICAÇÃO CRÍTICA: garantir que securityReport existe
  if (!securityReport) {
    console.error('Falha ao gerar relatório de segurança');
    alert('Erro ao gerar relatório de segurança. Tente novamente.');
    return;
  }
  
  // Adicionar aviso de segurança
  const enhancedData = {
    ...data,
    security: securityReport,
    warning: '⚠️ DADOS SENSÍVEIS DE ANÁLISE DE SEGURANÇA ⚠️\nNÃO COMPARTILHE CÓDIGO CONTENDO INFORMAÇÕES CRÍTICAS\nNÃO COMPARTILHE SEGREDOS/CHAVES HARDCODED'
  };

  const jsonString = typeof stringifyFn === 'function' 
    ? stringifyFn(enhancedData) 
    : JSON.stringify(enhancedData, null, 2);
  
  // CORREÇÃO: Usar securityReport.securityScore direto
  const securityScore = securityReport.securityScore || 100;
  const threatLevel = getThreatCategory(securityScore);
  const criticalCount = securityReport.stats?.critical || 0;
  const highCount = securityReport.stats?.high || 0;
  
  // Adicionar marca d'água de segurança CORRIGIDA
  const watermarkedString = `// === JS INSPECTOR ELITE SECURITY SCAN ===
// Scanned: ${new Date().toISOString()}
// Security Score: ${securityScore}/100
// Security Level: ${threatLevel}
// Critical Vulnerabilities: ${criticalCount}
// High Vulnerabilities: ${highCount}
// ⚠️  SECURITY WARNING: Handle with extreme care
// =============================================\n\n${jsonString}`;
  
  navigator.clipboard.writeText(watermarkedString)
    .then(() => {
      const threatMsg = threatLevel === 'CRITICAL' 
        ? `🚨 ALERTA CRÍTICO: ${criticalCount} vulnerabilidades críticas!`
        : `Nível de segurança: ${threatLevel}`;
      
      alert(`✅ Análise copiada para a área de transferência!\n\n${threatMsg}\n\nScore: ${securityScore}/100`);
    })
    .catch(err => {
      console.error('Erro ao copiar:', err);
      
      // Fallback para versão antiga
      const textArea = document.createElement('textarea');
      textArea.value = watermarkedString;
      document.body.appendChild(textArea);
      textArea.select();
      
      try {
        document.execCommand('copy');
        alert('Análise copiada (método alternativo)!');
      } catch (fallbackErr) {
        alert('Erro ao copiar. Permissão negada ou navegador não suportado.');
      }
      
      document.body.removeChild(textArea);
    });
}

/**
 * Gera relatório de segurança completo
 */
function generateSecurityReport(data) {
  const threats = [];
  const warnings = [];
  const recommendations = [];
  
  // Análise de funções perigosas
  const dangerousPatterns = [
    { pattern: /eval\s*\(/, name: 'eval()', severity: 'CRITICAL' },
    { pattern: /Function\s*\(/, name: 'Function constructor', severity: 'HIGH' },
    { pattern: /setTimeout\s*\([^)]*\)/, name: 'Dynamic setTimeout', severity: 'MEDIUM' },
    { pattern: /setInterval\s*\([^)]*\)/, name: 'Dynamic setInterval', severity: 'MEDIUM' },
    { pattern: /innerHTML\s*=/, name: 'innerHTML assignment', severity: 'HIGH' },
    { pattern: /outerHTML\s*=/, name: 'outerHTML assignment', severity: 'HIGH' },
    { pattern: /document\.write/, name: 'document.write', severity: 'MEDIUM' },
    { pattern: /localStorage\s*\./, name: 'localStorage access', severity: 'LOW' },
    { pattern: /sessionStorage\s*\./, name: 'sessionStorage access', severity: 'LOW' },
    { pattern: /XMLHttpRequest/, name: 'XHR', severity: 'MEDIUM' },
    { pattern: /fetch\s*\(/, name: 'fetch()', severity: 'MEDIUM' },
    { pattern: /postMessage\s*\(/, name: 'postMessage', severity: 'MEDIUM' },
    { pattern: /importScripts/, name: 'importScripts', severity: 'HIGH' },
    { pattern: /WebSocket/, name: 'WebSocket', severity: 'MEDIUM' },
    { pattern: /<script>/i, name: 'Inline script tag', severity: 'CRITICAL' },
    { pattern: /<iframe>/i, name: 'Inline iframe', severity: 'HIGH' },
    { pattern: /on\w+\s*=/, name: 'Inline event handler', severity: 'MEDIUM' },
    { pattern: /javascript:/i, name: 'JavaScript protocol', severity: 'CRITICAL' },
    { pattern: /data:/i, name: 'Data protocol', severity: 'HIGH' },
    { pattern: /blob:/i, name: 'Blob protocol', severity: 'MEDIUM' },
    { pattern: /new\s+ActiveXObject/, name: 'ActiveXObject', severity: 'CRITICAL' },
    { pattern: /\$\.ajax/, name: 'jQuery AJAX', severity: 'MEDIUM' },
    { pattern: /require\s*\(/, name: 'Dynamic require', severity: 'HIGH' },
    { pattern: /import\s*\(/, name: 'Dynamic import', severity: 'MEDIUM' },
    { pattern: /constructor\.constructor/, name: 'Constructor chaining', severity: 'CRITICAL' },
    { pattern: /prototype\.__proto__/, name: 'Proto pollution', severity: 'CRITICAL' },
    { pattern: /Object\.assign\s*\([^,)]*,/, name: 'Object.assign merge', severity: 'MEDIUM' },
    { pattern: /JSON\.parse\s*\([^)]*\)/, name: 'JSON.parse', severity: 'LOW' },
    { pattern: /JSON\.stringify/, name: 'JSON.stringify', severity: 'LOW' },
    { pattern: /btoa\s*\(/, name: 'Base64 encode', severity: 'LOW' },
    { pattern: /atob\s*\(/, name: 'Base64 decode', severity: 'LOW' },
    { pattern: /escape\s*\(/, name: 'escape()', severity: 'LOW' },
    { pattern: /unescape\s*\(/, name: 'unescape()', severity: 'LOW' },
    { pattern: /decodeURIComponent/, name: 'decodeURIComponent', severity: 'LOW' },
    { pattern: /encodeURIComponent/, name: 'encodeURIComponent', severity: 'LOW' },
    { pattern: /crypto\s*\./, name: 'Crypto API', severity: 'LOW' },
    { pattern: /SubtleCrypto/, name: 'SubtleCrypto', severity: 'LOW' },
    { pattern: /window\.open/, name: 'window.open', severity: 'MEDIUM' },
    { pattern: /location\s*=/, name: 'location redirect', severity: 'MEDIUM' },
    { pattern: /history\.(pushState|replaceState)/, name: 'History manipulation', severity: 'MEDIUM' }
  ];
  
  // Converter dados para string para análise
  const codeString = data ? JSON.stringify(data).toLowerCase() : '';
  
  // Analisar padrões perigosos
  dangerousPatterns.forEach(pattern => {
    if (pattern.pattern.test(codeString)) {
      threats.push({
        type: pattern.name,
        severity: pattern.severity,
        description: getThreatDescription(pattern.name),
        recommendation: getThreatRecommendation(pattern.name)
      });
    }
  });
  
  // Análise de possíveis XSS
  if (data && data.domIds && data.domIds.length > 0) {
    const domOperations = data.domIds.filter(d => 
      d.id && (d.id.includes('script') || d.id.includes('content') || d.id.includes('html'))
    );
    if (domOperations.length > 0) {
      warnings.push({
        type: 'POTENTIAL_XSS',
        elements: domOperations.map(d => d.id),
        description: 'Elementos DOM com nomes suspeitos podem ser alvos de XSS',
        recommendation: 'Validar e sanitizar conteúdo atribuído a esses elementos'
      });
    }
  }
  
  // Análise de variáveis globais perigosas
  if (data && data.globals && data.globals.length > 0) {
    const dangerousGlobals = data.globals.filter(g => 
      g.name && ['password', 'secret', 'key', 'token', 'auth', 'credential'].some(word => 
        g.name.toLowerCase().includes(word)
      )
    );
    if (dangerousGlobals.length > 0) {
      warnings.push({
        type: 'SENSITIVE_GLOBALS',
        variables: dangerousGlobals.map(g => g.name),
        description: 'Variáveis globais com nomes sensíveis detectadas',
        recommendation: 'Mover para variáveis de ambiente ou secret manager'
      });
    }
  }
  
  // Análise de classes perigosas
  if (data && data.classes && data.classes.length > 0) {
    const dangerousClasses = data.classes.filter(c => 
      c.security && c.security.hasDangerousMethods
    );
    if (dangerousClasses.length > 0) {
      warnings.push({
        type: 'DANGEROUS_CLASSES',
        classes: dangerousClasses.map(c => c.name),
        description: 'Classes com métodos perigosos detectadas',
        recommendation: 'Auditar métodos perigosos e implementar validação'
      });
    }
  }
  
  // Análise de funções perigosas
  if (data && data.execFunctions && data.execFunctions.length > 0) {
    const dangerousFunctions = data.execFunctions.filter(f => 
      f.security && f.security.isDangerous
    );
    if (dangerousFunctions.length > 0) {
      warnings.push({
        type: 'DANGEROUS_FUNCTIONS',
        functions: dangerousFunctions.map(f => f.name),
        description: 'Funções com vulnerabilidades de segurança',
        recommendation: 'Revisar e corrigir vulnerabilidades'
      });
    }
  }
  
  // Gerar recomendações baseadas nas ameaças
  if (threats.some(t => t.severity === 'CRITICAL')) {
    recommendations.push('🚨 CRÍTICO: Remover eval() e Function() do código');
    recommendations.push('🔒 Implementar Content Security Policy (CSP)');
    recommendations.push('🛡️ Usar sandbox para execução de código dinâmico');
  }
  
  if (threats.some(t => t.severity === 'HIGH')) {
    recommendations.push('✅ Validar todas as entradas de usuário');
    recommendations.push('🧼 Sanitizar saídas para prevenir XSS');
    recommendations.push('🔍 Implementar logging de segurança');
  }
  
  if (threats.length > 10) {
    recommendations.push('📋 Revisão de segurança profunda recomendada');
    recommendations.push('👥 Considerar auditoria de segurança por terceiros');
  }
  
  // Calcular nível de ameaça geral
  let threatLevel = 'LOW';
  let securityScore = 100;
  
  if (threats.some(t => t.severity === 'CRITICAL')) {
    threatLevel = 'CRITICAL';
    securityScore = 30;
  } else if (threats.some(t => t.severity === 'HIGH')) {
    threatLevel = 'HIGH';
    securityScore = 50;
  } else if (threats.some(t => t.severity === 'MEDIUM')) {
    threatLevel = 'MEDIUM';
    securityScore = 70;
  }
  
  // Ajustar score baseado na quantidade
  if (threats.length > 5) securityScore -= 10;
  if (threats.length > 10) securityScore -= 15;
  if (threats.length > 20) securityScore -= 25;
  if (warnings.length > 5) securityScore -= 10;
  
  securityScore = Math.max(0, Math.min(100, securityScore));
  
  return {
    threats,
    warnings,
    recommendations,
    threatLevel,
    securityScore,
    stats: {
      totalThreats: threats.length,
      critical: threats.filter(t => t.severity === 'CRITICAL').length,
      high: threats.filter(t => t.severity === 'HIGH').length,
      medium: threats.filter(t => t.severity === 'MEDIUM').length,
      low: threats.filter(t => t.severity === 'LOW').length,
      totalWarnings: warnings.length
    },
    scanTimestamp: new Date().toISOString(),
    scanner: 'JS Inspector Pro Elite Security v2.0.0'
  };
}

/**
 * Descrições detalhadas das ameaças
 */
function getThreatDescription(threatName) {
  const descriptions = {
    'eval()': 'Permite execução de código arbitrário - vulnerabilidade crítica de RCE',
    'Function constructor': 'Similar a eval() - pode executar código malicioso dinamicamente',
    'innerHTML assignment': 'Possível vetor de XSS se conteúdo não for sanitizado',
    'outerHTML assignment': 'Alto risco de XSS - pode substituir elementos completamente',
    'document.write': 'Pode ser usado para injection attacks e DOM manipulation',
    'postMessage': 'Comunicação cross-origin - validar origem para prevenir ataques',
    'ActiveXObject': 'Vetor de ataque conhecido em Internet Explorer - evitar completamente',
    'Proto pollution': 'Pode levar a Remote Code Execution através de prototype manipulation',
    'Constructor chaining': 'Pode contornar sandboxes e execução segura',
    'javascript: protocol': 'Permite execução de código através de URLs - risco de XSS',
    'Dynamic setTimeout': 'Pode executar código arbitrário se não validado',
    'Dynamic setInterval': 'Similar a setTimeout - risco de execução de código malicioso'
  };
  return descriptions[threatName] || 'Padrão potencialmente perigoso detectado';
}

/**
 * Recomendações para ameaças específicas
 */
function getThreatRecommendation(threatName) {
  const recommendations = {
    'eval()': 'Substituir por JSON.parse() ou funções específicas. Se necessário, usar sandbox seguro.',
    'Function constructor': 'Evitar completamente. Usar funções nomeadas ou arrow functions.',
    'innerHTML assignment': 'Usar textContent ou sanitizar com DOMPurify. Implementar CSP.',
    'outerHTML assignment': 'EVITAR completamente. Usar replaceWith() ou manipulação segura do DOM.',
    'document.write': 'Substituir por métodos DOM seguros como appendChild ou innerHTML sanitizado.',
    'postMessage': 'Sempre validar origem e tipo de mensagem. Usar allowlist de origens.',
    'ActiveXObject': 'Não usar. Substituir por APIs modernas e seguras.',
    'Proto pollution': 'Validar objetos antes de manipulação. Usar Object.create(null) para objetos limpos.',
    'Constructor chaining': 'Validar parâmetros de construtores. Não confiar em input do usuário.',
    'javascript: protocol': 'Não usar em href ou src. Validar URLs com allowlist.',
    'Dynamic setTimeout': 'Usar funções em vez de strings. Validar código antes de execução.',
    'Dynamic setInterval': 'Similar a setTimeout - usar callbacks nomeados.'
  };
  return recommendations[threatName] || 'Revisar código e implementar validações adequadas.';
}

/**
 * Determinar nível de ameaça baseado no score
 */
function getThreatCategory(score) {
  if (score >= 90) return 'VERY_SECURE';
  if (score >= 70) return 'SECURE';
  if (score >= 50) return 'MODERATE';
  if (score >= 30) return 'RISKY';
  return 'CRITICAL';
}

/**
 * Log de eventos de segurança para auditoria
 */
function logSecurityEvent(action, filename, securityLevel) {
  const logEntry = {
    timestamp: new Date().toISOString(),
    action,
    filename,
    securityLevel,
    userAgent: navigator.userAgent,
    origin: window.location.origin,
    referrer: document.referrer,
    screenResolution: `${window.screen.width}x${window.screen.height}`,
    language: navigator.language
  };
  
  // Enviar para servidor de logs (se configurado)
  if (window.securityLogger && typeof window.securityLogger === 'function') {
    window.securityLogger(logEntry);
  }
  
  // Armazenar localmente (apenas para debug/demo)
  try {
    const securityLogs = JSON.parse(localStorage.getItem('js_inspector_security_logs') || '[]');
    logEntry.ipHash = 'xxx.xxx.xxx.xxx'; // Em produção, hash do IP
    securityLogs.push(logEntry);
    
    // Manter apenas os últimos 100 logs
    if (securityLogs.length > 100) {
      securityLogs.splice(0, securityLogs.length - 100);
    }
    
    localStorage.setItem('js_inspector_security_logs', JSON.stringify(securityLogs));
  } catch (e) {
    console.warn('Não foi possível salvar log de segurança:', e);
  }
}

/**
 * Exporta relatório de segurança em formato de tabela HTML
 */
export function exportSecurityHTML(data, filename = 'security_report.html') {
  const securityReport = generateSecurityReport(data);
  const threatLevel = getThreatCategory(securityReport.securityScore);
  const securityScore = securityReport.securityScore || 100;
  const criticalCount = securityReport.stats?.critical || 0;
  const highCount = securityReport.stats?.high || 0;
  const totalThreats = securityReport.stats?.totalThreats || 0;
  
  const html = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Relatório de Segurança - JS Inspector Pro Elite</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', 'Roboto', Arial, sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
            color: #333;
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
            position: relative;
        }
        
        .header::after {
            content: '';
            position: absolute;
            bottom: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, #4285f4, #34a853, #fbbc05, #ea4335);
        }
        
        .security-score {
            font-size: 72px;
            font-weight: 800;
            margin: 20px 0;
            font-family: 'Courier New', monospace;
        }
        
        .grade-badge {
            display: inline-block;
            padding: 12px 30px;
            border-radius: 50px;
            font-weight: bold;
            font-size: 24px;
            margin: 10px;
            background: ${getThreatColor(threatLevel)};
            color: white;
            text-shadow: 0 2px 4px rgba(0,0,0,0.3);
        }
        
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
            transition: transform 0.3s;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
        }
        
        .stat-value {
            font-size: 42px;
            font-weight: bold;
            margin: 10px 0;
            font-family: 'Courier New', monospace;
        }
        
        .threat-card {
            border-left: 5px solid;
            margin: 15px 0;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 10px;
            transition: all 0.3s;
        }
        
        .threat-card:hover {
            transform: translateX(10px);
            box-shadow: 0 5px 20px rgba(0,0,0,0.1);
        }
        
        .critical { border-color: #d93025; background: #ffe6e6; }
        .high { border-color: #f29900; background: #fff3e6; }
        .medium { border-color: #f6bf26; background: #fff9e6; }
        .low { border-color: #0b8043; background: #e6f4ea; }
        
        .recommendation {
            background: #e3f2fd;
            border-left: 4px solid #2196f3;
            padding: 15px;
            margin: 10px 0;
            border-radius: 8px;
            display: flex;
            align-items: flex-start;
            gap: 15px;
        }
        
        .recommendation::before {
            content: '💡';
            font-size: 24px;
        }
        
        .footer {
            margin-top: 40px;
            padding: 30px;
            background: #f5f5f5;
            text-align: center;
            color: #666;
            border-top: 1px solid #eee;
        }
        
        .google-badge {
            background: linear-gradient(135deg, #4285f4, #34a853, #fbbc05, #ea4335);
            color: white;
            padding: 8px 20px;
            border-radius: 20px;
            font-size: 14px;
            font-weight: bold;
            display: inline-block;
            margin: 10px;
        }
        
        @media print {
            body { background: white; }
            .container { box-shadow: none; }
            .stat-card { break-inside: avoid; }
        }
        
        .timestamp {
            color: rgba(255,255,255,0.8);
            font-size: 14px;
            margin-top: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1 style="font-size: 36px; margin-bottom: 10px;">🔒 Relatório de Segurança Avançado</h1>
            <p style="font-size: 18px; opacity: 0.9;">JS Inspector Pro Elite Security</p>
            <div class="google-badge">GOOGLE SECURITY DIVISION</div>
            
            <div class="security-score" style="color: ${getThreatColor(threatLevel)}">
                ${securityScore}/100
            </div>
            <div class="grade-badge">
                ${threatLevel}
            </div>
            <div class="timestamp">Gerado em: ${new Date(securityReport.scanTimestamp).toLocaleString()}</div>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <h3>Ameaças Totais</h3>
                <div class="stat-value">${totalThreats}</div>
            </div>
            <div class="stat-card" style="background: linear-gradient(135deg, #f5576c 0%, #f093fb 100%);">
                <h3>Críticas</h3>
                <div class="stat-value">${criticalCount}</div>
            </div>
            <div class="stat-card" style="background: linear-gradient(135deg, #f6d365 0%, #fda085 100%);">
                <h3>Altas</h3>
                <div class="stat-value">${highCount}</div>
            </div>
            <div class="stat-card" style="background: linear-gradient(135deg, #5ee7df 0%, #b490ca 100%);">
                <h3>Segurança</h3>
                <div class="stat-value">${securityScore}%</div>
            </div>
        </div>
        
        <div style="padding: 30px;">
            ${securityReport.threats.length > 0 ? `
            <h2 style="margin-bottom: 20px; color: #1a237e;">⚠️ Ameaças Detectadas</h2>
            ${securityReport.threats.map(threat => `
            <div class="threat-card ${threat.severity.toLowerCase()}">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                    <h3 style="margin: 0;">${threat.type}</h3>
                    <span style="padding: 5px 15px; border-radius: 20px; background: ${getSeverityColor(threat.severity)}; color: white; font-weight: bold; font-size: 12px;">
                        ${threat.severity}
                    </span>
                </div>
                <p style="margin-bottom: 10px; color: #555;">${threat.description}</p>
                <p style="color: #666; font-size: 14px;"><strong>Recomendação:</strong> ${threat.recommendation}</p>
            </div>
            `).join('')}
            ` : '<div style="text-align: center; padding: 40px; color: #0b8043;"><h2>✅ Nenhuma ameaça crítica detectada</h2><p style="margin-top: 10px;">O código parece estar seguro!</p></div>'}
            
            ${securityReport.warnings.length > 0 ? `
            <h2 style="margin: 40px 0 20px 0; color: #1a237e;">📋 Alertas de Segurança</h2>
            ${securityReport.warnings.map(warning => `
            <div class="recommendation">
                <div>
                    <h4 style="margin: 0 0 10px 0;">${warning.type}</h4>
                    <p style="margin-bottom: 5px;">${warning.description}</p>
                    <p style="color: #1976d2; font-weight: bold;">${warning.recommendation}</p>
                </div>
            </div>
            `).join('')}
            ` : ''}
            
            ${securityReport.recommendations.length > 0 ? `
            <h2 style="margin: 40px 0 20px 0; color: #1a237e;">💡 Recomendações de Segurança</h2>
            ${securityReport.recommendations.map(rec => `
            <div class="recommendation">
                <p style="margin: 0; font-weight: 500;">${rec}</p>
            </div>
            `).join('')}
            ` : ''}
        </div>
        
        <div class="footer">
            <p style="margin-bottom: 10px; font-size: 14px;">Relatório gerado por JS Inspector Pro Elite Security</p>
            <p style="color: #999; font-size: 12px; margin-bottom: 20px;">© ${new Date().getFullYear()} - Google Security Research Division</p>
            <div style="font-size: 11px; color: #aaa; margin-top: 20px;">
                <p>Este relatório é confidencial e contém informações sensíveis de segurança.</p>
                <p>Não compartilhe publicamente. Destrua após uso se contiver informações críticas.</p>
            </div>
        </div>
    </div>
</body>
</html>
  `;
  
  const blob = new Blob([html], { type: 'text/html' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.style.display = 'none';
  document.body.appendChild(a);
  a.click();
  
  setTimeout(() => {
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, 1000);
}

/**
 * Helper: Obter cor baseada na severidade
 */
function getSeverityColor(severity) {
  const colors = {
    'CRITICAL': '#d93025',
    'HIGH': '#f29900',
    'MEDIUM': '#f6bf26',
    'LOW': '#0b8043'
  };
  return colors[severity] || '#666';
}

/**
 * Helper: Obter cor baseada no nível de ameaça
 */
function getThreatColor(threatLevel) {
  const colors = {
    'VERY_SECURE': '#0b8043',
    'SECURE': '#34a853',
    'MODERATE': '#fbbc05',
    'RISKY': '#f29900',
    'CRITICAL': '#ea4335'
  };
  return colors[threatLevel] || '#666';
}

/**
 * Nova função: Exportar relatório em formato CSV
 */
export function exportSecurityCSV(data, filename = 'security_report.csv') {
  const securityReport = generateSecurityReport(data);
  
  let csv = 'Category,Type,Severity,Description,Recommendation\n';
  
  // Adicionar ameaças
  securityReport.threats.forEach(threat => {
    csv += `Threat,${escapeCSV(threat.type)},${threat.severity},${escapeCSV(threat.description)},${escapeCSV(threat.recommendation)}\n`;
  });
  
  // Adicionar alertas
  securityReport.warnings.forEach(warning => {
    csv += `Warning,${escapeCSV(warning.type)},MEDIUM,${escapeCSV(warning.description)},${escapeCSV(warning.recommendation)}\n`;
  });
  
  // Adicionar estatísticas
  csv += `\nSummary,Metric,Value\n`;
  csv += `Summary,Security Score,${securityReport.securityScore || 100}\n`;
  csv += `Summary,Threat Level,${securityReport.threatLevel || 'UNKNOWN'}\n`;
  csv += `Summary,Total Threats,${securityReport.stats?.totalThreats || 0}\n`;
  csv += `Summary,Critical Threats,${securityReport.stats?.critical || 0}\n`;
  csv += `Summary,High Threats,${securityReport.stats?.high || 0}\n`;
  csv += `Summary,Timestamp,${securityReport.scanTimestamp || new Date().toISOString()}\n`;
  
  const blob = new Blob([csv], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

/**
 * Helper: Escapar strings para CSV
 */
function escapeCSV(str) {
  if (str == null) return '';
  str = String(str);
  if (str.includes(',') || str.includes('"') || str.includes('\n')) {
    return '"' + str.replace(/"/g, '""') + '"';
  }
  return str;
}