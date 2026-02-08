/* ============================
       Imports (relative modules)
       ============================ */
    import { runScanner as coreRunScanner } from './scanner.js';
    import { scanClasses } from './scanner-classes.js';
    import { scanFunctions } from './scanner-functions.js';
    import { scanGlobals } from './scanner-globals.js';
    import { scanDom } from './scanner-dom.js';
    import {
        analyzeExecutableFunctions,
        analyzeFunctionAttributes,
        createSmartSandbox,
        generateDeepReport,
        generateSecurityReport
    } from './scriptTest.js';

    // Importar módulos de segurança elite
    import { exportJson, copyJson, exportSecurityHTML, exportSecurityCSV } from './ui-utils.js';
    import { securityScanner } from './security-scanner.js';
    import { THREAT_DATABASE, validateAgainstThreatDB, generateThreatReport } from './threat-database.js';

    /* ============================
       DOM Elements & Global Variables
       ============================ */
    // Função segura para obter elementos
    function getElementSafely(id) {
        const element = document.getElementById(id);
        if (!element) {
            console.warn(`⚠️ Elemento #${id} não encontrado no DOM`);
        }
        return element;
    }
    
    const $ = getElementSafely;
    
    // Editor elements (com fallbacks)
    const codeEl = $('code') || { value: '', addEventListener: () => {}, removeEventListener: () => {} };
    const engineLabel = $('engineLabel') || { textContent: '' };
    const qEl = $('q') || { value: '', addEventListener: () => {} };
    
    // Result elements
    const classesEl = $('classes') || document.createElement('div');
    const functionsEl = $('functions') || document.createElement('div');
    const globalsEl = $('globals') || document.createElement('div');
    const domidsEl = $('domids') || document.createElement('div');
    const astEl = $('ast') || document.createElement('pre');
    const execEl = $('exec') || document.createElement('pre');
    
    // Security elements
    const threatLevelEl = $('current-threat-level') || document.createElement('span');
    const realTimeStatus = $('real-time-status') || document.createElement('div');
    const securityStatsEl = $('security-stats') || document.createElement('div');
    const securityResultsEl = $('security-results') || document.createElement('div');
    
    // State variables
    let lastScan = null;
    let jitTimer = null;
    let realTimeProtectionEnabled = false;
    let currentSecurityScore = 100;
    let isScanning = false;

    /* ============================
       Utility Functions
       ============================ */
    function safeStringify(v) { 
        try { 
            return JSON.stringify(v, null, 2); 
        } catch(e) { 
            return String(v); 
        } 
    }

    function escapeHtml(s) { 
        if (s == null) return ''; 
        return String(s).replace(/[&<>"']/g, c => ({
            '&':'&amp;',
            '<':'&lt;',
            '>':'&gt;',
            '"':'&quot;',
            "'":'&#39;'
        }[c])); 
    }

    function renderList(el, list) {
        if (!el) {
            console.warn('Elemento não encontrado para renderizar lista');
            return;
        }
        
        if (!list || !list.length) { 
            el.innerHTML = '<div class="item"><div class="muted">Nenhum item encontrado</div></div>'; 
            return; 
        }
        
        el.innerHTML = list.map(item => {
            const name = escapeHtml(item.name || item.id || (item || ''));
            const line = item.loc ? ('ln ' + (item.loc.line || item.loc.start?.line || '')) : '';
            const type = item.type ? `<span class="small muted">${item.type}</span>` : '';
            
            return `
                <div class="item">
                    <div>
                        <div>${name}</div>
                        ${type}
                    </div>
                    <div class="small muted">${line}</div>
                </div>
            `;
        }).join('');
    }

    function showLoading(button, text = 'Processando...') {
        if (!button) {
            console.warn('Botão não encontrado para mostrar loading');
            return '';
        }
        
        const originalText = button.innerHTML;
        button.innerHTML = `<span>⏳</span> ${text}`;
        button.classList.add('loading');
        return originalText;
    }

    function hideLoading(button, originalText) {
        if (!button) {
            console.warn('Botão não encontrado para esconder loading');
            return;
        }
        
        button.innerHTML = originalText;
        button.classList.remove('loading');
    }

    /* ============================
       Import Functions
       ============================ */
    async function importUrl() {
        const url = prompt("Cole a URL do arquivo JS para importar:", "https://");
        if (!url) return;

        const btn = $('btn-import-url');
        if (!btn) return;
        
        const originalText = showLoading(btn, 'Carregando...');

        try {
            // Validar URL
            if (!url.startsWith('http')) {
                throw new Error('URL deve começar com http:// ou https://');
            }
            
            const response = await fetch(url);
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const code = await response.text();
            if (codeEl && typeof codeEl.value !== 'undefined') {
                codeEl.value = code;
            }
            
            // Auto-scan
            await scanAndRender();
            
            alert(`✅ Código importado de:\n${url}\n\nTotal: ${code.length} caracteres`);
        } catch (error) {
            console.error("Import error:", error);
            alert(`❌ Falha ao importar URL:\n\n${error.message}\n\nVerifique:\n1. URL correta\n2. Permissões CORS\n3. Conexão ativa`);
        } finally {
            hideLoading(btn, originalText);
        }
    }

    /* ============================
       Main Scan Function
       ============================ */
    async function scanAndRender() {
        const code = (codeEl && codeEl.value) || '';
        if (!code.trim()) {
            alert('Digite ou cole algum código JavaScript para analisar.');
            return null;
        }

        if (isScanning) {
            alert('Aguarde, análise já em andamento...');
            return null;
        }

        isScanning = true;
        const scanBtn = $('btn-scan');
        const originalText = showLoading(scanBtn, 'Analisando...');

        try {
            let result;
            try {
                // Verificar se coreRunScanner existe e é uma função
                if (typeof coreRunScanner === 'function') {
                    result = coreRunScanner(code);
                } else {
                    console.warn('coreRunScanner não encontrado, usando fallback regex');
                    result = null;
                }
            } catch (e) {
                console.warn('Core scanner error:', e);
                result = null;
            }

            // AST Analysis
            if (result && result.success && result.engine === 'acorn') {
                if (engineLabel) engineLabel.textContent = 'acorn';
                lastScan = result.result;
                
                // Renderizar listas se elementos existirem
                if (classesEl) renderList(classesEl, lastScan.classes || []);
                if (functionsEl) renderList(functionsEl, lastScan.functions || []);
                if (globalsEl) renderList(globalsEl, lastScan.globals || []);
                if (domidsEl) renderList(domidsEl, lastScan.domIds || []);
                
                // AST Preview
                const astPreview = result.ast?.type ? 
                    { type: result.ast.type, body: result.ast.body?.slice(0, 6) } : 
                    result.ast;
                
                if (astEl) {
                    astEl.textContent = JSON.stringify(astPreview, null, 2);
                    safeHighlight(astEl);
                }
            } else {
                // Regex Fallback
                if (engineLabel) engineLabel.textContent = 'regex';
                
                // Verificar se funções de scanner existem
                const classes = typeof scanClasses === 'function' ? scanClasses(code) : [];
                const funcs = typeof scanFunctions === 'function' ? scanFunctions(code) : [];
                const globals = typeof scanGlobals === 'function' ? scanGlobals(code) : [];
                const dom = typeof scanDom === 'function' ? scanDom(code) : [];

                lastScan = { classes, functions: funcs, globals, domIds: dom };
                
                if (classesEl) renderList(classesEl, classes);
                if (functionsEl) renderList(functionsEl, funcs);
                if (globalsEl) renderList(globalsEl, globals);
                if (domidsEl) renderList(domidsEl, dom);

                if (astEl) {
                    astEl.textContent = 'AST not available (using regex fallback)';
                    safeHighlight(astEl);
                }
            }

            // Execute Analysis (se funções existirem)
            try {
                if (typeof analyzeExecutableFunctions === 'function' && 
                    typeof analyzeFunctionAttributes === 'function' && 
                    typeof createSmartSandbox === 'function') {
                    
                    const execList = analyzeExecutableFunctions(code);
                    const attrs = analyzeFunctionAttributes(code, execList.map(n => ({name: n, type: 'func', params: []})));
                    const sandbox = createSmartSandbox(attrs.length ? attrs : execList.map(n => ({name: n})));
                    
                    // Store for testing
                    window.testSandbox = sandbox;
                    
                    // Display execution results
                    if (execEl) {
                        execEl.textContent = safeStringify(execList);
                        safeHighlight(execEl);
                    }
                }
            } catch (execError) {
                console.warn('Análise executável falhou:', execError);
                if (execEl) {
                    execEl.textContent = 'Análise executável não disponível';
                    safeHighlight(execEl);
                }
            }

            console.info('🔍 Scan completed:', lastScan);
            
            // Real-time security check
            if (realTimeProtectionEnabled && typeof securityScanner?.scan === 'function') {
                performRealTimeSecurityCheck(code);
            }

            // Update threat level
            updateThreatLevel();

        } catch (error) {
            console.error('Scan error:', error);
            alert(`Erro durante análise:\n${error.message}`);
        } finally {
            if (scanBtn) hideLoading(scanBtn, originalText);
            isScanning = false;
        }

        return lastScan;
    }

    /* ============================
       JIT (Live) Scanning
       ============================ */
    function enableJIT(enabled) {
        if (!codeEl) return;
        
        if (jitTimer) {
            clearTimeout(jitTimer);
            jitTimer = null;
        }
        
        if (enabled) {
            codeEl.addEventListener('input', onCodeInput);
            console.log('⚡ JIT Live Scanning enabled');
        } else {
            codeEl.removeEventListener('input', onCodeInput);
            console.log('⚡ JIT Live Scanning disabled');
        }
    }

    function onCodeInput() {
        if (jitTimer) clearTimeout(jitTimer);
        jitTimer = setTimeout(() => {
            scanAndRender();
            const unsafeToggle = $('unsafeToggle');
            if (unsafeToggle && unsafeToggle.checked) {
                console.warn('⚠️ JIT with unsafe eval enabled');
            }
        }, 500);
    }

    /* ============================
       Execution Modes
       ============================ */
    function runInIframe(code) {
        if (!code.trim()) {
            alert('Digite algum código para executar no sandbox.');
            return;
        }

        try {
            const iframe = document.createElement('iframe');
            iframe.style.cssText = `
                width: 0; height: 0; position: absolute;
                left: -9999px; border: none; visibility: hidden;
            `;
            iframe.setAttribute('sandbox', 'allow-scripts');
            iframe.setAttribute('srcdoc', `
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="utf-8">
                    <title>Sandbox Execution</title>
                </head>
                <body>
                    <script>
                        try {
                            ${code.replace(/<\/script>/gi, '<\\/script>')}
                            console.log('✅ Sandbox execution completed');
                        } catch(e) {
                            console.error('❌ Sandbox error:', e);
                        }
                    <\\/script>
                </body>
                </html>
            `);

            document.body.appendChild(iframe);
            setTimeout(() => {
                try {
                    if (iframe.parentNode === document.body) {
                        document.body.removeChild(iframe);
                    }
                } catch(e) {
                    console.warn('Error removing iframe:', e);
                }
            }, 10000);

            alert('Código executado em sandbox (iframe). Verifique o console do navegador para resultados.');
        } catch (error) {
            console.error('Erro ao executar no iframe:', error);
            alert(`Erro ao executar código: ${error.message}`);
        }
    }

    function runEval(code) {
        if (!code.trim()) {
            alert('Digite algum código para executar com eval().');
            return;
        }

        if (!confirm('⚠️ AVISO: Executar eval() é PERIGOSO!\n\nDeseja continuar?')) {
            return;
        }

        try {
            const result = (0, eval)(code);
            console.info('Eval result:', result);
            alert(`✅ Eval executado com sucesso!\n\nResultado: ${typeof result}\nVerifique o console para detalhes.`);
        } catch(e) {
            console.error('Eval error:', e);
            alert(`❌ Erro no eval:\n\n${e.message}`);
        }
    }

    function bindUnsafe(code) {
        if (!code.trim()) {
            alert('Digite algum código para bind no window.');
            return;
        }

        if (!confirm('🚨 PERIGO EXTREMO!\n\nIsso irá executar código e possivelmente anexar ao objeto window global.\n\nContinuar?')) {
            return;
        }

        try {
            const fn = new Function(code + '\nreturn typeof module !== "undefined" ? module.exports : null;');
            const out = fn();
            
            console.warn('Unsafe bind output:', out);
            alert(`⚠️ Código bindado ao window!\n\nSaída: ${typeof out}\nVerifique o console e a aba "Sources" para ver o que foi adicionado ao window.`);
        } catch(e) {
            alert(`❌ Erro na execução unsafe:\n\n${e.message}`);
        }
    }

    /* ============================
       CVE Checker Functions
       ============================ */
    async function performCVECheck() {
        const code = codeEl?.value || '';
        if (!code.trim()) {
            alert('Digite algum código JavaScript para verificação de CVEs.');
            return;
        }

        const cveBtn = $('btn-cve-check');
        if (!cveBtn) return;
        
        const originalText = showLoading(cveBtn, '🔍 Verificando CVEs...');

        try {
            // Importar dinamicamente o módulo CVE Checker
            const { CVE_DATABASE, CVEChecker } = await import('./cve-checker.js');
            
            // Criar instância do verificador
            const cveChecker = new CVEChecker();
            
            // Executar verificação
            const cveResults = cveChecker.scanCodeForCVEs(code);
            
            // Exibir resultados
            displayCVEResults(cveResults);
            
            console.info('🔍 CVE scan completed:', cveResults);
            
        } catch (error) {
            console.error('CVE check error:', error);
            alert(`❌ Erro na verificação de CVEs:\n\n${error.message}`);
        } finally {
            hideLoading(cveBtn, originalText);
        }
    }

    function displayCVEResults(results) {
        if (!results || !securityResultsEl) return;
        
        const summary = results.summary || {};
        const vulnerabilities = results.detectedVulnerabilities || [];
        
        // Atualizar score de segurança
        currentSecurityScore = summary.securityScore || 100;
        
        // Gerar HTML para exibição
        let resultsHTML = `
            <h3 style="margin-top: 0; display: flex; align-items: center; gap: 10px;">
                🔍 CVE Security Scan Report
                <span class="google-badge">GOOGLE SECURITY</span>
            </h3>
            
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0;">
                <div style="background: rgba(255,255,255,0.1); padding: 20px; border-radius: 15px; text-align: center; backdrop-filter: blur(10px); border: 1px solid rgba(255,255,255,0.2);">
                    <div style="font-size: 12px; opacity: 0.8;">Security Score</div>
                    <div style="font-size: 36px; font-weight: bold; color: ${getScoreColor(summary.securityScore || 100)}">
                        ${summary.securityScore || 100}/100
                    </div>
                    <div style="font-size: 14px;">${summary.securityGrade || 'A+'}</div>
                </div>
                
                <div style="background: rgba(255,255,255,0.1); padding: 20px; border-radius: 15px; text-align: center; backdrop-filter: blur(10px); border: 1px solid rgba(255,255,255,0.2);">
                    <div style="font-size: 12px; opacity: 0.8;">Total Vulnerabilities</div>
                    <div style="font-size: 36px; font-weight: bold; color: ${vulnerabilities.length > 0 ? '#ef4444' : '#10b981'}">
                        ${vulnerabilities.length}
                    </div>
                    <div style="font-size: 14px;">
                        <span style="color: #ef4444">${summary.critical || 0} Critical</span>
                        <span style="color: #f59e0b; margin-left: 8px;">${summary.high || 0} High</span>
                    </div>
                </div>
                
                <div style="background: rgba(255,255,255,0.1); padding: 20px; border-radius: 15px; text-align: center; backdrop-filter: blur(10px); border: 1px solid rgba(255,255,255,0.2);">
                    <div style="font-size: 12px; opacity: 0.8;">Libraries Found</div>
                    <div style="font-size: 36px; font-weight: bold; color: #3b82f6">
                        ${results.importedLibraries?.length || 0}
                    </div>
                    <div style="font-size: 14px;">${results.timestamp ? new Date(results.timestamp).toLocaleTimeString() : 'Now'}</div>
                </div>
            </div>
        `;
        
        // Se houver vulnerabilidades, mostrar detalhes
        if (vulnerabilities.length > 0) {
            resultsHTML += `
                <h4>⚠️ Vulnerabilidades Detectadas</h4>
                <div style="max-height: 400px; overflow-y: auto; margin: 15px 0; padding-right: 10px;">
            `;
            
            vulnerabilities.forEach(vuln => {
                const severityColor = {
                    'CRITICAL': '#ef4444',
                    'HIGH': '#f59e0b',
                    'MEDIUM': '#eab308',
                    'LOW': '#10b981'
                }[vuln.severity] || '#94a3b8';
                
                resultsHTML += `
                    <div style="border-left: 4px solid ${severityColor}; margin: 12px 0; padding: 16px; background: rgba(255,255,255,0.05); border-radius: 8px;">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <div>
                                <strong>${vuln.cve || vuln.pattern || 'Unknown'}</strong>
                                <span style="font-size: 11px; color: #94a3b8; margin-left: 8px;">${vuln.type || 'general'}</span>
                            </div>
                            <span style="background: ${severityColor}; color: ${vuln.severity === 'MEDIUM' ? '#1f2937' : 'white'}; padding: 4px 12px; border-radius: 20px; font-size: 11px; font-weight: bold;">
                                ${vuln.severity || 'UNKNOWN'}
                            </span>
                        </div>
                        <div style="margin-top: 8px;">
                            <div style="font-size: 14px; color: #e2e8f0;">${vuln.name || vuln.description || 'No description'}</div>
                            ${vuln.library ? `<div style="font-size: 12px; color: #94a3b8; margin-top: 4px;">Library: ${vuln.library}</div>` : ''}
                            ${vuln.affectedVersions ? `<div style="font-size: 12px; color: #fca5a5; margin-top: 4px;">Affected: ${vuln.affectedVersions}</div>` : ''}
                            ${vuln.mitigation ? `<div style="font-size: 12px; color: #86efac; margin-top: 4px;">✅ Mitigation: ${vuln.mitigation}</div>` : ''}
                            ${vuln.cvssScore ? `<div style="font-size: 12px; color: #cbd5e1; margin-top: 4px;">CVSS Score: ${vuln.cvssScore}</div>` : ''}
                            ${vuln.confidence ? `<div style="font-size: 11px; color: #64748b; margin-top: 4px;">Confidence: ${vuln.confidence}</div>` : ''}
                        </div>
                    </div>
                `;
            });
            
            resultsHTML += '</div>';
        } else {
            resultsHTML += `
                <div style="text-align: center; padding: 40px; color: #10b981;">
                    <div style="font-size: 48px; margin-bottom: 20px;">✅</div>
                    <h4 style="margin: 0;">Nenhuma vulnerabilidade CVE encontrada!</h4>
                    <p style="margin-top: 10px; color: #94a3b8;">Seu código não parece ter vulnerabilidades CVE conhecidas.</p>
                </div>
            `;
        }
        
        // Se houver bibliotecas importadas, mostrar lista
        if (results.importedLibraries?.length > 0) {
            resultsHTML += `
                <h4 style="margin-top: 30px;">📦 Bibliotecas Detectadas</h4>
                <div style="display: flex; flex-wrap: wrap; gap: 10px; margin: 15px 0;">
            `;
            
            results.importedLibraries.forEach(lib => {
                resultsHTML += `
                    <span style="background: rgba(59,130,246,0.2); color: #60a5fa; padding: 6px 12px; border-radius: 20px; font-size: 12px;">
                        ${lib}
                    </span>
                `;
            });
            
            resultsHTML += '</div>';
        }
        
        // Recomendações
        if (results.recommendations?.length > 0) {
            resultsHTML += `
                <h4 style="margin-top: 30px;">🛡️ Recomendações de Segurança</h4>
                <div style="background: rgba(255,255,255,0.05); padding: 20px; border-radius: 12px; margin-top: 15px;">
            `;
            
            results.recommendations.forEach(rec => {
                resultsHTML += `
                    <div style="display: flex; align-items: start; gap: 12px; margin-bottom: 12px;">
                        <div style="color: #3b82f6; font-size: 20px;">${rec.includes('🚨') ? '🚨' : rec.includes('⚠️') ? '⚠️' : '🔍'}</div>
                        <div style="flex: 1; font-size: 14px;">${rec}</div>
                    </div>
                `;
            });
            
            resultsHTML += '</div>';
        }
        
        // Mostrar no painel de segurança
        securityResultsEl.innerHTML = resultsHTML;
        
        // Atualizar estatísticas gerais
        updateGlobalThreatLevel(currentSecurityScore);
        
        // Mostrar alerta se houver vulnerabilidades críticas
        const criticalCount = summary.critical || 0;
        if (criticalCount > 0) {
            alert(`🚨 CVE CRÍTICAS ENCONTRADAS!\n\n${criticalCount} vulnerabilidade(s) CRÍTICA(s) detectada(s)!\n\nScore de segurança: ${summary.securityScore}/100\n\nReveja as recomendações no painel de segurança.`);
        } else if (vulnerabilities.length > 0) {
            alert(`⚠️ CVEs Detectadas\n\n${vulnerabilities.length} vulnerabilidade(s) encontrada(s).\n\nScore de segurança: ${summary.securityScore}/100`);
        } else {
            alert(`✅ Verificação de CVEs concluída!\n\nScore de segurança: ${summary.securityScore}/100 (${summary.securityGrade})\n\nNenhuma vulnerabilidade CVE conhecida detectada.`);
        }
    }

    /* ============================
       Elite Security Functions
       ============================ */
    async function performDeepSecurityScan() {
        const code = codeEl?.value || '';
        if (!code.trim()) {
            alert('Digite algum código JavaScript para análise de segurança.');
            return;
        }

        if (isScanning) {
            alert('Aguarde, análise já em andamento...');
            return;
        }

        isScanning = true;
        const securityBtn = $('btn-deep-scan');
        if (!securityBtn) {
            isScanning = false;
            return;
        }
        
        const originalText = showLoading(securityBtn, '🔄 Analisando segurança...');

        try {
            // Verificar se securityScanner existe
            if (typeof securityScanner?.scan !== 'function') {
                throw new Error('Scanner de segurança não disponível');
            }
            
            // Execute security scanner
            const securityResults = securityScanner.scan(code);
            currentSecurityScore = securityResults?.score || 100;
            
            // Update security UI
            if (securityResults) {
                updateSecurityUI(securityResults);
                
                // Update global threat level
                updateGlobalThreatLevel(securityResults.score);
                
                // Check against threat database (se existir)
                if (typeof validateAgainstThreatDB === 'function') {
                    const threatDBResults = validateAgainstThreatDB(code);
                    if (threatDBResults.length > 0) {
                        console.log('Threat DB matches:', threatDBResults);
                    }
                }
                
                // Generate threat report (se existir)
                if (typeof generateThreatReport === 'function') {
                    const threatReport = generateThreatReport(code);
                }
                
                console.info('🔒 Security scan completed:', securityResults);
                
                // Show alert based on severity
                if (securityResults.score < 60) {
                    const criticalCount = securityResults.threats?.filter(t => t.severity === 'CRITICAL').length || 0;
                    alert(`🚨 ALERTA DE SEGURANÇA CRÍTICA!\n\nScore: ${securityResults.score}/100\n\n${criticalCount} vulnerabilidades CRÍTICAS detectadas!\n\nRecomendações:\n${(securityResults.recommendations || []).slice(0, 3).join('\n')}`);
                } else if (securityResults.score < 80) {
                    alert(`⚠️ AVISO DE SEGURANÇA\n\nScore: ${securityResults.score}/100\n\n${securityResults.threats?.length || 0} vulnerabilidades encontradas.\nReveja as recomendações de segurança.`);
                } else {
                    alert(`✅ Análise de segurança completa!\n\nScore: ${securityResults.score}/100 (${securityResults.grade || 'A'})\n\nO código parece seguro!`);
                }
            }
            
        } catch (error) {
            console.error('Security scan error:', error);
            alert(`❌ Erro na análise de segurança:\n\n${error.message}`);
        } finally {
            hideLoading(securityBtn, originalText);
            isScanning = false;
        }
    }

    function updateSecurityUI(securityResults) {
        if (!securityResultsEl || !securityStatsEl) return;
        
        const score = securityResults?.score || 100;
        const threats = securityResults?.threats || [];
        const warnings = securityResults?.warnings || [];
        const recommendations = securityResults?.recommendations || [];
        
        // Update stats
        securityStatsEl.innerHTML = `
            <div class="stat-box">
                <div class="small">Security Score</div>
                <div class="stat-value" style="color: ${getScoreColor(score)}">
                    ${score}/100
                </div>
                <div>${securityResults?.grade || 'A'}</div>
            </div>
            <div class="stat-box">
                <div class="small">Total Threats</div>
                <div class="stat-value">${threats.length}</div>
                <div>
                    <span class="security-badge critical-badge">${threats.filter(t => t.severity === 'CRITICAL').length} Critical</span>
                    <span class="security-badge high-badge">${threats.filter(t => t.severity === 'HIGH').length} High</span>
                </div>
            </div>
            <div class="stat-box">
                <div class="small">Alerts</div>
                <div class="stat-value">${warnings.length}</div>
                <div>Recommendations: ${recommendations.length}</div>
            </div>
            <div class="stat-box">
                <div class="small">Last Scan</div>
                <div class="stat-value">${new Date().getHours().toString().padStart(2, '0')}:${new Date().getMinutes().toString().padStart(2, '0')}</div>
                <div>${threats.length === 0 ? '✅ Clean' : '⚠️ Issues Found'}</div>
            </div>
        `;
        
        // Update detailed results
        let resultsHTML = '';
        
        if (threats.length > 0) {
            resultsHTML += `
                <h3 style="margin-top: 0;">Detected Threats</h3>
                <div style="max-height: 400px; overflow-y: auto; margin: 15px 0; padding-right: 10px;">
            `;
            
            threats.forEach(threat => {
                resultsHTML += `
                    <div class="threat-card ${threat.severity?.toLowerCase() || 'medium'}">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <div>
                                <strong>${threat.type || threat.id || 'Unknown'}</strong>
                                <span style="font-size: 11px; color: #94a3b8; margin-left: 8px;">${threat.category || 'general'}</span>
                            </div>
                            <span class="security-badge ${(threat.severity?.toLowerCase() || 'medium')}-badge">
                                ${threat.severity || 'MEDIUM'}
                            </span>
                        </div>
                        <div class="small" style="margin-top: 8px; color: #cbd5e1;">${threat.description || 'No description'}</div>
                        <div class="small" style="color: #94a3b8; margin-top: 8px;">
                            <strong>Mitigation:</strong> ${threat.mitigation || threat.recommendation || 'No mitigation provided'}
                        </div>
                        ${threat.occurrences ? `<div class="small" style="color: #64748b; margin-top: 5px;">Occurrences: ${threat.occurrences}</div>` : ''}
                        ${threat.warning ? `<div class="small" style="color: #ef4444; margin-top: 5px; font-weight: bold;">${threat.warning}</div>` : ''}
                    </div>
                `;
            });
            
            resultsHTML += '</div>';
        }
        
        if (warnings.length > 0) {
            resultsHTML += `
                <h3>Security Warnings</h3>
                <div style="background: rgba(255,255,255,0.05); padding: 15px; border-radius: 10px; margin-top: 10px;">
            `;
            
            warnings.forEach(warning => {
                resultsHTML += `
                    <div style="display: flex; align-items: start; gap: 10px; margin-bottom: 10px;">
                        <div style="color: #f59e0b; font-size: 20px;">⚠️</div>
                        <div style="flex: 1;">
                            <div><strong>${warning.type || 'Warning'}</strong></div>
                            <div class="small" style="color: #cbd5e1; margin-top: 5px;">${warning.description || 'No description'}</div>
                            <div class="small" style="color: #94a3b8; margin-top: 5px;">
                                <strong>Recommendation:</strong> ${warning.recommendation || 'No recommendation'}
                            </div>
                        </div>
                    </div>
                `;
            });
            
            resultsHTML += '</div>';
        }
        
        if (recommendations.length > 0) {
            resultsHTML += `
                <h3 style="margin-top: 20px;">Security Recommendations</h3>
                <div style="background: rgba(255,255,255,0.05); padding: 15px; border-radius: 10px; margin-top: 10px;">
            `;
            
            recommendations.forEach(rec => {
                resultsHTML += `
                    <div style="display: flex; align-items: start; gap: 10px; margin-bottom: 10px;">
                        <div style="color: #10b981; font-size: 20px;">✓</div>
                        <div style="flex: 1;">${rec}</div>
                    </div>
                `;
            });
            
            resultsHTML += '</div>';
        }
        
        if (!resultsHTML) {
            resultsHTML = `
                <div style="text-align: center; padding: 40px; color: #10b981;">
                    <div style="font-size: 48px; margin-bottom: 20px;">✅</div>
                    <h3 style="margin: 0;">No Security Issues Found!</h3>
                    <p style="margin-top: 10px; color: #94a3b8;">Your code appears to be secure.</p>
                </div>
            `;
        }
        
        securityResultsEl.innerHTML = resultsHTML;
    }

    function getScoreColor(score) {
        if (score >= 90) return '#10b981';
        if (score >= 70) return '#eab308';
        if (score >= 50) return '#f59e0b';
        return '#ef4444';
    }

    function updateGlobalThreatLevel(score) {
        if (!threatLevelEl || !realTimeStatus) return;
        
        let threatLevel = 'LOW';
        let color = '#10b981';
        let status = '🟢';
        
        if (score < 50) {
            threatLevel = 'CRITICAL';
            color = '#ef4444';
            status = '🔴';
        } else if (score < 70) {
            threatLevel = 'HIGH';
            color = '#f59e0b';
            status = '🟡';
        } else if (score < 85) {
            threatLevel = 'MEDIUM';
            color = '#eab308';
            status = '🟡';
        }
        
        threatLevelEl.textContent = threatLevel;
        threatLevelEl.style.color = color;
        
        const parent = threatLevelEl.parentElement;
        if (parent) {
            parent.style.background = color + '20';
            parent.style.color = color;
        }
        
        realTimeStatus.textContent = `${status} ${threatLevel} THREAT LEVEL`;
        realTimeStatus.className = threatLevel.toLowerCase();
    }

    function updateThreatLevel() {
        if (currentSecurityScore !== 100) {
            updateGlobalThreatLevel(currentSecurityScore);
        }
    }

    function performRealTimeSecurityCheck(code) {
        if (!realTimeProtectionEnabled || !realTimeStatus) return;
        
        try {
            if (typeof securityScanner?.scan === 'function') {
                const securityResults = securityScanner.scan(code);
                updateGlobalThreatLevel(securityResults?.score || 100);
                
                // Check for critical threats
                const criticalThreats = securityResults?.threats?.filter(t => t.severity === 'CRITICAL') || [];
                
                if (criticalThreats.length > 0) {
                    realTimeStatus.textContent = `🔴 ${criticalThreats.length} CRITICAL THREATS`;
                    realTimeStatus.style.background = 'rgba(239,68,68,0.3)';
                    realTimeStatus.style.color = '#fca5a5';
                    
                    // Block eval() and Function() automatically
                    const hasEval = code.includes('eval(') || code.includes('new Function');
                    if (hasEval) {
                        if (!confirm(`🚨 CRITICAL THREAT DETECTED!\n\nFound ${criticalThreats.length} critical security threats.\n\nEval() or Function() detected - these are EXTREMELY dangerous.\n\nContinue anyway?`)) {
                            if (codeEl) {
                                codeEl.value = codeEl.value.replace(/eval\s*\(/g, '// ⚠️ BLOCKED: eval(');
                                codeEl.value = codeEl.value.replace(/new\s+Function/g, '// ⚠️ BLOCKED: new Function');
                                alert('Critical threats blocked by real-time protection.');
                            }
                        }
                    }
                } else {
                    realTimeStatus.textContent = '🟢 REAL-TIME PROTECTION';
                    realTimeStatus.style.background = 'rgba(16,185,129,0.2)';
                    realTimeStatus.style.color = '#10b981';
                }
            }
        } catch (error) {
            console.warn('Real-time security check failed:', error);
        }
    }

    function enableRealTimeProtection() {
        realTimeProtectionEnabled = true;
        if (realTimeStatus) {
            realTimeStatus.textContent = '🟢 REAL-TIME PROTECTION ACTIVE';
            realTimeStatus.style.background = 'rgba(16,185,129,0.3)';
            realTimeStatus.style.color = '#10b981';
        }
        
        // Monitor changes
        const originalValue = codeEl?.value || '';
        
        const checkChanges = () => {
            if (realTimeProtectionEnabled && codeEl && codeEl.value !== originalValue) {
                performRealTimeSecurityCheck(codeEl.value);
            }
        };
        
        if (codeEl) {
            codeEl.addEventListener('input', checkChanges);
        }
        
        alert('✅ Real-time protection enabled!\n\nSecurity threats will be detected and blocked automatically.');
    }

    /* ============================
       Export Functions
       ============================ */
    function exportSecurityReport() {
        const code = codeEl?.value || '';
        if (!code.trim()) {
            alert('Digite algum código para gerar relatório de segurança.');
            return;
        }
        
        try {
            if (typeof securityScanner?.scan !== 'function') {
                throw new Error('Security scanner not available');
            }
            
            const securityResults = securityScanner.scan(code);
            const htmlReport = securityScanner.generateHTMLReport?.(securityResults) || 
                             `<h1>Security Report</h1><pre>${JSON.stringify(securityResults, null, 2)}</pre>`;
            
            const blob = new Blob([htmlReport], { type: 'text/html' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `security_report_${Date.now()}.html`;
            document.body.appendChild(a);
            a.click();
            setTimeout(() => {
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
            }, 100);
            
            alert('✅ Relatório de segurança exportado como HTML!');
        } catch (error) {
            console.error('Export error:', error);
            alert(`❌ Erro ao exportar relatório: ${error.message}`);
        }
    }

    /* ============================
       Helper Functions - CORRIGIDO
       ============================ */
    function safeHighlight(element) {
        try {
            if (element && typeof hljs !== 'undefined') {
                // Verificar se é um elemento DOM válido (nodeType === 1)
                if (element.nodeType && element.nodeType === 1) {
                    // Verificar se é um elemento <code> ou <pre>
                    if (element.tagName === 'CODE' || element.tagName === 'PRE') {
                        if (hljs.highlightElement) {
                            hljs.highlightElement(element);
                        }
                    }
                }
            }
        } catch (highlightError) {
            console.warn('Highlight failed:', highlightError);
        }
    }

    function highlightAllCodeBlocks() {
        if (typeof hljs === 'undefined') {
            console.warn('Highlight.js não está disponível');
            return;
        }
        
        try {
            // Método mais seguro: highlight apenas os blocos de código específicos
            document.querySelectorAll('pre code').forEach(codeBlock => {
                try {
                    safeHighlight(codeBlock);
                } catch (error) {
                    console.warn('Could not highlight code block:', error);
                }
            });
        } catch (error) {
            console.warn('highlightAllCodeBlocks failed:', error);
        }
    }

    /* ============================
       UI Event Handlers
       ============================ */
    function initAppListeners() {
        // 1. Main Actions
        const btnScan = $('btn-scan');
        if (btnScan) {
            btnScan.addEventListener('click', scanAndRender);
        }
        
        const btnClear = $('btn-clear');
        if (btnClear) {
            btnClear.addEventListener('click', () => {
                if (codeEl) codeEl.value = '';
                renderList(classesEl, []);
                renderList(functionsEl, []);
                renderList(globalsEl, []);
                renderList(domidsEl, []);
                
                if (astEl) {
                    astEl.textContent = '// AST aparecerá aqui após análise...';
                    safeHighlight(astEl);
                }
                
                if (execEl) {
                    execEl.textContent = '(vazio - execute um scan primeiro)';
                    safeHighlight(execEl);
                }
                
                alert('Editor limpo!');
            });
        }
        
        const btnExample = $('btn-example');
        if (btnExample) {
            btnExample.addEventListener('click', () => {
                if (codeEl) {
                    codeEl.value = `// Exemplo de código JavaScript com várias funcionalidades

// Classes
class User {
    constructor(name, email) {
        this.name = name;
        this.email = email;
    }
    
    getInfo() {
        return \`\${this.name} <\${this.email}>\`;
    }
}

// Funções
function calculateSum(a, b) {
    return a + b;
}

const multiply = (x, y) => x * y;

// Globais
const API_KEY = 'demo_key_123';
let userCount = 0;
var debugMode = false;

// DOM Access
document.getElementById('app');
document.querySelector('.container');
document.querySelectorAll('.item');

// Vulnerabilidades de exemplo (para teste de segurança)
const dangerousCode = "alert('hacked')";
// eval(dangerousCode); // DESCOMENTE PARA TESTAR VULNERABILIDADE

// innerHTML (potencial XSS)
// document.body.innerHTML = '<script>malicious()</script>';

// Template literal com input do usuário
const userInput = "'; DROP TABLE users; --";
const query = \`SELECT * FROM users WHERE name = '\${userInput}'\`;

console.log('Código de exemplo carregado!');`;
                    scanAndRender();
                    alert('Exemplo de código carregado! Execute o scan para análise.');
                }
            });
        }

        // 2. Import/Export
        const btnImportUrl = $('btn-import-url');
        if (btnImportUrl) {
            btnImportUrl.addEventListener('click', importUrl);
        }
        
        const btnImport = $('btn-import');
        if (btnImport) {
            btnImport.addEventListener('click', () => {
                const filePicker = $('filePicker');
                if (filePicker) filePicker.click();
            });
        }
        
        const filePicker = $('filePicker');
        if (filePicker) {
            filePicker.addEventListener('change', (e) => {
                const file = e.target.files[0];
                if (!file) return;
                
                const reader = new FileReader();
                reader.onload = (event) => {
                    if (codeEl) {
                        codeEl.value = event.target.result;
                        scanAndRender();
                        alert(`Arquivo "${file.name}" carregado com sucesso!`);
                    }
                };
                reader.onerror = () => {
                    alert('❌ Erro ao ler o arquivo.');
                };
                reader.readAsText(file);
                
                // Reset file input
                e.target.value = '';
            });
        }
        
        const btnExportJson = $('btn-export-json');
        if (btnExportJson) {
            btnExportJson.addEventListener('click', () => {
                if (!lastScan) {
                    alert('Execute um Scan primeiro para gerar dados para exportar.');
                    return;
                }
                if (typeof exportJson === 'function') {
                    exportJson(lastScan, 'js_inspector_report.json', safeStringify);
                } else {
                    alert('Função exportJson não disponível');
                }
            });
        }
        
        const btnCopyJson = $('btn-copy-json');
        if (btnCopyJson) {
            btnCopyJson.addEventListener('click', () => {
                if (!lastScan) {
                    alert('Execute um Scan primeiro para gerar dados para copiar.');
                    return;
                }
                if (typeof copyJson === 'function') {
                    copyJson(lastScan, safeStringify);
                } else {
                    alert('Função copyJson não disponível');
                }
            });
        }

        // 3. Execution Modes
        const btnRunIframe = $('btn-run-iframe');
        if (btnRunIframe) {
            btnRunIframe.addEventListener('click', () => {
                if (codeEl) runInIframe(codeEl.value);
            });
        }
        
        const btnRunEval = $('btn-run-eval');
        if (btnRunEval) {
            btnRunEval.addEventListener('click', () => {
                const unsafeToggle = $('unsafeToggle');
                if (unsafeToggle && unsafeToggle.checked) {
                    if (!confirm('⚠️ Unsafe Eval enabled - this is dangerous!\n\nContinue?')) return;
                }
                if (codeEl) runEval(codeEl.value);
            });
        }
        
        const btnBindUnsafe = $('btn-bind-unsafe');
        if (btnBindUnsafe) {
            btnBindUnsafe.addEventListener('click', () => {
                if (codeEl) bindUnsafe(codeEl.value);
            });
        }

        // 4. Toggles
        const jitToggle = $('jitToggle');
        if (jitToggle) {
            jitToggle.addEventListener('change', (e) => {
                enableJIT(e.target.checked);
                if (e.target.checked) {
                    alert('⚡ JIT Live Scanning habilitado!\n\nA análise será executada automaticamente enquanto você digita.');
                }
            });
        }
        
        const unsafeToggle = $('unsafeToggle');
        if (unsafeToggle) {
            unsafeToggle.addEventListener('change', (e) => {
                if (e.target.checked) {
                    if (!confirm('🚨 ATENÇÃO: Unsafe Mode ativado!\n\nIsso permite execução de eval() e bind ao window.\n\nUse APENAS com código de confiança!\n\nContinuar?')) {
                        e.target.checked = false;
                    }
                }
            });
        }

        // 5. Search
        if (qEl) {
            qEl.addEventListener('input', () => {
                const query = qEl.value.trim().toLowerCase();
                if (!lastScan) return;
                
                const filter = arr => (arr || []).filter(item => 
                    (item.name || item.id || '').toString().toLowerCase().includes(query) ||
                    (item.type || '').toString().toLowerCase().includes(query)
                );
                
                renderList(classesEl, filter(lastScan.classes || []));
                renderList(functionsEl, filter(lastScan.functions || []));
                renderList(globalsEl, filter(lastScan.globals || []));
                renderList(domidsEl, filter(lastScan.domIds || []));
            });
        }

        // 6. Security Actions
        const btnDeepScan = $('btn-deep-scan');
        if (btnDeepScan) {
            btnDeepScan.addEventListener('click', performDeepSecurityScan);
        }
        
        const btnExportSecurity = $('btn-export-security');
        if (btnExportSecurity) {
            btnExportSecurity.addEventListener('click', exportSecurityReport);
        }
        
        const btnRealTimeProtection = $('btn-real-time-protection');
        if (btnRealTimeProtection) {
            btnRealTimeProtection.addEventListener('click', enableRealTimeProtection);
        }
        
        const btnThreatMap = $('btn-threat-map');
        if (btnThreatMap) {
            btnThreatMap.addEventListener('click', () => {
                const modal = $('threatMapModal');
                const content = $('threatMapContent');
                
                if (!lastScan) {
                    alert('Execute um Scan primeiro para ver o mapa de ameaças.');
                    return;
                }
                
                if (!modal || !content) {
                    alert('Modal de mapa de ameaças não encontrado.');
                    return;
                }
                
                // Generate threat map content
                content.innerHTML = `
                    <h4>🗺️ Mapa de Ameaças do Código</h4>
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: ${Math.max(10, Math.min(100, currentSecurityScore))}%"></div>
                    </div>
                    <div style="text-align: center; margin: 20px 0;">
                        <div style="font-size: 36px; color: ${getScoreColor(currentSecurityScore)}">${currentSecurityScore}/100</div>
                        <div>Score de Segurança</div>
                    </div>
                    
                    <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 15px; margin-top: 20px;">
                        <div style="background: rgba(255,255,255,0.05); padding: 15px; border-radius: 10px;">
                            <div style="font-size: 24px; color: #60a5fa;">${lastScan.classes?.length || 0}</div>
                            <div>Classes</div>
                        </div>
                        <div style="background: rgba(255,255,255,0.05); padding: 15px; border-radius: 10px;">
                            <div style="font-size: 24px; color: #a78bfa;">${lastScan.functions?.length || 0}</div>
                            <div>Funções</div>
                        </div>
                        <div style="background: rgba(255,255,255,0.05); padding: 15px; border-radius: 10px;">
                            <div style="font-size: 24px; color: #fbbf24;">${lastScan.globals?.length || 0}</div>
                            <div>Globais</div>
                        </div>
                        <div style="background: rgba(255,255,255,0.05); padding: 15px; border-radius: 10px;">
                            <div style="font-size: 24px; color: #34d399;">${lastScan.domIds?.length || 0}</div>
                            <div>Elementos DOM</div>
                        </div>
                    </div>
                    
                    <div style="margin-top: 20px; padding: 15px; background: rgba(255,255,255,0.05); border-radius: 10px;">
                        <h5>Recomendações de Segurança:</h5>
                        <ul style="margin: 10px 0; padding-left: 20px;">
                            <li>Use HTTPS para todas as requisições</li>
                            <li>Implemente Content Security Policy (CSP)</li>
                            <li>Valide todas as entradas do usuário</li>
                            <li>Sanitize saídas para prevenir XSS</li>
                            <li>Use prepared statements para SQL</li>
                            <li>Nunca armazene segredos no código fonte</li>
                        </ul>
                    </div>
                `;
                
                modal.style.display = 'flex';
            });
        }
        
        const btnCveCheck = $('btn-cve-check');
        if (btnCveCheck) {
            btnCveCheck.addEventListener('click', performCVECheck);
        }

        // Close modal when clicking outside
        const threatMapModal = $('threatMapModal');
        if (threatMapModal) {
            threatMapModal.addEventListener('click', (e) => {
                if (e.target === threatMapModal) {
                    e.target.style.display = 'none';
                }
            });
        }

        // 7. Keyboard Shortcuts
        document.addEventListener('keydown', (e) => {
            // Ctrl+Enter = Scan
            if (e.ctrlKey && e.key === 'Enter') {
                e.preventDefault();
                scanAndRender();
            }
            
            // Ctrl+Shift+S = Deep Security Scan
            if (e.ctrlKey && e.shiftKey && e.key === 'S') {
                e.preventDefault();
                performDeepSecurityScan();
            }
            
            // Ctrl+E = Export
            if (e.ctrlKey && e.key === 'e') {
                e.preventDefault();
                if (lastScan && typeof exportJson === 'function') {
                    exportJson(lastScan, 'js_inspector_report.json', safeStringify);
                }
            }
            
            // Ctrl+J = Toggle JIT
            if (e.ctrlKey && e.key === 'j') {
                e.preventDefault();
                const jitToggle = $('jitToggle');
                if (jitToggle) {
                    jitToggle.checked = !jitToggle.checked;
                    enableJIT(jitToggle.checked);
                }
            }
        });
    }

    /* ============================
       Initialize Application - CORRIGIDO
       ============================ */
    function initApp() {
        // Initialize event listeners
        initAppListeners();
        
        // Initialize syntax highlighting - CORRIGIDO
        setTimeout(() => {
            highlightAllCodeBlocks();
        }, 100);
        
        // Set initial code example
        if (codeEl && !codeEl.value.trim()) {
            codeEl.value = `// JS Inspector Pro Elite Security
// Cole seu código JavaScript aqui e clique em Scan para análise

function helloWorld() {
    console.log("Olá, segurança!");
}

class Calculator {
    add(a, b) {
        return a + b;
    }
}

const result = new Calculator().add(2, 3);
console.log("Resultado:", result);

// Elementos DOM
document.getElementById("app");
document.querySelector(".content");`;
        }
        
        // Perform initial scan
        setTimeout(() => {
            scanAndRender().catch(e => {
                console.log('Initial scan skipped or failed (normal for empty code):', e);
            });
        }, 500);
        
        console.log('🚀 JS Inspector Pro Elite Security inicializado!');
    }

    // Start the application when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initApp);
    } else {
        initApp();
    }

    // Make functions available globally for debugging (opcional)
    try {
        window.jsInspector = {
            scanAndRender,
            performDeepSecurityScan,
            performCVECheck,
            runInIframe,
            runEval,
            bindUnsafe,
            enableRealTimeProtection,
            exportSecurityReport
        };
    } catch (e) {
        console.warn('Could not expose jsInspector to window:', e);
    }
