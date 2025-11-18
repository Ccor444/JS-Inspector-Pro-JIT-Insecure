// ui-utils.js

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
  
  // Usa a função de serialização passada, que deve ser safeStringify
  const jsonString = typeof stringifyFn === 'function' ? stringifyFn(data) : JSON.stringify(data, null, 2);
  
  const blob = new Blob([jsonString], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/**
 * Copia um objeto de dados para a área de transferência do sistema.
 * @param {object} data - Os dados de análise a serem copiados.
 * @param {function} stringifyFn - A função para serializar o objeto (safeStringify).
 */
export function copyJson(data, stringifyFn) {
  if (!data) {
    alert('Nenhum dado de análise disponível para copiar.');
    return;
  }

  const jsonString = typeof stringifyFn === 'function' ? stringifyFn(data) : JSON.stringify(data, null, 2);
  
  // Usa a API Clipboard (requer contexto seguro/HTTPS)
  navigator.clipboard.writeText(jsonString)
    .then(() => alert('Análise copiada para a área de transferência!'))
    .catch(err => {
      console.error('Erro ao copiar:', err);
      alert('Erro ao copiar. Permissão negada ou função indisponível.');
    });
}
