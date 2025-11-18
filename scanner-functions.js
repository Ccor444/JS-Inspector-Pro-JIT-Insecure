// scanner-functions.js
// Autor: Cleiton & ChatGPT — Modo Insano Dev
// Scanner avançado para localizar TODAS as funções possíveis dentro de um arquivo JS

export function scanFunctions(source) {
    const results = [];

    const lines = source.split(/\r?\n/);

    // =============== REGEX AVANÇADAS ===============

    // function foo() {}
    const re_named_function = /^\s*(async\s+)?function\s+([A-Za-z0-9_$]+)\s*\(/;

    // const foo = function() {}
    const re_var_function = /^\s*(const|let|var)\s+([A-Za-z0-9_$]+)\s*=\s*(async\s+)?function\s*\(/;

    // const foo = () => {}
    const re_arrow_function = /^\s*(const|let|var)\s+([A-Za-z0-9_$]+)\s*=\s*(async\s+)?\(/;

    // foo: function() {}
    const re_object_function = /^\s*([A-Za-z0-9_$]+)\s*:\s*(async\s+)?function\s*\(/;

    // métodos de classe
    const re_class_method = /^\s*(async\s+)?([A-Za-z0-9_$]+)\s*\((.*?)\)\s*\{/;

    // =============== LOOP DE LEITURA ===============
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        let match;

        // function foo()
        if ((match = line.match(re_named_function))) {
            results.push({
                type: "function-declaration",
                name: match[2],
                line: i + 1,
                async: !!match[1]
            });
            continue;
        }

        // const foo = function()
        if ((match = line.match(re_var_function))) {
            results.push({
                type: "var-function",
                name: match[2],
                line: i + 1,
                async: !!match[3]
            });
            continue;
        }

        // const foo = () =>
        if ((match = line.match(re_arrow_function))) {
            results.push({
                type: "arrow-function",
                name: match[2],
                line: i + 1,
                async: !!match[3]
            });
            continue;
        }

        // foo: function()
        if ((match = line.match(re_object_function))) {
            results.push({
                type: "object-function",
                name: match[1],
                line: i + 1,
                async: !!match[2]
            });
            continue;
        }

        // método de classe
        if ((match = line.match(re_class_method))) {
            // Não capturar palavras-chave especiais (constructor)
            if (match[2] !== "constructor") {
                results.push({
                    type: "class-method",
                    name: match[2],
                    line: i + 1,
                    async: !!match[1]
                });
            }
            continue;
        }
    }

    // Modo avançado: remover duplicados por segurança
    const unique = {};
    const final = [];

    for (const f of results) {
        const key = f.name + "_" + f.line;
        if (!unique[key]) {
            unique[key] = true;
            final.push(f);
        }
    }

    return final;
}

// =============== DEBUG DIRETO NO CONSOLE ===============
export function scanFunctionsDebug(source) {
    console.log("=== SCANNER FUNCTIONS ===");
    const res = scanFunctions(source);
    res.forEach(fn => {
        console.log(`[${fn.type}] ${fn.name} (linha ${fn.line}) ${fn.async ? "async" : ""}`);
    });
    console.log("=========================");
    return res;
}