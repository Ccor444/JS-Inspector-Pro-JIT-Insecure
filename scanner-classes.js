// scanner-classes.js
// Autor: Cleiton & ChatGPT — Scanner avançado de classes JS

export function scanClasses(source) {
    const results = [];
    const lines = source.split(/\r?\n/);

    // ===== REGEX AVANÇADAS PARA CAPTURAR CLASSES =====

    // class Nome {  }  — normal
    const re_class_named = /^\s*class\s+([A-Za-z0-9_$]+)\s*(?:extends\s+([A-Za-z0-9_$\.]+))?\s*\{/;

    // const X = class {  } — classes anônimas atribuídas
    const re_class_assigned = /^\s*(const|let|var)\s+([A-Za-z0-9_$]+)\s*=\s*class\s*(?:extends\s+([A-Za-z0-9_$\.]+))?\s*\{/;

    // class dentro de objetos: obj.Algo = class {...}
    const re_class_property = /^\s*([A-Za-z0-9_$\.]+)\s*=\s*class\s*(?:extends\s+([A-Za-z0-9_$\.]+))?\s*\{/;

    // ===== MÉTODOS DA CLASSE =====
    const re_class_method = /^\s*(async\s+)?([A-Za-z0-9_$]+)\s*\(/;

    let insideClass = false;
    let currentClass = null;

    // ===== VARREDURA LINHA POR LINHA =====
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        let match;

        // 1 — class Nome
        if (!insideClass && (match = line.match(re_class_named))) {
            currentClass = {
                type: "class",
                name: match[1],
                extends: match[2] || null,
                line: i + 1,
                methods: []
            };
            insideClass = true;
            continue;
        }

        // 2 — const X = class
        if (!insideClass && (match = line.match(re_class_assigned))) {
            currentClass = {
                type: "class-assigned",
                name: match[2],
                extends: match[3] || null,
                line: i + 1,
                methods: []
            };
            insideClass = true;
            continue;
        }

        // 3 — obj.prop = class
        if (!insideClass && (match = line.match(re_class_property))) {
            currentClass = {
                type: "class-property",
                name: match[1],
                extends: match[2] || null,
                line: i + 1,
                methods: []
            };
            insideClass = true;
            continue;
        }

        // ===== Dentro da classe: capturar métodos =====
        if (insideClass) {
            // fechar classe
            if (line.includes("}")) {
                results.push(currentClass);
                insideClass = false;
                currentClass = null;
                continue;
            }

            // métodos
            if ((match = line.match(re_class_method))) {
                const methodName = match[2];

                // evitar palavras inválidas
                if (!["if", "for", "while", "switch"].includes(methodName)) {
                    currentClass.methods.push({
                        name: methodName,
                        async: !!match[1],
                        line: i + 1
                    });
                }
            }
        }
    }

    return results;
}


// ===== DEBUG PRONTO =====
export function scanClassesDebug(source) {
    console.log("=== SCANNER CLASSES ===");
    const res = scanClasses(source);

    res.forEach(c => {
        console.log(
            `[CLASS] ${c.name}` +
            (c.extends ? ` extends ${c.extends}` : "") +
            ` (linha ${c.line})`
        );

        c.methods.forEach(m => {
            console.log(
                `   -> método ${m.name} (linha ${m.line}) ${m.async ? "async" : ""}`
            );
        });
    });

    console.log("=========================");
    return res;
}