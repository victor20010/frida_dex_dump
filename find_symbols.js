function scanModulesForKeywords(keywords) {
    const modules = Process.enumerateModules();
    keywords = keywords.map(k => k.toLowerCase());

    for (const module of modules) {
        try {
            const symbols = Module.enumerateSymbols(module.name);
            for (const symbol of symbols) {
                if (symbol.type === 'function') {
                    const lowerName = symbol.name.toLowerCase();
                    if (keywords.some(k => lowerName.includes(k))) {
                        console.log(`[+] ${module.name} -> ${symbol.name} @ ${symbol.address}`);
                    }
                }
            }
        } catch (e) {
            // Некоторые модули не могут быть перечислены, игнорируем
        }
    }
}

setImmediate(() => {
    console.log("[*] Сканирование символов, содержащих 'OpenCommon' или 'DexFileLoader' ...");
    scanModulesForKeywords(["DexFile"]);
    console.log("[*] Готово.");
});


// frida -H 127.0.0.1:1234  -F -l find_symbols.js -o log.txt
