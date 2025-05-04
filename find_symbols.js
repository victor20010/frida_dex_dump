// Frida 脚本：查找所有模块中包含 "OpenCommon" 或 "DexFileLoader" 的函数符号
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
            // 某些模块无法枚举，忽略
        }
    }
}

setImmediate(() => {
    console.log("[*] Scanning for symbols containing 'OpenCommon' or 'DexFileLoader' ...");
    scanModulesForKeywords(["DexFile"]);
    console.log("[*] Done.");
});


// frida -H 127.0.0.1:1234  -F -l find_symbols.js -o log.txt
