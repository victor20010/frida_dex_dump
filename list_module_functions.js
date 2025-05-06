function listAllFunctions(moduleName) {
    const baseAddr = Module.findBaseAddress(moduleName);
    if (!baseAddr) {
        console.error(`[-] ${moduleName} не найден.`);
        return;
    }

    console.log(`[+] ${moduleName} базовый адрес:`, baseAddr);

    const symbols = Module.enumerateSymbolsSync(moduleName);
    let count = 0;

    for (let sym of symbols) {
        if (sym.type === 'function') {
            console.log(`[${count}]`, sym.address, sym.name);
            count++;
        }
    }

    console.log(`[*] Всего найдено символов функций в ${moduleName}:`, count);
}

// Перечисление всех функций в libart.so
setImmediate(function () {
    listAllFunctions("libart.so");
});


// frida -H 127.0.0.1:1234  -F -l list_module_functions.js -o log.txt
