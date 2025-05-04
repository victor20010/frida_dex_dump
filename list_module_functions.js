function listAllFunctions(moduleName) {
    const baseAddr = Module.findBaseAddress(moduleName);
    if (!baseAddr) {
        console.error(`[-] ${moduleName} not found.`);
        return;
    }

    console.log(`[+] ${moduleName} base address:`, baseAddr);

    const symbols = Module.enumerateSymbolsSync(moduleName);
    let count = 0;

    for (let sym of symbols) {
        if (sym.type === 'function') {
            console.log(`[${count}]`, sym.address, sym.name);
            count++;
        }
    }

    console.log(`[*] Total function symbols found in ${moduleName}:`, count);
}

// 列出 libart.so 的所有函数
setImmediate(function () {
    listAllFunctions("libart.so");
});


// frida -H 127.0.0.1:1234  -F -l list_module_functions.js -o log.txt