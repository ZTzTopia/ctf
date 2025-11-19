import Java from "frida-java-bridge";

Java.perform(() => {
    console.log("Java:", Java.available);

    setTimeout(() => {
        Java.enumerateLoadedClasses({
            onMatch: (className) => { },
            onComplete: () => {
                const m = Process.getModuleByName('libil2cpp.so');

                console.log("[*] libil2cpp.so base address:", m.base);

                const SCORE = 13371337;

                const fnPtr = m.base.add(0x6d5024); // set_score
                const fn = new NativeFunction(fnPtr, 'void', ['pointer', 'int']);

                const fn2Ptr = m.base.add(0x6d5034); // set_encryptedScore
                const fn2 = new NativeFunction(fn2Ptr, 'void', ['pointer', 'int']);

                const fn3Ptr = m.base.add(0x6D44F4); // Encrypt?
                const fn3 = new NativeFunction(fn3Ptr, 'int', ['int']);

                Interceptor.attach(m.base.add(0x6d5460), {
                    onEnter(args) {
                        console.log('IncreaseScore called');

                        fn(args[0], SCORE);

                        console.log(`Calling set_encryptedScore with ${fn3(SCORE)}`);
                        fn2(args[0], Number(fn3(SCORE)));
                    },
                    onLeave(retval) { }
                });
            }
        });
    }, 1000);
});
