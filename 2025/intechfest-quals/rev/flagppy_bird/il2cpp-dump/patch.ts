import "frida-il2cpp-bridge";
import Java from "frida-java-bridge";

Interceptor.attach(Module.getGlobalExportByName("dl_iterate_phdr"), {
    onEnter(args) {
        this.cb = args[0];
        this.data = args[1];

        try {
            const seenPtr = this.data.add(Process.pointerSize).readPointer();
            // console.log('[*] seenPtr =', seenPtr);
            if (!seenPtr.isNull()) {
                seenPtr.writeU8(1);
                // console.log('[*] forced seen=1');
            }
        } catch (e) {
            console.error(e);
        }
    },
    onLeave(retval) {}
});

Java.perform(() => {
  console.log("[*] Java:", Java.available);

  setTimeout(() => {
    Java.enumerateLoadedClasses({
      onMatch: (className) => {},
      onComplete: () => {
        Il2Cpp.perform(() => {
            console.log(`Hello, Unity ${Il2Cpp.unityVersion}`);

            Il2Cpp.domain.assembly("Assembly-CSharp").image.classes.forEach(klass => {
                console.log(`[*] ${klass.name} (${klass.methods.length} methods)`);
                klass.methods.forEach(method => {
                    console.log(`   [*] ${method.name} (${method.parameters.length} params) (VA: ${method.virtualAddress}) (RVA: ${method.relativeVirtualAddress})`);
                });
            });
        });
      }
    });
  }, 1000);
});
