import Java from "frida-java-bridge";

const PTR_SIZE = Process.pointerSize;
const SIZE_T = PTR_SIZE === 8 ? "ulong" : "uint";
const MASK64 = ptr("0x00ffffffffffffff"); // strip top-byte tag (AArch64 TBI/MTE)

const untag = (p: NativePointer) =>
  (Process.arch === "arm64") ? p.and(MASK64) : p;

function tryReadUtf8String(p: NativePointer): string | null {
  if (p.isNull()) {
    return "";
  }

  try {
    return p.readUtf8String();
  } catch {
    return "";
  }
}

function looksPrintableId(s: string) {
  // tolerate C# identifiers + dots/backticks for generics
  return s.length > 0 && s.length < 256 && /^[\w.`$<>+,-]+$/.test(s);
}

// Fast fallback if export fails: scan MethodInfo head for a likely name ptr
function readMethodNameViaStruct(mi: NativePointer): string {
  const base = untag(mi);
  // scan first 0x80 bytes for a pointer to a short printable string
  for (let off = 0; off < 0x80; off += PTR_SIZE) {
    const p = base.add(off).readPointer();
    const s = tryReadUtf8String(p) || "";
    if (looksPrintableId(s) && /[A-Za-z_]/.test(s[0])) {
      return s;
    }
  }

  return "";
}

Java.perform(() => {
  console.log("[*] Java:", Java.available);

  setTimeout(() => {
    Java.enumerateLoadedClasses({
      onMatch: (className) => {},
      onComplete: () => {
        const m = Process.getModuleByName("libil2cpp.so");

        console.log("[*] libil2cpp.so base address:", m.base);

        const il2cpp_thread_attach = new NativeFunction(
          m.findExportByName("il2cpp_thread_attach")!,
          "pointer",
          ["pointer"]
        );

        const il2cpp_domain_get = new NativeFunction(
          m.findExportByName("il2cpp_domain_get")!,
          "pointer",
          []
        );

        const il2cpp_domain_get_assemblies = new NativeFunction(
          m.findExportByName("il2cpp_domain_get_assemblies")!,
          "pointer",
          ["pointer", "pointer"]
        );

        const il2cpp_assembly_get_image = new NativeFunction(
          m.findExportByName("il2cpp_assembly_get_image")!,
          "pointer",
          ["pointer"]
        );

        const il2cpp_image_get_name = new NativeFunction(
          m.findExportByName("il2cpp_image_get_name")!,
          "pointer",
          ["pointer"]
        );

        const il2cpp_image_get_class_count = new NativeFunction(
          m.findExportByName("il2cpp_image_get_class_count")!,
          SIZE_T,
          ["pointer"]
        );

        const il2cpp_image_get_class = new NativeFunction(
          m.findExportByName("il2cpp_image_get_class")!,
          "pointer",
          ["pointer", SIZE_T]
        );

        const il2cpp_class_get_type = new NativeFunction(
          m.findExportByName("il2cpp_class_get_type")!,
          "pointer",
          ["pointer"]
        );

        const il2cpp_type_get_name = new NativeFunction(
          m.findExportByName("il2cpp_type_get_name")!,
          "pointer",
          ["pointer"]
        );

        const il2cpp_class_get_methods = new NativeFunction(
          m.findExportByName("il2cpp_class_get_methods")!, "pointer", ["pointer", "pointer"]
        );
        const il2cpp_method_get_name = new NativeFunction(
          m.findExportByName("il2cpp_method_get_name")!, "pointer", ["pointer"]
        );
        const il2cpp_method_get_param_count = new NativeFunction(
          m.findExportByName("il2cpp_method_get_param_count")!, "uint", ["pointer"]
        );

        setTimeout(() => {
          try {
            const domain = il2cpp_domain_get();
            if (!domain) {
              return console.error("[!] il2cpp_domain_get() returned null");
            }

            console.log("[*] il2cpp_domain_get():", domain);
            il2cpp_thread_attach(domain);

            const assembliesSizePtr = Memory.alloc(PTR_SIZE);
            assembliesSizePtr.writeU64(0);
            const assembliesPtr = il2cpp_domain_get_assemblies(domain, assembliesSizePtr);
            const assembliesCount = Number(assembliesSizePtr.readU64());

            console.log(`[*] ${assembliesCount} assemblies loaded`);

            for (let i = 0; i < assembliesCount; i++) {
              const assembly = assembliesPtr.add(i * PTR_SIZE).readPointer();
              console.log(`    [*] Assembly ${i}:`, assembly);

              /* const image = il2cpp_assembly_get_image(assembly);
              console.log(`         image:`, image);

              const namePtr = il2cpp_image_get_name(image);
              console.log(`         namePtr:`, namePtr);

              const name = namePtr.isNull() ? "" : namePtr.readByteArray(32);
              console.log(`         name:`, name); */

              const image = untag(assembly).readPointer();

              const pName = untag(image).readPointer();
              const pNameNoExt = untag(image).add(PTR_SIZE).readPointer();
              const pAsmName = untag(image).add(2 * PTR_SIZE).readPointer();

              const name = tryReadUtf8String(pName);
              const nameNoExt = tryReadUtf8String(pNameNoExt);
              const asmName = tryReadUtf8String(pAsmName);

              console.log(
                `    [*] Assembly ${i}: ${assembly}\n` +
                `         image: ${image}\n` +
                `         name: ${name}\n` +
                `         nameNoExt: ${nameNoExt}\n` +
                `         assemblyName: ${asmName}`
              );

              if (name !== "Assembly-CSharp.dll") {
                continue;
              }

              const classCount = il2cpp_image_get_class_count(image);
              console.log(`         classCount:`, classCount);

              for (let j = 0; j < classCount; j++) {
                const klass = il2cpp_image_get_class(image, j);

                const pName = untag(klass).add(2 * PTR_SIZE).readPointer();

                const name = tryReadUtf8String(pName);

                console.log(`             [*] Class ${j}: ${klass} - ${name}`);

                // if (name !== "GameManager") {
                //   continue;
                // }

                const iterPtr = Memory.alloc(PTR_SIZE);
                iterPtr.writePointer(NULL);

                while (true) {
                  const methodsPtr = il2cpp_class_get_methods(untag(klass), iterPtr);
                  if (methodsPtr.isNull()) {
                    break;
                  }

                  const methodNamePtr = il2cpp_method_get_name(untag(methodsPtr));
                  const methodName = tryReadUtf8String(methodNamePtr);
                  const methodNameViaStruct = readMethodNameViaStruct(methodsPtr);

                  const paramCount = il2cpp_method_get_param_count(untag(methodsPtr));
                  const VA = untag(methodsPtr).readPointer();
                  const RVA = VA.sub(untag(m.base));

                  console.log(`                 - Method: ${VA} (RVA ${untag(RVA)}) ${methodNameViaStruct} (params: ${paramCount})`);

                  if (methodNameViaStruct !== "IncreaseScore") {
                    continue;
                  }

                  console.log(`                   -> Found IncreaseScore method name, hooking...`);

                  const SCORE = 13371337;

                  const fnPtr = m.base.add(0x6d5024); // set_score
                  const fn = new NativeFunction(fnPtr, "void", ["pointer", "int"]);

                  const fn2Ptr = m.base.add(0x6d5034); // set_encryptedScore
                  const fn2 = new NativeFunction(fn2Ptr, "void", ["pointer", "int"]);

                  const fn3Ptr = m.base.add(0x6D44F4); // Encrypt?
                  const fn3 = new NativeFunction(fn3Ptr, "int", ["int"]);

                  Interceptor.attach(RVA.add(m.base), {
                    onEnter(args) {
                      console.log(`                  -> ${methodNameViaStruct} called`);

                      fn(args[0], SCORE);

                      console.log(`Calling set_encryptedScore with ${fn3(SCORE)}`);
                      fn2(args[0], Number(fn3(SCORE)));
                    },
                    onLeave(retval) {}
                  });
                }
              }
            }
          } catch (e) {
            return console.error("[!] Failed:", e);
          }
        }, 1500);
      }
    });
  }, 1000);
});