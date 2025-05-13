import base64
from Crypto.Cipher import AES

base64_ciphertext = (
    "6kGrsTkEwA0bU526wlqbjD98CkEP7jqAw3oEm2oTHS9wnXWer25jeDmNnCq088+mKXXN36QcQkFGL7xp8hPqvV66JZkRinvWFW/pZ"
    "Tybuo5NR9MsKLl5LKQ+APRU5e10h4lD2y607Z90x0yzHkuCeuG4vzBYiTwzNv0YvXAEkn8VUEklZ3ngsg9T6UZm4HvJdJUiPkzg8p"
    "VBJNaCmgSdkYCdzuhBPDhnbGo+xqQAvsl97hjlNFNKTqazjdLJgJLwl+juzLQwzBUiW9Fi55aGmIbrO2SDFTZSSlJNhNXqcTlA"
)
key_source = (
    "ShimpaziniBananiwaifu.find-it.id0123456789abcdefTerminateProcessexec: no command23841857910156250123456789ABCDEFinvalid exchangeno route to hostinvalid argumentmessage too longobject is remoteremote I/O errorSetFilePointerExOpenProcessTokenRegQueryInfoKeyWRegQueryValueExWDnsNameCompare_WCreateDirectoryWFlushFileBuffersGetComputerNameWGetFullPathNameWGetLongPathNameWRemoveDirectoryWNetApiBufferFreeDuplicateTokenExGetCurrentThreadGetModuleHandleWRtlVirtualUnwindinteger overflowgcshrinkstackofftracefpunwindoffGC scavenge waitGC worker (idle)page trace flush/gc/gogc:percent, not a functiongc: unswept span KiB work (bg),  mheap.sweepgen=runtime: nelems=workbuf is emptymSpanList.removemSpanList.insertbad special kindbad summary dataruntime: addr = runtime: base = runtime: head = timeBeginPeriod"
)

key = key_source[:16].encode("utf-8")
data = base64.b64decode(base64_ciphertext)

nonce_size = 12
nonce = data[:nonce_size]
ciphertext_and_tag = data[nonce_size:]

try:
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext_and_tag[:-16], ciphertext_and_tag[-16:])
    print("Decrypted plaintext:", plaintext.decode("utf-8"))
except Exception as e:
    print("Decryption failed:", str(e))
