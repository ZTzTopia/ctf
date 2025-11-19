import fs from "fs";

const x = (block1, block2) => {
    if (block1.length !== 8 || block2.length !== 8)
        throw new Error("Cannot encrypt, invalid block");
    return block1.map((byte, idx) => byte ^ block2[idx]);
};

const decryptData = (encryptedData, keyBytes, nonce) => {
    if (encryptedData.length % 8 !== 0)
        throw new Error("Cannot decrypt, invalid block");

    let decryptedBlocks = [];
    let currentVector = nonce.slice(0, 8);

    function decryptBlock(block) {
        return x(block, keyBytes); // same as encryption due to XOR symmetry
    }

    for (let i = 0; i < encryptedData.length; i += 8) {
        const encryptedBlock = encryptedData.slice(i, i + 8);
        const temp = decryptBlock(encryptedBlock);
        const originalBlock = x(temp, currentVector);
        decryptedBlocks.push(originalBlock);
        // Update current vector just like in encryption
        currentVector = x(encryptedBlock, originalBlock);
    }

    return decryptedBlocks.flat();
};

const decryptCapturedPayload = (payload) => {
    // Extract the prefix (magic bytes + hostname)
    const prefix = payload.slice(0, payload.indexOf(0));
    
    let dataStartIndex = payload.indexOf(0) + 1 + 8;
    const encryptedData = payload.slice(dataStartIndex);
    
    return encryptedData;
};

async function getNonce(timestamp) {
    const encoder = new TextEncoder();
    const hashBuffer = await crypto.subtle.digest(
        "SHA-256",
        encoder.encode(timestamp.toString())
    );
    return Array.from(new Uint8Array(hashBuffer)).slice(0, 8);
}

const s = [];
const encryptedData = fs.readFileSync("6fd3c199ffa6a3f32156d117844dcb18b25a638b268e6ce92c840fe406dd7bc2_2025-05-09T06:48:08.599Z.bin");

const currentTime = Math.floor(new Date('2025-05-09T06:48:08.599Z').getTime() / 1e3);
// console.log("Timestamp:", currentTime);

for (let yyy = currentTime - 5; yyy < currentTime + 5; yyy++) {
    let nonce = await getNonce(yyy);
    // console.log("Nonce:", nonce);

    const payload = decryptCapturedPayload(encryptedData);

    for (let wtf = 0; wtf < 90; wtf++) {
        const k1 = ["absolute","activate","baseline","blending","bordered","boxstyle","browsing","centrate","circular","clipping","collapse","columned","computed","contrast","cropping","cursived","declared","defaultt","dimcolor","disabled","dividing","dropping","ellipsis","emphasis","enlarged","expanded","facesize","fanciful","filtered","flexwrap","floating","fontsize","fontface","fonttype","foremost","formlook","gradient","graphics","gridlook","grouping","headings","hovering","imagemap","imported","inlining","innerbox","inputbox","inserted","isolated","italicst","junction","justifyt","kernings","keyframe","labeling","layering","leadings","lineheig","linktype","listitem","markdown","maskstyp","matching","maximums","measures","mimetype","minified","minwidth","mouseout","moveable","multisel","navstyle","negative","newtabst","nobreaks","nonclear","nospaced","numerate","offwhite","opaquely","outlines","overlaid","overflow","override","pacingst","paddings","pageflow","pagesize","paneling","patterns","pinnable","pointing"][wtf]
        const keyBytes = Array.from(new TextEncoder().encode(k1));

        const decryptedBytes = decryptData(payload, keyBytes, nonce);

        const newBytesArray = [];
        for (let i = 0; i < decryptedBytes.length; i++) {
            for (let j = 0; j < 8; j++) {
                newBytesArray.push(decryptedBytes[i][j]);
            }
        }

        s.push(100, 48, 110, 103, 48);

        let hostname = 'id.kraken.com';
        if (hostname.length > 0) {
            const hostnameBytes = hostname.split("").map(ch => ch.charCodeAt(0));
            s.push(...hostnameBytes);
        }
        s.push(0);

        nonce = await getNonce(yyy);
        nonce.forEach(byte => {
            if (byte <= 256) {
                s.push(0);
            }
        });

        function unshuffleDataBytes(dataBytes, s) {
            // Recreate the seedArray used during shuffle
            const seedArray = s.reduce((acc, value) => {
                if (value === 0 || acc.done) {
                    acc.done = true;
                    return acc;
                }
                acc.result.push(value);
                return acc;
            }, { result: [], done: false }).result;

            const arr = Array.from(dataBytes);
            const len = arr.length;

            // Rebuild the original swap sequence
            const swaps = [];
            for (let i = 0; i < len; i++) {
                const swapIndex = seedArray[i % seedArray.length] % len;
                swaps.push([i, swapIndex]);
            }

            // Undo swaps in reverse order
            for (let i = swaps.length - 1; i >= 0; i--) {
                const [a, b] = swaps[i];
                [arr[a], arr[b]] = [arr[b], arr[a]];
            }

            return arr;
        }

        const dataBytes = unshuffleDataBytes(newBytesArray, s);
        const dataString = String.fromCharCode(...dataBytes);

        if (dataString.includes("IFEST13")) {
            console.log("Found IFEST13 in dataString:", dataString);
            break;
        }
    }
}
