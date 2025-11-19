from scapy.all import rdpcap
import base64
import hashlib
import re
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

key = hashlib.sha256(b"aewfoijdc887xc6qwj21t").digest()

pcap_file = "capture.pcapng"
packets = rdpcap(pcap_file)

# group by TCP stream (src/dst/ports)
sessions = packets.sessions()

cmds = []
for sess, pkts in sessions.items():
    data = b''.join(pkt["Raw"].load for pkt in pkts if pkt.haslayer("Raw"))
    # find all oldcss=... tokens (across reassembled data)
    for b64val in re.findall(rb"oldcss=([A-Za-z0-9+/=]+)", data):
        raw = base64.b64decode(b64val)
        iv, ct = raw[:16], raw[16:]
        pt = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
        cmds.append(unpad(pt, 16).decode("utf-8","ignore"))

for i, cmd in enumerate(cmds, 1):
    print(f"{i:02d}: {cmd}")
