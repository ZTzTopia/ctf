import scapy.all as scapy
import zlib

scapy_cap = scapy.rdpcap('1.pcapng')
with open('output', 'wb') as f:
    for packet in scapy_cap:
        # ICMP ONLY
        if packet.haslayer(scapy.ICMP):
            f.write(bytes.fromhex((bytes(packet.payload)[28:]).decode('utf-8')))


# Read the extracted payload
with open('output', 'rb') as f:
    data = f.read()

# Split at every zlib header
parts = data.split(b'\x78\x9c')

# print(f"Found {parts} parts in the data")

count = 0
for part in parts[1:]:  # skip the first empty split
    try:
        # get last byte
        print(f'Last 1-byte: {ord(part[-1:])}')
        decompressed = zlib.decompress(b'\x78\x9c' + part)
        with open(f'z_{ord(part[-1:])}.png', 'wb') as out:
            out.write(decompressed)
        count += 1
    except:
        continue

print(f'Extracted {count} PNG files')
