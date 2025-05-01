import pyshark
from encryption import Encryption
from session_key import SessionKey

pcap_file = '../dist/capture.pcapng'
cap = pyshark.FileCapture(pcap_file, display_filter='tcp')

for packet in cap:
    try:
        if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'payload'):
            # print(f'Packet {packet.number}: {packet.tcp.payload}')
            payload = bytes.fromhex(packet.tcp.payload.replace(':', ''))

            if len(payload) == 16:
                print(f'Challenge packet {packet.number}: {payload.hex()}')
                continue
            elif len(payload) == 48:
                print(f'Challenge response packet {packet.number}: {payload.hex()}')
                continue

            print(f'Packet {packet.number}: {payload.hex()}')
            message = Encryption.decrypt(SessionKey.derive_session_key().encode(), payload)
            print(f'Decrypted message: {message}')
    except Exception as e:
        print(f'Error processing packet {packet.number}: {e}')
        continue

cap.close()
