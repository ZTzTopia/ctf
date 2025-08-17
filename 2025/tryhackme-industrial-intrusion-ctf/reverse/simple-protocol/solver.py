import socket
import struct

SERVER_HOST = '10.10.162.28'
SERVER_PORT = 4444

def send_packet(command_id, payload_id):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((SERVER_HOST, SERVER_PORT))

    v4 = 0x1234
    v5 = command_id
    payload_id_net = payload_id
    some_value = payload_id_net

    checksum = ((v4 ^ v5) << 16) | (some_value & 0xFFFF)

    header = struct.pack('!HHII', v4, v5, checksum, payload_id_net)
    metadata = struct.pack('!II', payload_id_net, 0)

    sock.sendall(header)
    sock.sendall(metadata)

    print("Packet sent successfully.")

    response = sock.recv(4096)
    print("Response received:", response)

    sock.close()

send_packet(command_id=256, payload_id=0xdeadbeef)
