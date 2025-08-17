---
title: "Simple Protocol"
categories: Reverse Engineering
tags: 
draft: false
completedDuringEvent: true
submitted: true
points: 90
solves: -1
flags: THM{REDACTED}
---
> Amid whirring routers and blinking panel lights, ZeroTrace dissects a custom network protocol linking industrial subsystems. Patterns in the packet flow hint at secrets embedded deep within machine chatter.

---

This challenge involves reverse engineering a server that listens on port `4444` and processes incoming packets based on a custom protocol. The server validates packets using a checksum and metadata before executing specific commands based on the `command_id` provided in the packet.

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  uint16_t v4; // [rsp+Ch] [rbp-74h]
  uint16_t v5; // [rsp+Eh] [rbp-72h]
  socklen_t addr_len; // [rsp+10h] [rbp-70h] BYREF
  int fd; // [rsp+14h] [rbp-6Ch]
  int v8; // [rsp+18h] [rbp-68h]
  uint32_t v9; // [rsp+1Ch] [rbp-64h]
  uint32_t v10; // [rsp+20h] [rbp-60h]
  int v11; // [rsp+24h] [rbp-5Ch]
  uint32_t v12; // [rsp+28h] [rbp-58h]
  uint32_t v13; // [rsp+2Ch] [rbp-54h]
  ssize_t v14; // [rsp+30h] [rbp-50h]
  uint32_t v15[2]; // [rsp+3Ch] [rbp-44h] BYREF
  uint16_t buf[2]; // [rsp+44h] [rbp-3Ch] BYREF
  uint32_t netlong; // [rsp+48h] [rbp-38h]
  uint32_t v18; // [rsp+4Ch] [rbp-34h]
  sockaddr addr; // [rsp+50h] [rbp-30h] BYREF
  struct sockaddr v20; // [rsp+60h] [rbp-20h] BYREF
  unsigned __int64 v21; // [rsp+78h] [rbp-8h]

  v21 = __readfsqword(0x28u);
  addr_len = 16;
  fd = socket(2, 1, 0);
  if ( fd < 0 )
  {
    perror("socket");
    exit(1);
  }
  addr.sa_family = 2;
  *(_DWORD *)&addr.sa_data[2] = 0;
  *(_WORD *)addr.sa_data = htons(0x115Cu);
  if ( bind(fd, &addr, 0x10u) < 0 )
  {
    perror("bind");
    exit(1);
  }
  if ( listen(fd, 5) < 0 )
  {
    perror("listen");
    exit(1);
  }
  printf("Listening on port %d\n", 4444);
  v8 = accept(fd, &v20, &addr_len);
  if ( v8 < 0 )
  {
    perror("accept");
    exit(1);
  }
  puts("Connection received.");
  v14 = recv(v8, buf, 0xCuLL, 256);
  if ( v14 != 12 )
  {
    fwrite("Failed to receive header.\n", 1uLL, 0x1AuLL, stderr);
    exit(1);
  }
  v4 = ntohs(buf[0]);
  v5 = ntohs(buf[1]);
  v9 = ntohl(netlong);
  v10 = ntohl(v18);
  v11 = ((unsigned __int16)(v4 ^ v5) << 16) | (unsigned __int16)v10;
  if ( v9 != v11 )
  {
    fwrite("Checksum validation failed.\n", 1uLL, 0x1CuLL, stderr);
    exit(1);
  }
  v14 = recv(v8, v15, 8uLL, 256);
  if ( v14 != 8 )
  {
    fwrite("Failed to receive body metadata.\n", 1uLL, 0x21uLL, stderr);
    exit(1);
  }
  v12 = ntohl(v15[0]);
  v13 = ntohl(v15[1]);
  if ( v12 != v10 )
  {
    fwrite("Body payload_id does not match header.\n", 1uLL, 0x27uLL, stderr);
    exit(1);
  }
  if ( v13 > 0x40 )
  {
    fwrite("Payload size too large.\n", 1uLL, 0x18uLL, stderr);
    exit(1);
  }
  if ( v5 == 256 )
  {
    sub_1421((unsigned int)v8);
  }
  else
  {
    if ( v5 > 0x100u )
      goto LABEL_27;
    if ( v5 == 1 )
      sub_13C9((unsigned int)v8);
    if ( v5 != 16 )
    {
LABEL_27:
      fprintf(stderr, "Invalid command: 0x%x\n", v5);
      exit(1);
    }
    sub_13E2((unsigned int)v8);
  }
  close(v8);
  close(fd);
  return 0LL;
}
```

## Packet Structure

To interact with the server, packets must follow the structure defined in the protocol:

1. Header:
   - `v4`: A fixed value (e.g., `0x1234`).
   - `v5`: The `command_id` indicating the operation to execute.
   - `checksum`: A validation value calculated as `((v4 ^ v5) << 16) | (payload_id & 0xFFFF)`.
   - `payload_id_net`: The payload ID.
2. Metadata:
   - `payload_id_net`: The payload ID (must match the header).
   - `unused`: A reserved field, typically set to `0`.

## Sending Packets

The following Python code demonstrates how to construct and send packets to the server:

```py
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
```
