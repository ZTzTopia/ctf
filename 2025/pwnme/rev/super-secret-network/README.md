---
title: "Super secure network"
categories: Reverse Engineering
tags: 
draft: true
completedDuringEvent: true
submitted: true
flags: PWNME{Crypt0_&_B4ndwidth_m4k3s_m3_f33l_UN83474813!!!}
---
> The target is hiding hisself in a small hotel of the town. One of our agents managed to capture the communications from the parking lot... Unfortunately, the target seems to use software on his phone to protect himself, reading the data exchanged with the server is impossible ! You have the captured trace and the recovered software. It's up to you.
>
> Author : `Prince2lu`
>
> Flag format: `PWNME{.........................}`

by Prince2lu

---

The provided software contains an initialization function, `init_module`, which appears to set up a secure communication mechanism using **Diffie-Hellman key exchange** and **AES encryption**. Below is the relevant portion of the code:

```c
__int64 __fastcall init_module(__int64 a1, __int64 a2, __int64 a3, __int64 a4, __int64 a5, __int64 a6)
{
  _QWORD v7[3]; // [rsp+0h] [rbp-58h] BYREF
  __int64 v8; // [rsp+18h] [rbp-40h]
  __int64 v9; // [rsp+20h] [rbp-38h]
  __int64 v10; // [rsp+28h] [rbp-30h] BYREF
  __int64 v11; // [rsp+30h] [rbp-28h] BYREF
  int v12; // [rsp+3Ch] [rbp-1Ch]
  __int64 v13; // [rsp+40h] [rbp-18h]
  __int64 v14; // [rsp+48h] [rbp-10h]
  unsigned int v15; // [rsp+54h] [rbp-4h]

  v15 = 0;
  v14 = 0LL;
  l1111l11l11l111l = l111lll11l1ll11l(60LL, a2, a3, a4, a5, a6, 0LL, 0LL, 0LL, 0x800000000LL, 0LL, 0LL);
  get_random_bytes(&lll1ll1l111l111l, 8LL);
  v10 = 2LL;
  LODWORD(v9) = 1;
  v7[1] = &l1111l11l11l111l;
  v7[2] = &v10;
  v11 = lll1l11l1l1l1111(2LL, lll1ll1l111l111l, l1111l11l11l111l);// pow
  v7[0] = &v11;
  LODWORD(v8) = 8;
  v15 = crypto_dh_key_len(v7);
  if ( v15 )
  {
    v13 = (int)v15;
    v12 = 17301536;
    v14 = _kmalloc((int)v15, 17301536LL);
    if ( v14 )
    {
      if ( !(unsigned int)crypto_dh_encode_key(v14, v15, v7) && (int)lll1llll111ll1l1(3232235836LL, 3333LL) >= 0 )
      {
        qword_B5C0 = (__int64)sub_E0A;
        byte_B5D8 = 2;
        dword_B5DC = 0;
        dword_B5E0 = 0x80000000;
        qword_B600 = (__int64)sub_104E;
        byte_B618 = 2;
        dword_B61C = 4;
        dword_B620 = 0x80000000;
        if ( !(unsigned int)nf_register_net_hook(&init_net, &qword_B5C0)
          && !(unsigned int)nf_register_net_hook(&init_net, &qword_B600) )
        {
          llll1l1ll1lll1l1(l1ll111lll11lll1, v14, v15);
        }
      }
    }
  }
  return 0LL;
}
```

The function `init_module` initializes the module and sets up the network hooks. The **Diffie-Hellman** key exchange is performed using the `crypto_dh_encode_key` function. `nf_register_net_hook` registers the network hooks for the functions `sub_E0A` and `sub_104E` where `sub_E0A` is `recv` and `sub_104E` is `send`.

The function `sub_E0A` checks for specific magic numbers to determine the next steps:

```c
if ( v2 == 0x86E35DE5 )
      {
        l11lll1l1l1ll1l1(v6);
      }
      else if ( v2 == 0x89E35DE5 )
      {
        if ( lll1ll1111l111ll )
        {
          v11 -= 4;
          ll1lll11ll1ll11l(v6, v11 - 16, v6 + v11 - 16LL);
          v11 -= 16;
          v10 = sub_D4(v11 + 96, 17301536LL);
          if ( v10 )
          {
            sub_123(v10, 96LL);
            v3 = skb_put(v10, v11);
            csum_partial_copy_from_user(v6, v3, v11, 0LL, &v5);
            *(_WORD *)(v10 + 184) = 8;
            *(_WORD *)(v10 + 186) = 0;
            *(_WORD *)(v10 + 190) = 0;
            sub_1C5(v10);
            *(_QWORD *)(v10 + 16) = *(_QWORD *)(a2 + 16);
            v9 = sub_1FC(v10);
            if ( v9 )
              netif_rx(v10);
          }
        }
      }
```

If the magic number is `0x86E35DE5`, the function `l11lll1l1l1ll1l1` is called. If the magic number is `0x89E35DE5`, encrypted data is processed using `ll1lll11ll1ll11l`.

When `0x86E35DE5` is received, `l11lll1l1l1ll1l1` is invoked:

```c
void *__fastcall l11lll1l1l1ll1l1(__int64 *a1)
{
  __int64 v1; // rcx
  __int64 v2; // r8
  __int64 v3; // r9
  void *result; // rax
  __int64 v5; // [rsp+8h] [rbp-30h] BYREF
  _QWORD s[4]; // [rsp+10h] [rbp-28h] BYREF
  __int64 v7; // [rsp+30h] [rbp-8h]

  memset(s, 0, sizeof(s));
  v5 = 0LL;
  v7 = *a1;
  v5 = lll1l11l1l1l1111(v7, lll1ll1l111l111l, l1111l11l11l111l);// sha256
  result = (void *)((__int64 (__fastcall *)(__int64 *, __int64, _QWORD *, __int64, __int64, __int64, __int64 *))l1l1l1l11111111l)(
                     &v5,
                     8LL,
                     s,
                     v1,
                     v2,
                     v3,
                     a1);
  if ( !(_DWORD)result )
  {
    l1l1llll1l1ll11l = sub_23F("aes", 4LL, 128LL);
    sub_2AE(l1l1llll1l1ll11l, s, 32LL);
    result = memset(s, 0, sizeof(s));
    lll1ll1111l111ll = 1;
  }
  return result;
}
```

This function calculates the SHA-256 hash of the exchanged key and initializes the AES encryption context and `l1l1llll1l1ll11l` becomes the AES encryption object.

When `0x89E35DE5` is received, `ll1lll11ll1ll11l` is called:

```c
__int64 __fastcall sub_104E(__int64 a1, __int64 a2)
{
  char *dest; // [rsp+28h] [rbp-28h]
  void *src; // [rsp+30h] [rbp-20h]
  unsigned int n; // [rsp+3Ch] [rbp-14h]
  __int64 v6; // [rsp+48h] [rbp-8h]

  if ( !a2 )
    return 1LL;
  if ( !sub_1FC(a2) )
    return 1LL;
  v6 = sub_215(a2);
  if ( !v6 )
    return 1LL;
  if ( __ROL2__(*(_WORD *)(v6 + 2), 8) == 3333 )
    return 1LL;
  if ( !lll1ll1111l111ll )
    return 1LL;
  n = *(_DWORD *)(a2 + 120);
  src = (void *)sub_19C(a2);
  dest = (char *)_kmalloc(n + 20, 17301536LL);
  if ( !dest )
    return 1LL;
  memcpy(dest, src, n);
  get_random_bytes(&dest[n], 16LL);
  ll1lll11ll1ll11l(dest, n, &dest[n]);
  *(_DWORD *)&dest[n + 16] = -1981588507;
  if ( !(unsigned int)llll1l1ll1lll1l1(l1ll111lll11lll1, dest, n + 20) )
    return 1LL;
  kfree(dest);
  kfree_skb(a2);
  return 2LL;
}
```

`ll1lll11ll1ll11l` is the function that encrypts the data using AES-CTR. And `l1l1llll1l1ll11l` variable is the aes object. from `l11lll1l1l1ll1l1` called after server sends the public key with `0x86E35DE5` magic number.

## The Communication

Because we have `pcpapng` file, we can extract the data from it and reconstruct the communication between the client and the server.

First, client send dh key, public key, and modulus to the server. Where we can extract the base, public key, and modulus from the `pcapng` file. 
Second, server sends the public key to the client.
Third, client sends the encrypted data to the server and server decrypts it or vice versa.

The encrypted packets are encrypted using AES-CTR. Packet structure is as follows:

| Field | Size | Description |
| --- | --- | --- |
| Encrypted Data | Variable | Encrypted data using AES-CTR |
| Nonce | 16 bytes | Random nonce used for AES-CTR |
| Magic Number | 4 bytes | Magic number to determine the next steps |

## Solution

So here is the python code to reconstruct the communication between the client and the server:

```py
import binascii
import os
import struct
import hashlib
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto import Random

def derive_dh_key(server_pubkey, client_privkey, prime):
    key = pow(server_pubkey, client_privkey, prime)
    key_bytes = key.to_bytes(8, byteorder='little', signed=False)
    print("Derived DH Key:", key)
    sha256_hash = hashlib.sha256(key_bytes).digest()
    print("SHA256 Hash:", sha256_hash.hex())
    return sha256_hash

# https://www.alpertron.com.ar/DILOG.HTM
aes_context = None
aes_key = None
base = 0
client_private_key = 1330218279148611220
server_private_key = 1375379614977946020
modulus = 0

def reconstruct_sub_104E(aes_context, data):
    dest = bytearray(len(data) + 20)
    nonce = Random.get_random_bytes(16)
    print("Nonce (Random):", nonce.hex())
    counter = Counter.new(128, initial_value=int.from_bytes(nonce, byteorder='big'))
    cipher = AES.new(aes_key, AES.MODE_CTR, counter=counter)
    dest = cipher.encrypt(data)
    dest += nonce
    dest += struct.pack("<I", 0x89E35BE5)
    return dest

def reconstruct_l11lll1l1l1ll1l1(data):
    global base, client_private_key, modulus, aes_context, aes_key
    
    print("Received Data:", hex(data))
    print("Private Key:", hex(client_private_key))
    print("Base:", hex(base))
    print("Modulus:", hex(modulus))

    v2 = pow(data, client_private_key, modulus)
    print("Shared Key:", v2)

    v3 = hashlib.sha256(v2.to_bytes(8, byteorder='little')).digest()
    print("Derived Key:", v3.hex())

    aes_key = v3
    aes_context = AES.new(v3, AES.MODE_ECB)
    return None

def reconstruct_sub_E0A(aes_context, data):
    global aes_key

    magic_number = struct.unpack("<I", data[-4:])[0]

    print("Magic Number:", hex(magic_number))
    if magic_number == 0x86E35DE5:
        reconstruct_l11lll1l1l1ll1l1(int.from_bytes(data[:-4], byteorder='little'))
        return None
    # elif magic_number != 0x89E35BE5: # 0x86E35DE5
    #     print("Invalid magic number")
    #     return None
    
    nonce = data[-20:-4]
    print("Nonce (Extracted):", nonce.hex())

    dest = data[:-20]

    counter = Counter.new(128, initial_value=int.from_bytes(nonce, byteorder='big'))
    cipher = AES.new(aes_key, AES.MODE_CTR, counter=counter)
    dest = cipher.decrypt(dest)
    return dest

DH_KPP_SECRET_MIN_SIZE = 4 + 3 * 4
CRYPTO_KPP_SECRET_TYPE_DH = 1

class DHParams:
	def __init__(self):
		self.key_size = 0
		self.p_size = 0
		self.g_size = 0
		self.key = None
		self.p = None
		self.g = None

class KPPSecret:
    def __init__(self, type, len):
        self.type = type
        self.len = len

def dh_unpack_data(src, size):
    data = src[:size]
    return data, src[size:]

def dh_data_size(params):
	return params.key_size + params.p_size + params.g_size

def crypto_dh_key_len(params):
	return DH_KPP_SECRET_MIN_SIZE + dh_data_size(params)

def crypto_dh_decode_key(buf, params):
    if not buf or len(buf) < DH_KPP_SECRET_MIN_SIZE:
        return -1

    ptr = bytes.fromhex(buf.decode())

    secret_data, ptr = dh_unpack_data(ptr, struct.calcsize('HH'))
    secret = KPPSecret(*struct.unpack('HH', secret_data))

    if secret.type != CRYPTO_KPP_SECRET_TYPE_DH:
        return -1

    key_size_data, ptr = dh_unpack_data(ptr, struct.calcsize('i'))
    params.key_size = struct.unpack('i', key_size_data)[0]

    p_size_data, ptr = dh_unpack_data(ptr, struct.calcsize('i'))
    params.p_size = struct.unpack('i', p_size_data)[0]

    g_size_data, ptr = dh_unpack_data(ptr, struct.calcsize('i'))
    params.g_size = struct.unpack('i', g_size_data)[0]

    if secret.len != crypto_dh_key_len(params):
        return -1

    if params.key_size > params.p_size or params.g_size > params.p_size:
        return -1

    params.key = ptr[:params.key_size]
    params.p = ptr[params.key_size:params.key_size + params.p_size]
    params.g = ptr[params.key_size + params.p_size:params.key_size + params.p_size + params.g_size]

    if all(b == 0 for b in params.p):
        return -1

    return 0

# Client's send base, public key, and modulus
crypto_dh_encode_key = b'010021000800000008000000010000005c4f31a50c2d980c6b152f4845212e1502'
params = DHParams()
crypto_dh_decode_key(crypto_dh_encode_key, params)

base = int.from_bytes(params.g, byteorder='little')
public_key = int.from_bytes(params.key, byteorder='little')
modulus = int.from_bytes(params.p, byteorder='little')

computed_pubkey = pow(base, client_private_key, modulus)
if computed_pubkey == public_key:
    print("Diffie-Hellman Key Agreement: Success")
else:
    print("Diffie-Hellman Key Agreement Failed")
    exit(1)

# Server's public key
reconstruct_sub_E0A(None, binascii.unhexlify('65027c9877d09804e55de386'))

plaintext = b"Hello, AES-CTR encryption!"
ciphertext = reconstruct_sub_104E(aes_context, plaintext)
print("Encrypted Data (Hex):", ciphertext.hex())

encrypted_data = [
    '010021000800000008000000010000005c4f31a50c2d980c6b152f4845212e1502',
    '65027c9877d09804e55de386',
    ciphertext.hex(),
    'a9962d2730df6c3c2d16f4f7d3022967f4f7e0947e5e03c2c2c026acc8a656f5708a8aa99d05134172f8df5b71ad32f7806743c9529fb6ad7e41c8f97e168034893020a6bb15636ded20bd90e55be389',
    '9e02b2aaf3fe8219de13745bce224b38130db68bf13ee3a2cfc035ab67d5420c5872d2952aa3e4ce43e368c6cd02564341ff59b05a2580bb8b7568d10944c5185739023e86901b98957cc54ae55be389',
    'd529357938cf40ae503b1eea1859efefea69add0d4e0d1a5c35fe217402fd3b81194bd8cf947cc29cb6e0790ef92b4c35741ca9392753c504bc33cf2b37dd856ea02d194e55de389',
    'a87e9bc7f7a3dd312c0146935ffd3e95b8f77643b70e8d7576002cc99bc64d202a3dbf268a7b1358cd163e7e3e9a134fe5e776e3b9695ef25726b78a8c35d2fae438b046e55de389',
    '0dc6f6ba652c3717abd212715e08623d19dc44b856a5c8037a056a060ae3cb6e4dac2b5754bbed2bb7781da6d58d5a4a8e3c320a379cafb5e55be389',
    '30a42a38d76a23bb443e477eb163fe14d52c390e40a262f4b2f0bbcafbd0fd45522d4ae3d05ca27f7942916b87c53cd10d78ed670cf5ae64e55be389',
    '7e70f360d880d8dcc05874c639d46d19c273729f554abc2f0c63a4c4e829c839abd846ee5aab313e453f98103f4682b277372133e57260f9c96076a1a33edbac155ad7882173f8f264aeb8318c06b1e8909ea89e341be7d9cc7abbc957579582a446915d5f4c8f8261b7b6039f1fedd96b4e44a8ba14e1e143f8db7e567bda25fd3c0d6fbee55be389',
    '6877c550aa2cebfc5f899f1847fb5ae6045f8d562277d574bee80647031fb055c7e71efbf9517ccbb0c2446b854dfed44ae867ecbc33dde85258c6f7887180e2d7be7ec4cb76739f39f0e3abb56a1b253594a96f086424c639d4af536ddd57301fcd2a9d35ac43e516d22a042f5c98bd464c0c761cf73514837545c98ff8cffc037af2eec2e55be389',
    '87cf38d005dff7f4059b87f002e425b64a399593ed98470fff9c3828298ba0a9919773d20acf7c86231f37439e8230930393af9bb6806d570f3a9b15afa125ae2021a1f9e55de389',
    '74501ea8ca0ef57a16c74dd16b1481f2ef51fabacfc93220da39d0488b27fb6d293c8a40828e875ae12f52fa65c34b63c6f100bdaf189580e55be389',
    'f1e9b87e501092585285c05b2fe9b3dbffe0961f08d1ce22b8e71fd8b46634e4d811fd78f4006c846495c820691e153595bb1363ab979e5b0dc2fd797ce3e65fe7e68febd2d352725e5f2dc4d1e75a46f88cf0c05dfdfb945fe2be5ea47ccaa68efcad3fa151d2856f37a38a6afbfc922f40895c41288d8839e4220a3de9daf8bd1d0dee4de55be389',
    '95bac19e9a3410287b34474501b83c5fb8ddf90d795160cc958fd739088acb84b318b3d580a3c3527406e0018e67ac3d40aadd6e952e2569e55de389',
    '469a8133423b95ac561f8e162498a4c3652c720fe26c46f14fc709072fb687c759cd623657fc631740b7d1e87a42d5cfee0e369971294d42e55be389',
    'c032ca90eabbceaebf7f5222c19a29980f9a9f483a79b5dc80d571b3f25f6d3c5a8fb7fe2e4dc83d2cfe54032683f5466bd856cf8d040290e55de389',
    'ab5c22714b7d71c53d404f345a3ee217d0fce3fd0f8d625c00b7b505b97449b139390b58d8ef448f43e9a839f84e0a1a35bd44df34340d8ae55be389',
    '4ecc53cd97a0a3ca6961e720c73f49c51a159f584febc30c8ce5be71cdbeacbce4bc61eb5e7ff5b80aaf33f359869d9d6650569b04f030e25b0d27c5225dbf30ae2e80e2cab6ee099f63d1f6b5ae8579fd05e9e2f315989614efe7ff05e237f219568f94c15361e0b2928ea76501ee65343653880c0c07948f954be3d3499ecccb9b34090dc1025c3fbd78b5828b9b3442928a323d3d684f053ca9793cc94bd6d7ab1bbf62a4441c70ecf4854e3d30ee442c673945e2c5f7e2a89129af3f3ad51bdc409209987071ddae949edfb84cf27f85d267fc4eb644c4379dbfe92599e3985149536b3b8511367ca341514812ddd704e55de389',
    'a714fe5ff6c6fb25b6e0c7c4ab1abe6c1524055ad03b862848df5019d52e7e44f90b31197b993f0f2bfa95d24b743bb55bb13a6a6d8034cae55be389',
    '47ece28b01ce83b3adb01403c647dcb5cf37db57c2d01704560ea42523464350f393aa6ab089621da42e602a895b80197d0283c4d20cf82f9b586497cdfdf27873a3abe17f830c84b5765837298868d372033dfb8942acdf1417d88d282e684b9beafdeb64bf7b3cb1e862b273f9f3143687d21169b59a5142ac9b4b7fadf2d8eb9ef6dbc2896cee584b64aee325b30341d25be3df4981dcd1a8dc8bfd5fe705d7b6b5f858253fe0d3c3299ae8d30392aab7f5443b18a9814904883f79bc98aaf8b38f75d12d24b9005458a088b8e209fb34a60d4bc7f4dcbd07321c5546f234565022e96bd56d0f0384ebf11f58f3501db2bbb1712f01480e0d016dcf8d0f7810db5f73cf0eabadce65fe40975cb2dab081f277cb88616b1addcf3c79e63b18a64df7e5cbdc5121a3726908ca6212376fc87a0108517bf3ad63e63537da41cb71197c30694e94309f436c8fc2d1bce9fbd1d4546575201a30f40b44b6b2d6d6216a95e02c2f7355f1635c5f40c0eff9b35696650885d2a2f1e189c4b746bd2ffb119f1a10ec868697e6fa05e3017dd0838cf283e8c8f25c5197b45d03aca6aaa5f43bbc22a0b558f50078edbd8de65efb9b73090dc9c981063ac4b3a3a06e8e59fc34cf5c609cb14d9737962efd9fce75f7e020fa5b3a7e1eafc504873b07617acb5ff545a99d5a5d2d637c44c81256a56179859249afeadb6d03090a67b58dccc780078f11c74729579f7a73b1e72ed1482c24bdc286a59a7a12f3855fd3114cfb1240670ae9315cfaae06a913746e6123af0a106d27a1f1fe6a76aa600f39fa673329535e975a2acf16f35893d6400ec42f06c9c716586606184f0f50a75a6bc03c06b147b76d42cc4bd0caaccb51ad4515c8e64236c283fb7b9cd5e7a2dcfd446a9b39dd8e0ae6081a863f01cc64beafd475db4cd3195aefb007d36cd5701757c2aedec4e161e21e58fab52330a0b370f7eb1e5f2f5ed86c68c77cc60bf3981657636df15cfc9d80633253b6130509a4c67e0071803a11e6511ff978da24afe5edc6e76ed3febd315470f2e98ec312a504e436ada941e89f611942eaeca8b3e33362b71f0346001dc3bc36495d78748d546aca1dbfa4257014abc01a1232a5e13e1661b004e5acd48732e445d71c09559faa2fc987fe637ccabbd1a81149bcede48b257dbdc218fc7bd5822b0792705e6ad628f795fba8b6541127c221717c86df4d1020c0aa5ce31a721f6c86d653a75f2492be6ff4a214c2857b1e2b9fe91a27a20109c179fa89811861aaa8b47eebe3e72e068fef5db2c61be3291b5e0efbd39ddc1248ace8e0d3ae99d76e3fcf0ccb47f5662ca949cf3de176fd7703a1bbd51393af4ef43760c402641201adaf9e5ffdbff8c8d86b6b3fd94475740218cf0c44f5a4fe75f658dfa428fc5b099105cb32183c90f239900d030946fa15836cc6c56762ffe924a34cfdefad56813f9288d7e99111cffbc76ffa1f7216d9944df94656c19e01bdc12e0f318d6aa3728664ef13c663ceee7c7cdb0af0060cd9630a8ca6ee57776b714efe2ec1ac1e90db18691f5dabbf0e9cd2e98d6efd7ce278374d161b37ba23da371eab299e1c13664237d0d07a5309ff656019579ea745553fef5bc8c9982d5f6e9d61363c7e9f10e27ec85b9ec8b8dc980aaff632a0a9684eb8b407bdb8a2a047bd253f50de6bb3260496076681aee55de389',
    'ae79ecfe16d1db7abbd095a05b6e0fafdf90f11874bbd15bfa3dcec70e5cfe95bfd1ef18cce34291b728474ada51f46c29704645b2c19772e55be389',
    '3ab84ffa9c90ab300f2abbae8e2c35de002cd8536dee90e4e51a8a73879bf1ebdb7cbf8f3c49f0413c9af6c1ea823d0852159bf81b22727ae55be389',
    '433ee94cf71e14e11e804dd4273fc8b060004d1f3225ac1b16149a5af54506a1a0807d02034e4bea1c0127438bceb2542ff3272d1879432b54ae3f46a1f7d54e7e735633c416e6d59318386106d2e048eb57029b993348b65ab5bd9ae8b74034046811e3df4e414dffe06d42372d242fd9b67f3289d625b4b55011db8a2762c5c1550f71515c9bbbd252bc5153e8e9238f25037ac6f3cb6e7a00d728a53f996e1b41066e8194d1ceda9c09e2452ccc846c82740718fcd6e4b98404300b1a018f2d6b142af5b0eab8e9b5253d254bbffaf4b2134f980f86bae7e31120dd328c219dd8baf15ce18603ae8c66c6984e44b8fcfda9a386d0fc8c949a7f66bf52dc2d35c3759a25792bd007b61a66effb1dfbeba01eb950fca3d01e359ec88395b44cfa9f3044a2a0ee885bda074ec1d40f1c7bc75e4aaff449c8c0d5a0d6c4dd40fee33a1d3f2022d3c7aef60b9267c2c74860b77cd4e24e9e757764a56fadb9659760aa58768e97f8d2a79ba34b3787e4ae9a398edc0cf26fea2b268861a07b99c1fcea95bfb84641833bf0ef07b47a7efd864f0fcb142e7ab7903efc25587389b805887641f66811080a85a62896ae4da7ca3f38715812e0e95276eb87fc94f99b4261227c8ec8f6cb0b7557a801d4a6e80f85f011e476f775481e0e3dbaa52119b0d6079d9d9344f22ea1a347168cf181b72aeaf10f2c55ab101423c9bfc6392cf8d05ad512f7db5bab16c33ace1976c262ac9cbdb4c5d20923a1bd7126b0bfa6b131ae243cb682a9c22c2a2601440810a1350ae6f7620e47ead954af3b75a37a9844146ac99fd0432d3b661d925e3c670f51f7b305f39677fe2e6279582d44b774788d1f89ac4dfce89af54918ee4ec1b65d572f18f04b3cfea02023805e4222fac9e7515a94eb9a20d7428ee4e93ba9376c690b78d84b71aa501376245c202f93c97a223b03cba94a4c6f64c11682561609adee00bdac101ce53fad42cf6908e8781a252386762d6f7f844d85a25fad7e07689e687bd61ad232a4c895bcf8a4f2ea7a9ab78210ae1c92662f92cf11b1656a757411848198faee8134ea6a439184de5d679b2840798032d67492cb7e14c575154ab23532882b57622b98831078b89efc9b8ef7287bb8705789f3399a5927bb4e63cf83ffaae7f4aa632e7189bddfb8a74ad04c9acfa4800e2503fe468cd1e742e109b85751168cbbe31b15523126f183626c216fb7831946e7814cb6ab0b39e48972cae3323704268af1eb434e260294cf7768fa0eb49244631a940aa9657b3a75ab6927bb6dc35eb0282ac9b28c4ac8f60576f8a2bc3decce4cae4315187726fa44b2fa46af888a07909fc9785308729f3588df48ec4aae0fda24a5787686897cde2c8f22d6339c8a721e30b7cf154f0f47e96f123213b4f3bc0dfe04d9632584d1e4bb5698078eed602bce5a4590e397fca1a22ffbdfc04a2889bf5ae61419f0cae4a8148b9c041cb7fb4b90b2ca5fc20e100a065258ba3f50dcc96a7644a2fc2631c0ee6dd9af55924b166205e618e39b5b481ea9ed327130de4c405d2ea2c7c9ec250296559839fc057012e6087b1e15f902d20b3d84c4660d744e99069292f5ac601e4035457dca02e3482a3f6ffbd4e295a890dbbe4d60d6f7268e3c0fe3ff9d740d35916602a17e8d464afe5f2466daaec058ec3b0f16110cceaa497dbdc44cf85130e55de389',
    '6dbc5f593321fdda9e60488ae01ec3c016e57d14d1341c38f019f7e978a2d88d5d048413bbd3b7b9963ecf2ebd36b6ec95825ec79e9c549b83182602d176c6bd4aee305be55be389',
    'd306bb2ddd23a54385e37f6977fd618cf9bf84c07e0c6c5b95ecb048251528dc1f5cf0d0054d1529106c97cf7b941fdf8234a7aaa988026ce9f761dd2b14c17ff0a298f59190ee4495b070b5a57715cdfd28e44855a839f04e00e3bfb9a2e5674d05c9ad32545f929f9232233f89e0dd1b76ea962a19c06fc808e784a980fb5f5d11c729dfe55de389',
    'fac86ac5117d45b79d54772bdc3be3a4a085b8126f34fa26f9c0a9fde263fb78bd866abd74015588510b5391d670519b1813c2a99d1a8f3ce55be389',
    'fc6b312ca781f99b07689be346cb137c0f6995c5241afbc1e8953edb27101953e5098da8ea85acd1049fc2a44da54d1bac84cd59a3b5bf15e55de389',
    'd324a93477f7ca75fc4e1228be1533d1e259d064e1cd25cc6745d40fa9a236e78012298fb5e5e8309ef10fc518ddc237ab5b5acb3d1a47d0e55be389',
    'f359679fa5ab2e3b4555dbf31d2100820809659901da4b59a07b5881457cb83197192a48c0b404f2a0edf07c30e395d5d89d37081b4cb5aee55de389',
    'a7ae9b48d41337370574d2f43b3fcd0758c6881f8827b259cf4e8aacb525cb838f82a4a8c61bb846da48e332f5289843212548b9a9806a26e55de389',
    'bff04b2f9e14ecf1f4b965ecc11e6fcd2e88556e0299c5866a9db761854b475dbe5c7d1e65de0fde38c479b7a9f2ab788f0b60dbe82c757ce55be389',
    '87c98375dedb36597f3790e2b1459d19887e51c44e720dfbdbb4055ce94823b0decd16e2ca91a940edfe380db4610c2a49b57ddb0924f45ce55de389',
    'd21ba305beec78de830677ccbdb976ceafc5dced0ae3e6465cac995516134a57c53c38bcbeb3359b3cca0be83c7b028563695ce9ee0d27e8e55de389',
    'd29e1e2002732a168f813a12017e8d243bb8b0187cd3ab384fdbb2a0f302a87a7b4bb321f5f7f0f780ebdc38ee9ea0a7657fcab6c34847b9e55be389',
    '7fc806db0dbf3687e542cbadb4dcfce22081de4bb5c4ec88a5f8e8641aa3e59efa57d4bec7f6ebf5a6ab8a12182a9baa493258cf3130c4bad281fff854ef5bd96130ef74e55de389',
    'be2ac8d131ba29199858b34834437c78c10ba0c464b9e6429d9e464c84663961ac298317c5ed43a431e3efdd48e9d13f046b45266ffaea4fe55be389',
    'a45639793f6f469dab76011f6f98314288d32d6b81753273eba6407268255815c700e436a2e94659067e5c29a2855dd36ce4b5ba609698bae55de389',
    '6a5150a543184a7110fb861d9d40cea11cf369283144ba7b8111ad0ee3171fd40a1e792840b114c5eaf58a2ccab6a3604d68380682557150e55de389',
    'b2b571a66d4b2105e553f376f6c1fd056bd1c3bc85d89dbb7f217063b13eb3479e5b9fb688955d9becb298740cfdd6761f740bbc4050624ce55be389',
    '55b677aa5ae672baf4ed57a5271c00b3bd2355bbee129630a616190a0d3c2574c7974c7eb1d70eb957c386a8e93b1cf5460ba6b83649f61de55de389',
    '729d1e26a5161c66fdf49138cc48d1d85f266651cb8d1eef0f5f9ebd1ebf16bf6aca5b196b4bce006043d940f4bc96237c77a332f8492617e55de389',
    '0f88a5f6d3ed13aa736c713d2b55e6e3350e97812e927ff68992e80474b258bce100f77e6bcea980601ab5cbdd266b0c054f0979de197830e55de389',
    '7f8f9e73925b9307d510adcaec8e15f778e39b7a946990880f2b5465a70f67e4cc2aa94e6ff11fd2a721863d5ecf5957e1b2a776ee180ccbe55de389',
    '3be49582026fa8a31e26122f93972e45bd0ae8dd6a0ef50af0850dff24d788b8556e32b990ae1f3f2badd2bad44c8456daa0c9dac594a6905ee3b5630796aa041156a89bafd9cf9e1050260ee55be389',
    '20a3f972b0e8e65fe4f82ab48942adb819fd7549c0a73bc7a54bbe640503b61fb269c73577247fd0b4cca77a4b95fc6a6d637deddded54388bebaa62148c5ed7adad0ed2d91c7fc0b3c9b939e55be389',
    '5bd507e6de008778439d7bc6b3d66a922b7bc86e5dde93400ed4a860deef71ff62ead788b7ba4a7743e11820cc29f057c21cef22f9e2397aadf440493cda5eca4d9a52b7e55de389',
    'a4e5dfe479df5345763142d97dc31e90670d5a0bc12ee94a45da3becc72ad11085481105c33a9612683cfd279e49aa74629b526a945e038fe55be389',
    '1f8ff7a27fd621e7f6c9712e81e59698cf024783ecc6f1f302dbeb06d719e0bfbc4d26e2880c9d60748c05aa407fc0b4579c4529bbaf909fe86213437fce84474538201ee55de389',
    '7c5ec79330f0dd15347b4e73421d61cad5ad435031333d90d9abdd2c40a18d70a59b9e9ed52adcbb2c5fc530575da45f264d806855d10d38e0bff6b43c95f088cb4eca08f7485457fbf53046ee9d337ec2c1cde59b69661c993d22b34c5cf408a5956f697e27d185d54259a83cbc66bc19bb58fcee30b76d810676e510627c0fc6c6e6b5db176c0bb253430440e55be389',
    '4dd28cc81ee865c00fd7b6238dc8e900c29b1e98264d1bea3e429e839ac9711340227b409e20d87c3115d3e4fa70c4066e7939e8f19c07bf57e4fc0faa04d3f4a067b54a57dbd3902fd6e2fa9ba11c37b12620f7d926798d0801deef0537cb928cf039dc2fa2ed1963edf7ee69332bcb32397594e8c173054bce2cd7d3f6876e13b6329a354c7ba5be3e09e66ee55be389',
    '9ca43ef9e258adc9206258bf6cdc15d8552f134e562cc335c81b02ede11f93413aa97bd4002a9bfe8b6667fe77746b812ec4eedd6d74de12f2f4911e85d99af9b977eb7ee55de389',
    '4bece9e86bd821513632d64e803f886f7868cec1b9d66ddf0775f57f83a6602e52de60b93b06fca5c7e19bf46b4a1a58aa7bd9cc853319f6e55be389',
    'bf93516f44535f93f8554ce0ff586d3ea0a798479e6f561ec8d5c44db37a3ce76d8d2fc7ab96ee2ebc9ea47f65b58ce816bc2ebc11d354c34f0fdda912d4ac45b71dd1ff36581307c37696b2f1bb9112d38bdfb4eb777c1b08bab9a18b0f3a089416946aa31dfa60035dd00f07f298812de22e3926cad6318e89debf822d9b8775ea0f27bebf731819e629d4cce55be389',
    '9b3f4e8dd569bb9be528b412d5f7a988d88ce940978e192dff11f28e4e3302eea6cebffef9e62a8297c1faa1264ea31df708106d1c2d7025e55de389',
    '1389f3449b5cbdf51ccfbb53a43cd3cf1bfe82fecba5b362861c238bb4720f2dc93394c63d80b1552836151b162f93bf7a1154879acc9a45e55be389',
    'b508fc1db3bef01cb3d60f0551c873a384b860e5d789761a5cc9d4785ba95c0832116c0a7b1488ab9984077864c5a18b1fab42cbbf513e4bbf0dfca596e7a7f2d37034efb09db5a4e7c2ddf743dc0ecca6df9904aa872d33d0cd423b93d14def085f98a09e0bb87d871edceff7eb82d01da44422e5c415943da05073eba72ebe055744070713bcdedc199d790d4cb6989da036e905eda643adbdd54e4db8b161f4f483e616b479baab3faf69abc7b03bbbbdd5b77ad68b8c46742b6abbb7466e895bd80e7ad0549a6e237bde78f4e1b14f17be879dd4452189391956052fda3e1d0be9928f657ae7aed518df690ff4add6b0e55de389',
    '048a3a2bb3e77d8c465b9e3dd49bb64b2b326df0777f3208f86d30296d91350847fae4427a549092a0a20805fbbda78099b0000cb348fbf0e55be389',
    'c52eeab7009ce2fe5ab0d29bac610794f1f25ed947da88a908a1e1520f55d0f8b3f5988540b20a2302a0c49fd5036de8fa9c0ee5401c47f7513952acc4a5e3141df150e770b016fa9d6e13ed35ecc28224f80c95184355f906ca9a867fcfbbafeda93819ec99ec6c8986f2803df52e9b655ea445a4f775bbc0c7dbda9433bfb480543a6e7b485758c4444c6dde93148738b4fd72dbf29e0b65c97e2e4df36ac1633e00319d7288f8cc9985271f28a0c6eaecb5142d2d3e73ca974f84ad80bdb521b56cb7d969356a009ed14009ad0d71de023a7c290dbd50679759119f38f0a25b35dadf8e9bd9fd1a1b210f00817766ebe19b195d31f64ddde874eeff26c0b586cf8a13558477e9eb9285792a21e2c81ba0d866c9ae18874e4cfe25ace18346d78fa7a1b7dc6be55de389',
    'a4135fb38289797f876a6e852e79c54364bc1a5f3585d45b13fb64f46e9e00f98e34256443202a223d38aa3d703c4166e72b547f7f63884be55be389',
    '73e586a33b33580621f29b8ee2d9f7a76b16978023c9b3c59fa2cff07055c025518e506d1f9f2dcb849750486f6e27070e7a2844987cb9f9e55be389',
    '43bad150964c4e84d9728618d2a9d432d91196bc1b293a1a5f943dace6058ab4fc99c530bf6d6e3dc5412e06656053bbee33cad71fb3fc60abd846b49aefcf61b249b04d7d5b5036b11512880b7efa1431bcb703070ab6bbeaa7f1e8bac33244b0df6c160748914721b70c7899bd2ce0cc3dc1c7c417abf6e71ad92846237fb09e616cbc311bf2a79e0514159a6762bd6f2df177067408798fa1048a5f3cdd8c0cec3215dcea50bfc6d98728fcb2ae67f981080a8b051ee393cce29574014282877280337aacd83e22d5ea9eed7eb1bd0830ad1693837ee94ba884f57734b1490643382006579b2c8bec103c104d846fb799568aea0e06106ec063e6f782a625d922a72ed707e3350ad48e31d73d6dcb509231ab0c3d0c5a2260e2e4fb52b70e419213f4815f22e55de389',
    '912c10d70e4e6be6e9fe05e60738bb5b0c126d209a78fcfd46d8257d8079d1a7b60fbb6c1b8a69603d6059661abc87641b5a614e48f1367952aa4567e368d74bfcbfa843e55be389',
]

print('\n\n')
for data in encrypted_data:
    try: 
        decrypted_text = reconstruct_sub_E0A(aes_context, binascii.unhexlify(data))
        if decrypted_text == None:
             continue
        
        print("Decrypted Message:", decrypted_text.decode('utf-8', errors='ignore'))
    except Exception as e:
        print(e)
```
