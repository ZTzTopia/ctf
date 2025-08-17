import struct
import subprocess
import zlib
# from scapy.all import PcapReader, TCP

SEGMENT_BITS = 0x7F
CONTINUE_BIT = 0x80

class PartialReadError(Exception):
    pass

def read_varint(data: bytes, offset: int = 0):
    value = 0
    position = 0
    index = offset

    while True:
        if index >= len(data):
            raise PartialReadError('Not enough bytes to read VarInt')

        current_byte = data[index]
        index += 1

        value |= (current_byte & SEGMENT_BITS) << position

        if (current_byte & CONTINUE_BIT) == 0:
            break

        position += 7
        if position >= 32:
            raise RuntimeError('VarInt is too big')

    return value, index - offset


def read_varlong(data: bytes, offset: int = 0):
    value = 0
    position = 0
    index = offset

    while True:
        if index >= len(data):
            raise PartialReadError('Not enough bytes to read VarLong')

        current_byte = data[index]
        index += 1

        value |= (current_byte & SEGMENT_BITS) << position

        if (current_byte & CONTINUE_BIT) == 0:
            break

        position += 7
        if position >= 64:
            raise RuntimeError('VarLong is too big')

    return value, index - offset

class EventEmitter:
    def __init__(self):
        self._events = {}

    def on(self, event, handler):
        self._events.setdefault(event, []).append(handler)

    def emit(self, event, *args, **kwargs):
        for handler in self._events.get(event, []):
            handler(*args, **kwargs)

class Splitter(EventEmitter):
    def __init__(self):
        super().__init__()
        self.buffer = bytearray()

    def feed(self, chunk: bytes):
        self.buffer.extend(chunk)

        offset = 0
        try:
            value, size = read_varint(self.buffer, offset)
        except PartialReadError:
            return

        while len(self.buffer) >= offset + size + value:
            packet = bytes(self.buffer[offset + size: offset + size + value])
            self.emit('packet', packet)
            offset += size + value

            try:
                value, size = read_varint(self.buffer, offset)
            except PartialReadError:
                break

        self.buffer = self.buffer[offset:]

class Decompressor(EventEmitter):
    def __init__(self, compression_threshold=-1):
        super().__init__()
        self.compression_threshold = compression_threshold

    def feed(self, chunk: bytes):
        try:
            value, size = read_varint(chunk, 0)  # must be implemented
        except PartialReadError:
            return  # not enough bytes yet

        if value == 0:
            # No compression
            self.emit('packet', chunk[size:])
            return

        try:
            new_buf = zlib.decompress(chunk[size:], wbits=-zlib.MAX_WBITS)
        except Exception:
            return

        if len(new_buf) != value and not self.hide_errors:
            print(f'uncompressed length should be {value} but is {len(new_buf)}')

        self.emit('packet', new_buf)

from PIL import Image, ImageDraw, ImageFont

villager_entities = []
render_queue = []

def parse_packet(packet: bytes):
    packet_id, size = read_varint(packet, 0)
    data = packet[size:]

    # print(f'Packet ID: {packet_id}, Length: {len(data)}')

    if packet_id == 0x01:  # add_entity
        entity_id, offset = read_varint(data, 0)
        
        entity_uuid = data[offset:offset + 16]
        offset += 16

        data = data[offset:]
        offset = 0

        entity_type, offset = read_varint(data, 0)

        if entity_type == 134:  # minecraft:villager
            x, y, z = struct.unpack('>ddd', data[offset:offset + 24])
            pitch, yaw, head_yaw = struct.unpack('bbb', data[offset + 24:offset + 24 + 3])

            data = data[offset + 24 + 3:]
            offset = 0

            data_length, offset = read_varint(data, 0)
            velocity_x, velocity_y, velocity_z = struct.unpack('>hhh', data[offset:offset + 6])

            villager_entities.append((entity_id, entity_uuid, x, y, z, pitch, yaw, head_yaw, velocity_x, velocity_y, velocity_z, ''))
            
            print(f'Found villager entity: ID={entity_id}, UUID={entity_uuid.hex()}, Position=({x}, {y}, {z}), '
                  f'Rotation=({pitch}, {yaw}, {head_yaw}), Velocity=({velocity_x}, {velocity_y}, {velocity_z})')

    if packet_id == 0x5C:  # set_entity_data
        # Read unsigned byte for entity ID (dont use read_varint)
        entity_id, offset = read_varint(data, 0)
        metadata_index = struct.unpack('>B', data[offset:offset + 1])[0]
        offset += 1
        
        metadata = data[offset:]
        metadata_type, offset = read_varint(metadata, 0)

        metadata = metadata[offset:]
        offset = 0

        if entity_id in [ent[0] for ent in villager_entities]:
            # print(f'Found villager metadata for ID={entity_id}, Metadata Index={metadata_index}, Metadata Type={metadata_type}')
            if metadata_type == 6:  # Optional Text Component
                has_text = struct.unpack('b', metadata[offset:offset + 1])
                offset += 1

                if has_text:
                    nbt_tag = struct.unpack('b', metadata[offset:offset + 1])[0]
                    _ = struct.unpack('b', metadata[offset + 1:offset + 2])[0]
                    string_length = struct.unpack('b', metadata[offset + 2:offset + 3])[0]
                    string_value = metadata[offset + 3:offset + 3 + string_length].decode('utf-8')
                    # print(f'Found villager metadata for ID={entity_id}, NBT Tag={nbt_tag}, String Length={string_length}, String Value={string_value}')
                    for i, ent in enumerate(villager_entities):
                        if ent[0] == entity_id:
                            villager_entities[i] = (ent[0], ent[1], ent[2], ent[3], ent[4], ent[5], ent[6], ent[7], ent[8], ent[9], ent[10], string_value)

    # if packet_id == 0x1F:  # entity_position_sync
    #     entity_id, offset = read_varint(data, 0)

    #     if entity_id in [ent[0] for ent in villager_entities]:
    #         x, y, z = struct.unpack('>ddd', data[offset:offset + 24])
    #         print(f'Entity Position Sync: ID={entity_id}, Position=({x}, {y}, {z})')
    #         for i, ent in enumerate(villager_entities):
    #             if ent[0] == entity_id:
    #                 villager_entities[i] = (ent[0], ent[1], x, y, z, ent[5], ent[6], ent[7], ent[8], ent[9], ent[10], ent[11])

splitter = Splitter()
decompressor = Decompressor()

splitter.on('packet', lambda pkt: decompressor.feed(pkt))
decompressor.on('packet', lambda pkt: parse_packet(pkt))

# scapy make server packet will incorrectly feed to the splitter, dont know why.
# with PcapReader('challenge.pcap') as pcap_reader:
#     for pkt in pcap_reader:
#         if pkt.haslayer(TCP) and pkt[TCP].payload:
#             data = bytes(pkt[TCP].payload)
#             splitter.feed(data)

proc = subprocess.Popen(
    ['tshark', '-r', 'challenge.pcap', '-Y', 'tcp.srcport == 25565',
     '-T', 'fields', '-e', 'tcp.payload'],
    stdout=subprocess.PIPE,
    text=True,
)

for line in proc.stdout:
    data = bytes.fromhex(line.strip())
    splitter.feed(data)

img = Image.new('RGB', (800, 600), color='white')
draw = ImageDraw.Draw(img)
font = ImageFont.load_default()
for ent in villager_entities:
    _, _, x, y, z, _, _, _, _, _, _, text = ent
    if not text:
        continue

    img_x = int(x * 10) % 800
    img_y = int(y * 10) % 600
    draw.text((img_x, img_y), text, fill='black', font=font)

img.save('villager_text.png')
