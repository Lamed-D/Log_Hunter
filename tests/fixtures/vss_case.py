"""Generate current NTFS plus two wholly stored fictional snapshot volumes."""
import struct
import uuid

from test_image import NTFSBuilder
from test_example_samples import load_demo
from test_vss_catalog import header
from log_hunter.image.vss import BLOCK_SIZE, HEADER_OFFSET

HISTORY = 'Users/alice/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt'
STORE_IDS = [str(uuid.UUID(int=number)) for number in (1, 2)]
CONTENTS = [b'Write-Output old-one\n', b'Write-Output old-two\n']
CURRENT = b'Write-Output current\n'


def ntfs(content, clusters):
    builder = NTFSBuilder(clusters=clusters)
    parent = builder.makedirs(HISTORY.rsplit('/', 1)[0])
    builder.add_file(parent, 'ConsoleHost_history.txt', content)
    hive = load_demo().HiveBuilder()
    label = content.decode('ascii').strip().split()[-1]
    command = 'C:\\Evidence\\' + label + '.exe'
    node = hive.key('Run', 133485408000000000,
                    [('Demo', 1, (command + '\0').encode('utf-16-le'))])
    for name in ('CurrentVersion', 'Windows', 'Microsoft', 'Software'):
        node = hive.key(name, 133485408000000000, children=[node])
    data = hive.build(hive.key('ROOT', 133485408000000000, children=[node]))
    builder.add_file(builder.makedirs('Users/alice'), 'NTUSER.DAT', data)
    return builder.build()


def build_case():
    """All data is generated, including each independent historic NTFS tree."""
    snapshots = [ntfs(content, 128) for content in CONTENTS]
    data = bytearray(ntfs(CURRENT, 1024))
    catalog = 1024 * 1024
    header(data, HEADER_OFFSET, 1)
    struct.pack_into('<Q', data, HEADER_OFFSET + 24, HEADER_OFFSET)
    struct.pack_into('<Q', data, HEADER_OFFSET + 48, catalog)
    volume_id = uuid.UUID(int=999).bytes_le
    data[HEADER_OFFSET + 64:HEADER_OFFSET + 96] = volume_id * 2
    header(data, catalog, 2)
    for index, snapshot in enumerate(snapshots):
        number = index + 1
        block_list = catalog + number * BLOCK_SIZE
        store_header = catalog + (number + 2) * BLOCK_SIZE
        stored = 2 * 1024 * 1024 + index * len(snapshot)
        data[stored:stored + len(snapshot)] = snapshot
        position = catalog + number * 256
        struct.pack_into('<QQ', data, position, 2, len(snapshot))
        identity = uuid.UUID(STORE_IDS[index]).bytes_le
        data[position + 16:position + 32] = identity
        struct.pack_into('<Q', data, position + 48, 133485408000000000 + number * 10000000)
        position += 128
        struct.pack_into('<QQ', data, position, 3, block_list)
        data[position + 16:position + 32] = identity
        struct.pack_into('<Q', data, position + 32, store_header)
        header(data, store_header, 4)
        struct.pack_into('<Q', data, store_header + 48, 68)
        payload = store_header + 128
        for relative, value in ((0, number + 10), (16, number + 100), (32, 200)):
            data[payload + relative:payload + relative + 16] = uuid.UUID(int=value).bytes_le
        struct.pack_into('<IIII', data, payload + 48, 0x1d, 1, 0x2000d, 0)
        header(data, block_list, 3)
        for item, offset in enumerate(range(0, len(snapshot), BLOCK_SIZE)):
            struct.pack_into('<QQQII', data, block_list + 128 + item * 32,
                             offset, 0, stored + offset, 0, 0)
    return bytes(data), snapshots
