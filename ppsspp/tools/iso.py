from __future__ import annotations

import hashlib
import struct

SECTOR = 2048
PVD_SECTOR = 16
TERM_SECTOR = 17
L_PATH_SECTOR = 18
M_PATH_SECTOR = 19
ROOT_SECTOR = 20
PSP_GAME_SECTOR = 21
SYSDIR_SECTOR = 22
FIRST_FILE_SECTOR = 23
SYSTEM_ID = b"PSP GAME"
SFO_MAGIC = b"\x00PSF"
SFO_VERSION = b"\x01\x01\x00\x00"
PSF_FMT_UINT32 = 0x0404
PSF_FMT_STRING = 0x0204


def _align(n, a=4):
    return (n + a - 1) & ~(a - 1)


def build_sfo(params):
    entries = []
    for key, kind, value in params:
        if kind == "int":
            raw = struct.pack("<I", int(value))
            fmt = PSF_FMT_UINT32
        elif kind == "str":
            raw = str(value).encode("utf-8") + b"\x00"
            fmt = PSF_FMT_STRING
        else:
            raise ValueError("unknown SFO kind: %r" % (kind,))
        entries.append((key, fmt, raw))
    entries.sort(key=lambda e: e[0])
    header_size = 20
    index_size = 16 * len(entries)
    key_table_start = header_size + index_size
    key_table = bytearray()
    key_offsets = []
    for key, _, _ in entries:
        key_offsets.append(len(key_table))
        key_table += key.encode("ascii") + b"\x00"
    data_table_start = _align(key_table_start + len(key_table), 4)
    index_table = bytearray()
    data_table = bytearray()
    data_offsets = []
    for i, (key, fmt, raw) in enumerate(entries):
        data_offsets.append(len(data_table))
        max_len = _align(len(raw), 4)
        index_table += struct.pack("<HHIII", key_offsets[i], fmt, len(raw), max_len, 0)
        data_table += raw + b"\x00" * (max_len - len(raw))
    for i, off in enumerate(data_offsets):
        struct.pack_into("<I", index_table, i * 16 + 12, off)
    out = bytearray()
    out += SFO_MAGIC
    out += SFO_VERSION
    out += struct.pack("<III", key_table_start, data_table_start, len(entries))
    out += index_table
    out += key_table
    out += b"\x00" * (data_table_start - (key_table_start + len(key_table)))
    out += data_table
    return bytes(out)


def _both16(v):
    return struct.pack("<H", v) + struct.pack(">H", v)


def _both32(v):
    return struct.pack("<I", v) + struct.pack(">I", v)


_ISO_DATE = bytes([126, 1, 1, 0, 0, 0, 0])


def dir_record(name, extent, size, flags, date=_ISO_DATE):
    length = 33 + len(name)
    if length % 2:
        length += 1
    rec = bytearray(length)
    rec[0] = length
    rec[1] = 0
    rec[2:10] = _both32(extent)
    rec[10:18] = _both32(size)
    rec[18:25] = date
    rec[25] = flags
    rec[26] = 0
    rec[27] = 0
    rec[28:32] = _both16(1)
    rec[32] = len(name)
    rec[33:33 + len(name)] = name
    return bytes(rec)


def _dir_payload(records, size=SECTOR):
    payload = b"".join(records)
    if len(payload) > size:
        raise ValueError("directory overflow: %d > %d" % (len(payload), size))
    return payload + b"\x00" * (size - len(payload))


def _path_table(records, big_endian):
    out = bytearray()
    for name, extent, parent in records:
        length = 8 + len(name)
        rec = bytearray()
        rec += bytes([length, 0])
        rec += struct.pack(">I" if big_endian else "<I", extent)
        rec += struct.pack(">H" if big_endian else "<H", parent)
        rec += bytes([len(name)]) + name
        if len(rec) % 2:
            rec += b"\x00"
        out += rec
    return bytes(out)


def build_iso(out_path, eboot, disc_id="ULUS00000", title="PSP Game",
              volume_id="PSP_GAME", extras=None):
    extras = extras or []
    sfo = build_sfo([("DISC_ID", "str", disc_id[:16]), ("TITLE", "str", title)])
    sfo_lba = FIRST_FILE_SECTOR
    sfo_sectors = _align(len(sfo), SECTOR) // SECTOR
    eboot_lba = sfo_lba + sfo_sectors
    eboot_sectors = _align(len(eboot), SECTOR) // SECTOR
    next_lba = eboot_lba + eboot_sectors
    extra_layout = []
    for name, data in extras:
        extra_layout.append((name, next_lba, data))
        next_lba += _align(len(data), SECTOR) // SECTOR
    total_sectors = next_lba
    root_dir = _dir_payload([
        dir_record(b"\x00", ROOT_SECTOR, SECTOR, 0x02),
        dir_record(b"\x01", ROOT_SECTOR, SECTOR, 0x02),
        dir_record(b"PSP_GAME", PSP_GAME_SECTOR, SECTOR, 0x02),
    ])
    psp_records = [
        dir_record(b"\x00", PSP_GAME_SECTOR, SECTOR, 0x02),
        dir_record(b"\x01", ROOT_SECTOR, SECTOR, 0x02),
        dir_record(b"PARAM.SFO;1", sfo_lba, len(sfo), 0x00),
        dir_record(b"SYSDIR", SYSDIR_SECTOR, SECTOR, 0x02),
    ]
    for name, lba, data in extra_layout:
        psp_records.append(dir_record(name.encode("ascii"), lba, len(data), 0x00))
    psp_game_dir = _dir_payload(psp_records)
    sysdir_dir = _dir_payload([
        dir_record(b"\x00", SYSDIR_SECTOR, SECTOR, 0x02),
        dir_record(b"\x01", PSP_GAME_SECTOR, SECTOR, 0x02),
        dir_record(b"EBOOT.BIN;1", eboot_lba, len(eboot), 0x00),
    ])
    path_records = [
        (b"\x00", ROOT_SECTOR, 1),
        (b"PSP_GAME", PSP_GAME_SECTOR, 1),
        (b"SYSDIR", SYSDIR_SECTOR, 2),
    ]
    l_path = _path_table(path_records, False)
    m_path = _path_table(path_records, True)
    pvd = bytearray(SECTOR)
    pvd[0] = 1
    pvd[1:6] = b"CD001"
    pvd[6] = 1
    pvd[8:40] = SYSTEM_ID.ljust(32, b" ")
    pvd[40:72] = volume_id.encode("ascii")[:32].ljust(32, b" ")
    pvd[80:88] = _both32(total_sectors)
    pvd[120:124] = _both16(1)
    pvd[124:128] = _both16(1)
    pvd[128:132] = _both16(SECTOR)
    pvd[132:140] = _both32(len(l_path))
    struct.pack_into("<I", pvd, 140, L_PATH_SECTOR)
    struct.pack_into("<I", pvd, 144, 0)
    struct.pack_into(">I", pvd, 148, M_PATH_SECTOR)
    struct.pack_into(">I", pvd, 152, 0)
    root_rec = dir_record(b"\x00", ROOT_SECTOR, SECTOR, 0x02)
    pvd[156:156 + len(root_rec)] = root_rec
    pvd[881] = 1
    term = bytearray(SECTOR)
    term[0] = 255
    term[1:6] = b"CD001"
    term[6] = 1
    image = bytearray(total_sectors * SECTOR)
    image[PVD_SECTOR * SECTOR:(PVD_SECTOR + 1) * SECTOR] = pvd
    image[TERM_SECTOR * SECTOR:(TERM_SECTOR + 1) * SECTOR] = term
    image[L_PATH_SECTOR * SECTOR:L_PATH_SECTOR * SECTOR + len(l_path)] = l_path
    image[M_PATH_SECTOR * SECTOR:M_PATH_SECTOR * SECTOR + len(m_path)] = m_path
    image[ROOT_SECTOR * SECTOR:(ROOT_SECTOR + 1) * SECTOR] = root_dir
    image[PSP_GAME_SECTOR * SECTOR:(PSP_GAME_SECTOR + 1) * SECTOR] = psp_game_dir
    image[SYSDIR_SECTOR * SECTOR:(SYSDIR_SECTOR + 1) * SECTOR] = sysdir_dir
    image[sfo_lba * SECTOR:sfo_lba * SECTOR + len(sfo)] = sfo
    image[eboot_lba * SECTOR:eboot_lba * SECTOR + len(eboot)] = eboot
    for name, lba, data in extra_layout:
        image[lba * SECTOR:lba * SECTOR + len(data)] = data
    with open(out_path, "wb") as fh:
        fh.write(image)
    return {
        "out": out_path,
        "size": len(image),
        "sectors": total_sectors,
        "eboot_lba": eboot_lba,
        "eboot_size": len(eboot),
        "disc_id": disc_id,
        "title": title,
        "extras": [(n, lba, len(d)) for n, lba, d in extra_layout],
        "sha256": hashlib.sha256(image).hexdigest(),
    }
