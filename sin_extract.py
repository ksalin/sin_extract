#!/usr/bin/env python3
import struct
import os
import sys

print("==^.^== Sin Reloaded Pak Extractor ==^.^==")
print("")

if len(sys.argv) <= 1:
    print(f"Usage: {sys.argv[0]} pak0.sin")
    print("...or some other .sin file")
    print("")
    print("It extracts contents of the sin file to a subfolder having its name.")
    print("")
    exit(1)

pak = sys.argv[1]
outdir = sys.argv[2] if len(sys.argv) > 2 else os.path.splitext(pak)[0]

with open(pak, "rb") as f:
    data = f.read()

# Header
magic, zero1, pool_end, zero2, pool_start, zero3, count, pool_size = \
    struct.unpack_from("<8I", data, 0)

assert magic == 0x4B505253, f"Not SRPK: {magic:08x}"
assert pool_end == pool_start + pool_size

print(f"SRPK")
print(f"files       : {count}")
print(f"string pool : {pool_start:#x} - {pool_end:#x}")
print(f"entry table : {pool_end:#x} - {pool_end + count * 16:#x}")
print(f"archive size: {len(data):#x}")

assert pool_end + count * 16 == len(data), \
    "Entry table does not terminate at EOF"

pool = data[pool_start:pool_end]

os.makedirs(outdir, exist_ok=True)

for i in range(count):
    rec = pool_end + i * 16

    data_offset, data_size, name_offset = struct.unpack_from(
        "<QII", data, rec
    )

    # Find NUL terminator in filename pool
    end = pool.find(b"\0", name_offset)
    if end < 0:
        raise RuntimeError(f"Unterminated filename at entry {i}")

    name = pool[name_offset:end].decode("utf-8", errors="replace")

    if data_offset + data_size > len(data):
        raise RuntimeError(
            f"Entry {i} out of bounds: "
            f"{data_offset:#x}+{data_size:#x}"
        )

    # Prevent ../ escaping the output directory
    name = name.replace("\\", "/")
    name = name.lstrip("/")
    parts = [p for p in name.split("/") if p not in ("", ".", "..")]
    name = "/".join(parts)

    if not name:
        name = f"unnamed_{i:05d}"

    path = os.path.join(outdir, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)

    with open(path, "wb") as out:
        out.write(data[data_offset:data_offset + data_size])

    print(
        f"{i:5d}  "
        f"{data_offset:10x}  "
        f"{data_size:8x}  "
        f"{name_offset:8x}  "
        f"{name}"
    )

print(f"Extracted {count} files to {outdir}/")
print("")
