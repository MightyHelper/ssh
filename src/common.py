def hexdump(value: bytes | int) -> str:
    if not isinstance(value, bytes):
        return hexdump(value.to_bytes((value.bit_length() + 7) // 8, byteorder='big'))
    out = ""
    for i in range(0, len(value), 16):
        chunk = value[i:i + 16]
        out += f"{i:08x}: {' '.join(f'{b:02x}' for b in chunk): <48} {''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)}\n"

    return out
