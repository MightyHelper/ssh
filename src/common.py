import hashlib
import hmac

from src.bytes_read_writable import BytesReadWritable


def hexdump(value: bytes | int) -> str:
    if not isinstance(value, bytes):
        return hexdump(value.to_bytes((value.bit_length() + 7) // 8, byteorder='big'))
    out = ""
    for i in range(0, len(value), 16):
        chunk = value[i:i + 16]
        out += f"{i:08x}: {' '.join(f'{b:02x}' for b in chunk): <48} {''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)}\n"

    return out


def encode_uint32(data: int) -> bytes:
  return data.to_bytes(4, byteorder='big')


def encode_str(data: bytes) -> bytes:
  return encode_uint32(len(data)) + data


def request_uint32(source: BytesReadWritable) -> int:
  return int.from_bytes(source.recv(4), byteorder='big')


def request_byte(source: BytesReadWritable) -> int:
  return int.from_bytes(source.recv(1), byteorder='big')


def encode_byte(data: int) -> bytes:
  return data.to_bytes(1, byteorder='big')


def request_str(source: BytesReadWritable) -> bytes:
  length = request_uint32(source)
  return source.recv(length)


def encode_mpint(n: int) -> bytes:
  if n < 0:
    raise NotImplementedError("Negative numbers not implemented")
  if n == 0:
    return b'\x00\x00\x00\x00'
  abs_bytes = n.to_bytes((n.bit_length() + 7) // 8, byteorder='big', signed=False)
  if abs_bytes[0] & 0x80:  # If the highest bit is set, prepend a 0x00 byte
    abs_bytes = b'\x00' + abs_bytes
  return encode_str(abs_bytes)


def request_mpint(source: BytesReadWritable) -> int:
  return int.from_bytes(request_str(source), byteorder='big')


def request_namelist(source: BytesReadWritable) -> list[bytes]:
  return request_str(source).split(b',')


def encode_namelist(data: list[bytes]) -> bytes:
  return encode_str(b','.join(data))


def request_bool(source: BytesReadWritable) -> bool:
  return bool(request_byte(source))


def encode_bool(data: bool) -> bytes:
  return encode_byte(1 if data else 0)

def create_hmac(key: bytes, message: bytes) -> bytes:
  return hmac.HMAC(key[:20], message, hashlib.sha1).digest()

