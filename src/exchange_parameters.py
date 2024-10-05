import hashlib

from src.common import encode_mpint, encode_str


class ExchangeParameters:
  v_c: bytes
  """Client's identification string (CR and LF must not be included)"""
  v_s: bytes
  """Server's identification string (CR and LF must not be included)"""
  i_c: bytes
  """Client's SSH_MSG_KEXINIT"""
  i_s: bytes
  """Server's SSH_MSG_KEXINIT"""
  k_s: bytes
  """Server's public host key"""
  p: int
  """Safe prime"""
  q: int
  """Subprime: Actually not computed, just estimated"""
  g: int
  """Generator for subgroup"""
  x: int
  """Private key"""
  e: int
  """Public key"""
  y: int | None
  """Server's private key"""
  f: int
  """Server's public key"""
  k: int
  """Shared secret"""
  session_id: bytes
  """The session ID (used for deriving keys, the first exchange hash)"""

  @property
  def e_bytes(self) -> bytes:
    return encode_mpint(self.e)

  @property
  def k_bytes(self) -> bytes:
    return encode_mpint(self.k)

  @property
  def f_bytes(self) -> bytes:
    return encode_mpint(self.f)

  @property
  def _buffer(self) -> bytes:
    parts = [
      encode_str(self.v_c[:-1]),
      encode_str(self.v_s),
      encode_str(self.i_c),
      encode_str(self.i_s),
      encode_str(self.k_s),
      self.e_bytes,
      self.f_bytes,
      self.k_bytes,
    ]
    return b''.join(parts)

  @property
  def h_bytes(self) -> bytes:
    """Exchange hash"""
    return hashlib.sha256(self._buffer).digest()

  @property
  def iv0_c2s(self) -> bytes:
    """Initial IV client to server"""
    return hashlib.sha256(encode_mpint(self.k) + self.h_bytes + b'A' + self.h_bytes).digest()

  @property
  def iv0_s2c(self) -> bytes:
    """Initial IV server to client"""
    return hashlib.sha256(encode_mpint(self.k) + self.h_bytes + b'B' + self.h_bytes).digest()

  @property
  def key_c2s(self) -> bytes:
    """Encryption key client to server"""
    return hashlib.sha256(encode_mpint(self.k) + self.h_bytes + b'C' + self.h_bytes).digest()

  @property
  def key_s2c(self) -> bytes:
    """Encryption key server to client"""
    return hashlib.sha256(encode_mpint(self.k) + self.h_bytes + b'D' + self.h_bytes).digest()

  @property
  def mac_c2s(self) -> bytes:
    """MAC key client to server"""
    return hashlib.sha256(encode_mpint(self.k) + self.h_bytes + b'E' + self.h_bytes).digest()

  @property
  def mac_s2c(self) -> bytes:
    """MAC key server to client"""
    return hashlib.sha256(encode_mpint(self.k) + self.h_bytes + b'F' + self.h_bytes).digest()
