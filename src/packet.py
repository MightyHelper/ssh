import io
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import ClassVar, Self

from src.bytes_io_read_writables import BytesIOReadWritable
from src.bytes_read_writable import BytesReadWritable
from src.common import encode_byte, encode_str, encode_uint32, encode_bool, request_uint32, request_str, request_bool, \
  encode_mpint, request_mpint, encode_namelist, request_namelist, request_byte
from src.constants import SSHConstants

from src.ssh_packet import SSHPacket


@dataclass
class Packet(ABC):
  type: ClassVar[SSHConstants]

  @abstractmethod
  def payload(self) -> bytes:
    pass

  def packet(self, block_size: int = 8) -> SSHPacket:
    return SSHPacket.create_from_bytes(encode_byte(self.type.value) + self.payload(), block_size)

  @classmethod
  def request(cls, source: BytesReadWritable) -> Self:
    """Assume the type has been read before"""
    raise NotImplementedError

  @classmethod
  def from_ssh_packet(cls, packet: SSHPacket) -> Self:
    assert len(packet.payload) > 0, "Packet payload is empty"
    assert packet.payload[0] == cls.type.value, f"Packet payload type is {packet.payload[0]}, expected {cls.type.value}"
    return cls.request(BytesIOReadWritable.of(packet.payload[1:]))


@dataclass
class SSHMessageChannelOpenPacket(Packet):
  type = SSHConstants.SSH2_MSG_CHANNEL_OPEN
  channel_type: bytes
  sender_channel: int
  initial_window_size: int
  maximum_packet_size: int

  def payload(self) -> bytes:
    return (
      encode_str(self.channel_type) +
      encode_uint32(self.sender_channel) +
      encode_uint32(self.initial_window_size) +
      encode_uint32(self.maximum_packet_size)
    )


@dataclass
class SSHMessageChannelRequestPacket(Packet):
  type = SSHConstants.SSH2_MSG_CHANNEL_REQUEST
  sender_channel: int
  request_type: bytes
  want_reply: bool
  request_data: bytes

  def payload(self) -> bytes:
    return (
      encode_uint32(self.sender_channel) +
      encode_str(self.request_type) +
      encode_bool(self.want_reply) +
      encode_str(self.request_data)
    )


@dataclass
class SSHNewKeysPacket(Packet):
  type = SSHConstants.SSH2_MSG_NEWKEYS

  def payload(self) -> bytes:
    return bytes()

  @classmethod
  def request(cls, source: BytesReadWritable) -> Self:
    return cls()


@dataclass
class SSHMessageRequestFailurePacket(Packet):
  type = SSHConstants.SSH2_MSG_REQUEST_FAILURE

  def payload(self) -> bytes:
    return bytes()

  @classmethod
  def request(cls, source: BytesReadWritable) -> Self:
    return cls()


@dataclass
class SSHKexdhInitPacket(Packet):
  type = SSHConstants.SSH2_MSG_KEXDH_INIT
  public_key_bytes: bytes

  def payload(self) -> bytes:
    return self.public_key_bytes


@dataclass
class SSHMessageServiceRequestPacket(Packet):
  type = SSHConstants.SSH2_MSG_SERVICE_REQUEST
  service_name: bytes

  def payload(self) -> bytes:
    return encode_str(self.service_name)


@dataclass
class SSHMessageUserAuthRequestPacket(Packet):
  type = SSHConstants.SSH2_MSG_USERAUTH_REQUEST
  username: bytes
  service_name: bytes
  method_name: bytes
  password: bytes

  def payload(self) -> bytes:
    return (
      encode_str(self.username) +
      encode_str(self.service_name) +
      encode_str(self.method_name) +
      encode_bool(False) +
      encode_str(self.password)
    )


@dataclass
class SSHMessageChannelOpenConfirmationPacket(Packet):
  type = SSHConstants.SSH2_MSG_CHANNEL_OPEN_CONFIRMATION
  recipient_channel: int
  sender_channel: int
  initial_window_size: int
  maximum_packet_size: int

  def payload(self) -> bytes:
    return (
      encode_uint32(self.recipient_channel) +
      encode_uint32(self.sender_channel) +
      encode_uint32(self.initial_window_size) +
      encode_uint32(self.maximum_packet_size)
    )

  @classmethod
  def request(cls, source: BytesReadWritable) -> Self:
    return cls(
      request_uint32(source),
      request_uint32(source),
      request_uint32(source),
      request_uint32(source)
    )


@dataclass
class SSHMessageChannelOpenFailurePacket(Packet):
  """
  byte      SSH_MSG_CHANNEL_OPEN_FAILURE
  uint32    recipient channel
  uint32    reason code
  string    description in ISO-10646 UTF-8 encoding [RFC3629]
  string    language tag [RFC3066]
  """
  type = SSHConstants.SSH2_MSG_CHANNEL_OPEN_FAILURE
  recipient_channel: int
  reason_code: int
  description: bytes
  language_tag: bytes

  def payload(self) -> bytes:
    return (
      encode_uint32(self.recipient_channel) +
      encode_uint32(self.reason_code) +
      encode_str(self.description) +
      encode_str(self.language_tag)
    )

  @classmethod
  def request(cls, source: BytesReadWritable) -> Self:
    return cls(
      request_uint32(source),
      request_uint32(source),
      request_str(source),
      request_str(source)
    )

  @property
  def reason(self) -> str:
    return SSHConstants.find_by_value("SSH2_OPEN", self.reason_code).name

@dataclass
class SSHMessageChannelDataPacket(Packet):
  """
  byte      SSH_MSG_CHANNEL_DATA
  uint32    recipient channel
  string    data
  """
  type = SSHConstants.SSH2_MSG_CHANNEL_DATA
  recipient_channel: int
  data: bytes

  def payload(self) -> bytes:
    return (
      encode_uint32(self.recipient_channel) +
      encode_str(self.data)
    )

  @classmethod
  def request(cls, source: BytesReadWritable) -> Self:
    return cls(
      request_uint32(source),
      request_str(source)
    )

@dataclass
class SSHMessageGlobalRequestPacket(Packet):
  """
  byte      SSH_MSG_GLOBAL_REQUEST
  string    "tcpip-forward"
  boolean   want reply
  string    address to bind (e.g., "0.0.0.0")
  uint32    port number to bind
  """
  type = SSHConstants.SSH2_MSG_GLOBAL_REQUEST
  request_name: bytes
  want_reply: bool
  extra_data: bytes

  def payload(self) -> bytes:
    return (
      encode_str(self.request_name) +
      encode_bool(self.want_reply) +
      encode_str(self.extra_data)
    )

  @classmethod
  def request(cls, source: BytesReadWritable) -> Self:
    return cls(
      request_str(source),
      request_bool(source),
      request_str(source)
    )

@dataclass
class SSHMessageKexdhReplyPacket(Packet):
  """
  byte      SSH_MSG_KEXDH_REPLY
  string    server public host key and certificates (K_S)
  mpint     f
  string    signature of H
  """
  type = SSHConstants.SSH2_MSG_KEXDH_REPLY
  server_public_host_key: bytes
  f: int
  signature: bytes

  def payload(self) -> bytes:
    return (
      encode_str(self.server_public_host_key) +
      encode_mpint(self.f) +
      encode_str(self.signature)
    )

  @classmethod
  def request(cls, source: BytesReadWritable) -> Self:
    return cls(
      request_str(source),
      request_mpint(source),
      request_str(source)
    )

@dataclass
class SSHKEXInitPacket(Packet):
  """
  Decodes the remote key exchange message with format
  ```
  byte         SSH_MSG_KEXINIT
  byte[16]     cookie (random bytes)
  name-list    kex_algorithms
  name-list    server_host_key_algorithms
  name-list    encryption_algorithms_client_to_server
  name-list    encryption_algorithms_server_to_client
  name-list    mac_algorithms_client_to_server
  name-list    mac_algorithms_server_to_client
  name-list    compression_algorithms_client_to_server
  name-list    compression_algorithms_server_to_client
  name-list    languages_client_to_server
  name-list    languages_server_to_client
  boolean      first_kex_packet_follows
  uint32       0 (reserved for future extension)
  ```
  """
  type = SSHConstants.SSH2_MSG_KEXINIT
  cookie: bytes
  kex_algorithms: list[bytes]
  server_host_key_algorithms: list[bytes]
  encryption_algorithms_client_to_server: list[bytes]
  encryption_algorithms_server_to_client: list[bytes]
  mac_algorithms_client_to_server: list[bytes]
  mac_algorithms_server_to_client: list[bytes]
  compression_algorithms_client_to_server: list[bytes]
  compression_algorithms_server_to_client: list[bytes]
  languages_client_to_server: list[bytes]
  languages_server_to_client: list[bytes]
  first_kex_packet_follows: bool
  reserved: int

  def payload(self) -> bytes:
    return (
      self.cookie +
      encode_namelist(self.kex_algorithms) +
      encode_namelist(self.server_host_key_algorithms) +
      encode_namelist(self.encryption_algorithms_client_to_server) +
      encode_namelist(self.encryption_algorithms_server_to_client) +
      encode_namelist(self.mac_algorithms_client_to_server) +
      encode_namelist(self.mac_algorithms_server_to_client) +
      encode_namelist(self.compression_algorithms_client_to_server) +
      encode_namelist(self.compression_algorithms_server_to_client) +
      encode_namelist(self.languages_client_to_server) +
      encode_namelist(self.languages_server_to_client) +
      encode_bool(self.first_kex_packet_follows) +
      encode_uint32(self.reserved)
    )

  @classmethod
  def request(cls, source: BytesReadWritable) -> Self:
    return cls(
      source.recv(16),
      request_namelist(source),
      request_namelist(source),
      request_namelist(source),
      request_namelist(source),
      request_namelist(source),
      request_namelist(source),
      request_namelist(source),
      request_namelist(source),
      request_namelist(source),
      request_namelist(source),
      bool(request_byte(source)),
      request_uint32(source)
    )

  def assert_supports_algorithms(self, other_key: Self):
    assert other_key.kex_algorithms[0] in self.kex_algorithms, "Server does not support DH key exchange"
    assert other_key.server_host_key_algorithms[
             0] in self.server_host_key_algorithms, "Server does not support RSA key exchange"
    assert other_key.encryption_algorithms_client_to_server[
             0] in self.encryption_algorithms_client_to_server, "Server does not support AES encryption"
    assert other_key.encryption_algorithms_server_to_client[
             0] in self.encryption_algorithms_server_to_client, "Server does not support AES encryption"
    assert other_key.mac_algorithms_client_to_server[
             0] in self.mac_algorithms_client_to_server, "Server does not support HMAC-SHA1"
    assert other_key.mac_algorithms_server_to_client[
             0] in self.mac_algorithms_server_to_client, "Server does not support HMAC-SHA1"
    assert other_key.compression_algorithms_client_to_server[
             0] in self.compression_algorithms_client_to_server, "Server does not support not using compression"
    assert other_key.compression_algorithms_server_to_client[
             0] in self.compression_algorithms_server_to_client, "Server does not support not using compression"

@dataclass
class SSHMessageIgnorePacket(Packet):
  """
  byte      SSH_MSG_IGNORE
  string    data
  """
  type = SSHConstants.SSH2_MSG_IGNORE
  data: bytes

  def payload(self) -> bytes:
    return encode_str(self.data)

  @classmethod
  def request(cls, source: BytesReadWritable) -> Self:
    return cls(request_str(source))