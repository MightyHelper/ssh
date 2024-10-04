from abc import ABC, abstractmethod
from dataclasses import dataclass

from src.common import encode_byte, encode_str, encode_uint32, encode_bool
from src.constants import SSHConstants

from src.ssh_packet import SSHPacket


@dataclass
class Packet(ABC):
  @abstractmethod
  def payload(self) -> bytes:
    pass

  def packet(self, block_size: int = 8) -> SSHPacket:
    return SSHPacket.create_from_bytes(self.payload(), block_size)


@dataclass
class SSHMessageChannelOpenPacket(Packet):
  channel_type: bytes
  sender_channel: int
  initial_window_size: int
  maximum_packet_size: int

  def payload(self) -> bytes:
    return (
      encode_byte(SSHConstants.SSH2_MSG_CHANNEL_OPEN) +
      encode_str(self.channel_type) +
      encode_uint32(self.sender_channel) +
      encode_uint32(self.initial_window_size) +
      encode_uint32(self.maximum_packet_size)
    )


@dataclass
class SSHMessageChannelRequestPacket(Packet):
  sender_channel: int
  request_type: bytes
  want_reply: bool
  request_data: bytes

  def payload(self) -> bytes:
    return (
      encode_byte(SSHConstants.SSH2_MSG_CHANNEL_REQUEST) +
      encode_uint32(self.sender_channel) +
      encode_str(self.request_type) +
      encode_bool(self.want_reply) +
      encode_str(self.request_data)
    )


@dataclass
class SSHNewKeysPacket(Packet):
  def payload(self) -> bytes:
    return SSHConstants.SSH2_MSG_NEWKEYS.to_bytes(1)


@dataclass
class SSHKexdhInitPacket(Packet):
  public_key_bytes: bytes

  def payload(self) -> bytes:
    return encode_byte(SSHConstants.SSH2_MSG_KEXDH_INIT) + self.public_key_bytes


@dataclass
class SSHMessageServiceRequestPacket(Packet):
  service_name: bytes

  def payload(self) -> bytes:
    return encode_byte(SSHConstants.SSH2_MSG_SERVICE_REQUEST) + encode_str(self.service_name)


@dataclass
class SSHMessageUserAuthRequestPacket(Packet):
  username: bytes
  service_name: bytes
  method_name: bytes
  password: bytes

  def payload(self) -> bytes:
    return (
      encode_byte(SSHConstants.SSH2_MSG_USERAUTH_REQUEST) +
      encode_str(self.username) +
      encode_str(self.service_name) +
      encode_str(self.method_name) +
      encode_bool(False) +
      encode_str(self.password)
    )
