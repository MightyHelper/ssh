import io
import logging
import os
import sys
from random import randint

import rich.table
import rich.table
import rich.table
import rich.table
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, AEADEncryptionContext, AEADDecryptionContext, modes
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from rich.console import Console
from rich.logging import RichHandler

from src.bytes_io_read_writables import BytesIOReadWritable
from src.bytes_read_writable import BytesReadWritable
from src.common import hexdump, encode_uint32, request_str, \
  request_mpint, create_hmac
from src.constants import SSHConstants
from src.exchange_parameters import ExchangeParameters
from src.group14_prime import GROUP14_PRIME
from src.packet import SSHMessageChannelOpenPacket, SSHMessageChannelRequestPacket, SSHNewKeysPacket, \
  SSHKexdhInitPacket, SSHMessageServiceRequestPacket, SSHMessageUserAuthRequestPacket, SSHMessageChannelDataPacket, \
  SSHMessageGlobalRequestPacket, SSHMessageRequestFailurePacket, SSHMessageChannelOpenConfirmationPacket, \
  SSHKEXInitPacket
from src.ssh_packet import SSHPacket
from src.ssh_socket_wrapper import SSHSocketWrapper
from src.version import SSHVersion

LENGTH = 256
KEY_SIZE = 2048

console = Console()
logging.basicConfig(
  level='DEBUG',
  format='%(name)s: %(message)s',
  datefmt='[%X]',
  handlers=[RichHandler(rich_tracebacks=True, console=console)],
)


class SSHClient:
  my_ssh_version: SSHVersion = SSHVersion.from_string('SSH-2.0-LeoFedeSsh0.1 Un trabajo para un tp\r\n')
  """The SSH version string for the client"""
  remote_ssh_version: SSHVersion = None
  """The SSH version string for the server"""
  s: SSHSocketWrapper | None
  """The socket connection to the server"""

  exchange_parameters: ExchangeParameters
  """The parameters for the key exchange"""

  cipher_c2s: Cipher
  cipher_s2c: Cipher
  encryptor: AEADEncryptionContext
  decryptor: AEADDecryptionContext

  logger: logging.Logger = logging.getLogger("SSHClient")
  bytes_logger: logging.Logger = logging.getLogger("SSH_bytes")
  packet_logger: logging.Logger = logging.getLogger("SSH_packt")

  def __init__(self, host, port):
    self.s = None
    self.host = host
    self.port = port
    self.block_size = 35000
    self.exchange_parameters = ExchangeParameters()

  def mac_validator_s2c(self, data: bytes, mac: bytes) -> bool:
    self.logger.info(f"Validate MAC #{SSHPacket.remote_to_local_sequence_number} on \n{hexdump(data)}")
    self.logger.info(f"mac_s2c is \n{hexdump(self.exchange_parameters.mac_s2c)}")
    c = self.mac_applicator_s2c(data)
    if mac == c:
      self.logger.info(f"MAC VALIDATED with offset {SSHPacket.remote_to_local_sequence_number}")
      return True
    c = self.mac_applicator_s2c(data)
    self.logger.warning(
      f"MAC NOT VALIDATED with offset {SSHPacket.remote_to_local_sequence_number}\n{hexdump(mac)}\n{hexdump(c)}")
    return False

  def mac_applicator_s2c(self, data: bytes, offset: int | None = None) -> bytes:
    offset = offset if offset is not None else SSHPacket.remote_to_local_sequence_number
    seq_with_data = encode_uint32(offset) + data
    return create_hmac(self.exchange_parameters.mac_s2c, seq_with_data)

  def mac_applicator_c2s(self, data: bytes, offset: int | None = None) -> bytes:
    offset = offset if offset is not None else SSHPacket.local_to_remote_sequence_number
    seq_with_data = encode_uint32(offset) + data
    return create_hmac(self.exchange_parameters.mac_c2s, seq_with_data)

  def connect(self):
    self.s = SSHSocketWrapper(self.host, self.port)
    self.logger.info('Connected to server')
    self._exchange_versions()
    self.my_key_exchange()
    expect_markus = True
    if expect_markus:
      print(self.s.recv_packet())
    self.s.send_packet(SSHPacket.create_from_bytes(b'\x02\x00\x00\x00\x06markus'))
    self.request_service('ssh-userauth')
    self.password_auth()
    chan = self.open_session_channel(0)
    self.run_exec_command(sys.argv[1], chan)

  def run_exec_command(self, command: str, channel_id: int = 0):
    self.s.send_packet(SSHMessageChannelRequestPacket(
      sender_channel=channel_id,
      request_type=b'exec',
      want_reply=True,
      request_data=command.encode('utf-8')
    ))
    response = self.s.recv_packet()
    while response.code_constant != SSHConstants.SSH2_MSG_CHANNEL_DATA:
      self.logger.info(f'Waiting for data... {response.code}')
      response = self.s.recv_packet()

    channel_data = SSHMessageChannelDataPacket.from_ssh_packet(response)
    self.logger.info(f'Response: {channel_data}')
    self.logger.info(f'Channel data: {response.payload} {channel_data.recipient_channel=} {channel_data.data=}')

  def deal_with_global_request(self):
    response = self.s.recv_packet()
    global_request = SSHMessageGlobalRequestPacket.from_ssh_packet(response)
    self.logger.info(f'Global request: {global_request}')

    self.s.send_packet(SSHMessageRequestFailurePacket())

  def open_session_channel(self, channel_id: int = 0):
    self.s.send_packet(SSHMessageChannelOpenPacket(
      channel_type=b'session',
      sender_channel=channel_id,
      initial_window_size=0x100000,
      maximum_packet_size=0x4000
    ))
    self.deal_with_global_request()
    response = self.s.recv_packet()
    channel_open_confirmation = SSHMessageChannelOpenConfirmationPacket.from_ssh_packet(response)
    self.logger.info(f'Channel open: {channel_open_confirmation}')
    return channel_open_confirmation.sender_channel

  def password_auth(self):
    self.s.send_packet(SSHMessageUserAuthRequestPacket(
      username=b'alakran',
      service_name=b'ssh-connection',
      method_name=b'password',
      password=b'nalanran'
    ))
    response = self.s.recv_packet()
    self.logger.info(f'Response: {response}')
    assert response.code_constant == SSHConstants.SSH2_MSG_USERAUTH_SUCCESS, f"Auth not successful {response.code}"

  def request_service(self, service_name: str) -> None:
    self.s.send_packet(SSHMessageServiceRequestPacket(service_name.encode('utf-8')))
    response = self.s.recv_packet()
    self.logger.info(f'Response: {response}')
    assert response.code_constant == SSHConstants.SSH2_MSG_SERVICE_ACCEPT, f"Service not accepted {response.code}"

  def my_key_exchange(self):
    """ Sends the initial key exchange message to the server with format """
    # 1. Send the initial key exchange message
    local_key2 = SSHKEXInitPacket(
      cookie=os.urandom(16),
      kex_algorithms=[b'diffie-hellman-group14-sha256'],
      server_host_key_algorithms=[b'rsa-sha2-256'],
      encryption_algorithms_client_to_server=[b'aes128-ctr'],
      encryption_algorithms_server_to_client=[b'aes128-ctr'],
      mac_algorithms_client_to_server=[b'hmac-sha1'],
      mac_algorithms_server_to_client=[b'hmac-sha1'],
      compression_algorithms_client_to_server=[b'none'],
      compression_algorithms_server_to_client=[b'none'],
      languages_client_to_server=[b''],
      languages_server_to_client=[b''],
      first_kex_packet_follows=False,
      reserved=0
    )
    if self.logger.level <= logging.INFO:
      console.print(f"Local key:", local_key2)
    self.exchange_parameters.i_c = local_key2.packet().payload
    self.s.send_packet(local_key2)
    packet = self.s.recv_packet()
    self.exchange_parameters.i_s = packet.payload
    remote_key = SSHKEXInitPacket.from_ssh_packet(packet)
    if self.logger.level <= logging.INFO:
      console.print(f"Remote key:", remote_key)

    remote_key.assert_supports_algorithms(local_key2)
    self.perform_dh_key_exchange()

  def perform_dh_key_exchange(self):
    """Run diffie-hellman-group14-sha256 kex"""
    public_key_bytes = self.generate_local_keys()
    self.send_local_keys(public_key_bytes)
    server_public_key = self.receive_remote_keys()
    self.expect_new_keys()
    self.derive_shared_key(server_public_key)
    self.enter_encryption()

  def enter_encryption(self):
    self.s.do_encryption = True
    self.s.encryptor = self.encryptor
    self.s.decryptor = self.decryptor
    self.s.mac_validator_s2c = self.mac_validator_s2c
    self.s.mac_applicator_c2s = self.mac_applicator_c2s

  def expect_new_keys(self):
    assert self.s.recv_packet().payload == SSHConstants.SSH2_MSG_NEWKEYS.to_bytes(), "Server did not send new keys"
    # Send the new keys message
    self.s.send_packet(SSHNewKeysPacket())
    self.logger.info("Habemus New Keys!")

  def derive_shared_key(self, server_f_value):
    shared_k = pow(server_f_value, self.exchange_parameters.x, self.exchange_parameters.p)

    self.exchange_parameters.k = shared_k
    self.exchange_parameters.session_id = self.exchange_parameters.h_bytes
    self.debug_parameter("Derived key", self.exchange_parameters.k)
    self.debug_parameter("Buffer", self.exchange_parameters._buffer)
    self.debug_parameter("hash", self.exchange_parameters.h_bytes)
    self.debug_parameter("[A] IV0 C2S", self.exchange_parameters.iv0_c2s)
    self.debug_parameter("[B] IV0 S2C", self.exchange_parameters.iv0_s2c)
    self.debug_parameter("[C] Key C2S", self.exchange_parameters.key_c2s)
    self.debug_parameter("[D] Key S2C", self.exchange_parameters.key_s2c)
    self.debug_parameter("[E] MAC C2S", self.exchange_parameters.mac_c2s)
    self.debug_parameter("[F] MAC S2C", self.exchange_parameters.mac_s2c)
    self.cipher_c2s = Cipher(
      AES(self.exchange_parameters.key_c2s[:16]),
      modes.CTR(self.exchange_parameters.iv0_c2s[:16]),
      default_backend()
    )
    self.cipher_s2c = Cipher(
      AES(self.exchange_parameters.key_s2c[:16]),
      modes.CTR(self.exchange_parameters.iv0_s2c[:16]),
      default_backend()
    )
    self.encryptor = self.cipher_c2s.encryptor()
    self.decryptor = self.cipher_s2c.decryptor()

  def debug_parameter(self, name, param):
    self.logger.info(f'{name}: {param}\n{hexdump(param)}')

  def receive_remote_keys(self):
    self.logger.info(f'waiting for server response')
    # 3. Receive the server's public key
    server_payload = self.s.recv_packet().payload
    parse_server_payload = BytesIOReadWritable(io.BytesIO(server_payload))
    assert parse_server_payload.recv(1) == bytes([SSHConstants.SSH2_MSG_KEXDH_REPLY])

    self.exchange_parameters.k_s = self.parse_server_public_key(parse_server_payload)

    self.exchange_parameters.f = request_mpint(parse_server_payload)
    self.logger.info(f'Server f value:\n{hexdump(self.exchange_parameters.f)}')
    server_signature = self.request_server_signature(parse_server_payload)
    # The server signature is used to verify the server's public key authenticity
    return self.exchange_parameters.f

  def generate_local_keys(self):
    self.logger.info(f'Generating keys...')
    self.exchange_parameters.p = GROUP14_PRIME
    self.exchange_parameters.g = 2
    self.exchange_parameters.q = 2 ** 256 - 1
    self.exchange_parameters.x = randint(2, self.exchange_parameters.q)
    self.exchange_parameters.e = pow(
      self.exchange_parameters.g,
      self.exchange_parameters.x,
      self.exchange_parameters.p
    )
    self.logger.info(f'P: {self.exchange_parameters.p}\n{hexdump(self.exchange_parameters.p)}')
    self.logger.info(f'G: {self.exchange_parameters.g}\n{hexdump(self.exchange_parameters.g)}')
    self.logger.info(f'X: {self.exchange_parameters.x}\n{hexdump(self.exchange_parameters.x)}')
    self.logger.info(f'E: {self.exchange_parameters.e}\n{hexdump(self.exchange_parameters.e)}')
    # Add sign bit
    return self.exchange_parameters.e_bytes

  def request_server_signature(self, server_payload: BytesReadWritable):
    hash_h = request_str(server_payload)
    hash_h_b = BytesIOReadWritable(io.BytesIO(hash_h))
    algorithm = request_str(hash_h_b)
    signature = request_str(hash_h_b)
    table = rich.table.Table(title="Server Signature", highlight=True)
    table.add_column("Field", overflow="fold")
    table.add_column("Value", overflow="fold")
    table.add_row("Algorithm", repr(algorithm))
    table.add_row("Signature", repr(signature))
    table.add_row("Trailing", repr(hash_h_b.recv(9999999)))
    console.print(table)
    return hash_h + algorithm + signature

  def parse_server_public_key(self, parse_server_payload: BytesReadWritable):
    server_public_key = request_str(parse_server_payload)
    server_public_key_b = BytesIOReadWritable(io.BytesIO(server_public_key))
    pk_type = request_str(server_public_key_b)
    assert pk_type == b'ssh-rsa'
    e = request_mpint(server_public_key_b)
    pk_value = request_mpint(server_public_key_b)
    table = rich.table.Table(title="Server Public Key", highlight=True)
    table.add_column("Field", overflow="fold")
    table.add_column("Value", overflow="fold")
    table.add_row("Type", repr(pk_type))
    table.add_row("E", repr(e))
    table.add_row("Value", repr(pk_value))
    table.add_row("Value hexdump", hexdump(pk_value))
    table.add_row("Trailing", repr(server_public_key_b.recv(9999)))
    console.print(table)
    # Discard all extra info
    return server_public_key

  def send_local_keys(self, public_key_bytes: bytes):
    self.s.send_packet(SSHKexdhInitPacket(public_key_bytes))
    self.logger.info(f'Sent SSH_MSG_KEXDH_INIT')

  def _exchange_versions(self) -> None:
    """Exchange SSH versions with the remote server (Step 1)"""
    self.logger.debug(f'My SSH version: {repr(self.my_ssh_version)}')
    self.s.send_str(str(self.my_ssh_version))
    # Note, according to RFC 4253, the server could send extra lines of utf-8 text ended by crlf not starting in SSH-, which can be ignored
    remote_version: str = self.s.recv_str()
    self.remote_ssh_version = SSHVersion.from_string(remote_version)
    self.logger.debug(f'Remote SSH version: {repr(self.remote_ssh_version)}')
    self.exchange_parameters.v_c = repr(self.my_ssh_version).encode('utf-8')
    self.exchange_parameters.v_s = repr(self.remote_ssh_version).encode('utf-8')


def main():
  ssh = SSHClient(host='localhost', port=8222)
  ssh.connect()


if __name__ == '__main__':
  # test_mpint()
  main()
  # main2()
