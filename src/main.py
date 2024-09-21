import hashlib
import hmac
import io
import os
import re
import socket
import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import ClassVar, Self
from rich.logging import RichHandler
from rich.console import Console
import sys
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC

import logging

from zmq.asyncio import Socket

console = Console()
logging.basicConfig(
    level='DEBUG',
    format='%(name)s[%(levelname)s]: %(message)s',
    datefmt='[%X]',
    handlers=[RichHandler(rich_tracebacks=True, console=console)],
)


@dataclass
class SSHVersion:
    proto_version: str
    software_version: str
    comments: str = ''

    PATTERN: ClassVar[re.Pattern] = re.compile(
        r'^SSH-(?P<proto_version>\d+\.\d+)-(?P<software_version>[a-zA-Z0-9_\-.]+)(\s*(?P<comments>.*))?\r?\n$'
    )

    def __str__(self):
        return f'SSH-{self.proto_version}-{self.software_version} {self.comments}\r\n'

    def __repr__(self):
        return f'SSH-{self.proto_version}-{self.software_version} {self.comments}'

    @classmethod
    def from_string(cls, data: str) -> Self:
        match = cls.PATTERN.match(data)
        if not match:
            raise ValueError(f'Invalid SSH version string: {data}')
        return cls(**match.groupdict())


@dataclass
class SSHKEXInitPacket:
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
    kex_algorithms: list[str]
    server_host_key_algorithms: list[str]
    encryption_algorithms_client_to_server: list[str]
    encryption_algorithms_server_to_client: list[str]
    mac_algorithms_client_to_server: list[str]
    mac_algorithms_server_to_client: list[str]
    compression_algorithms_client_to_server: list[str]
    compression_algorithms_server_to_client: list[str]
    languages_client_to_server: list[str]
    languages_server_to_client: list[str]
    first_kex_packet_follows: bool
    reserved: int

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        myio = io.BytesIO(data)
        kex_init = myio.read(1)
        assert kex_init == bytes([SSHConstants.SSH_MSG_KEXINIT])
        _cookie = myio.read(16)
        read_name_list = lambda: myio.read(int.from_bytes(myio.read(4), 'big')).decode('utf-8').split(',')
        return cls(
            kex_algorithms=read_name_list(),
            server_host_key_algorithms=read_name_list(),
            encryption_algorithms_client_to_server=read_name_list(),
            encryption_algorithms_server_to_client=read_name_list(),
            mac_algorithms_client_to_server=read_name_list(),
            mac_algorithms_server_to_client=read_name_list(),
            compression_algorithms_client_to_server=read_name_list(),
            compression_algorithms_server_to_client=read_name_list(),
            languages_client_to_server=read_name_list(),
            languages_server_to_client=read_name_list(),
            first_kex_packet_follows=myio.read(1) == b'\x01',
            reserved=int.from_bytes(myio.read(4), 'big')
        )

    def to_bytes(self) -> bytes:
        myio = io.BytesIO()
        myio.write(bytes([SSHConstants.SSH_MSG_KEXINIT]))
        myio.write(os.urandom(16))
        write_name_list = lambda x: myio.write(struct.pack('>I', len(','.join(x))) + ','.join(x).encode('utf-8'))
        write_name_list(self.kex_algorithms)
        write_name_list(self.server_host_key_algorithms)
        write_name_list(self.encryption_algorithms_client_to_server)
        write_name_list(self.encryption_algorithms_server_to_client)
        write_name_list(self.mac_algorithms_client_to_server)
        write_name_list(self.mac_algorithms_server_to_client)
        write_name_list(self.compression_algorithms_client_to_server)
        write_name_list(self.compression_algorithms_server_to_client)
        write_name_list(self.languages_client_to_server)
        write_name_list(self.languages_server_to_client)
        myio.write(b'\x01' if self.first_kex_packet_follows else b'\x00')
        myio.write(struct.pack('>I', self.reserved))
        return myio.getvalue()


class SSHConstants(IntEnum):
    """Graciously donated by https://javadoc.io/doc/org.apache.sshd/sshd-common/2.6.0/constant-values.html#org.apache.sshd.common.SshConstants"""
    SSH2_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT = 1
    SSH_EXTENDED_DATA_STDERR = 1
    SSH_MSG_DISCONNECT = 1
    SSH_OPEN_ADMINISTRATIVELY_PROHIBITED = 1
    SSH2_DISCONNECT_CONNECTION_LOST = 10
    SSH_MSG_CHANNEL_FAILURE = 100
    SSH2_DISCONNECT_BY_APPLICATION = 11
    SSH2_DISCONNECT_TOO_MANY_CONNECTIONS = 12
    SSH2_DISCONNECT_AUTH_CANCELLED_BY_USER = 13
    SSH2_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE = 14
    SSH2_DISCONNECT_ILLEGAL_USER_NAME = 15
    MSG_KEX_COOKIE_SIZE = 16
    SSH2_DISCONNECT_PROTOCOL_ERROR = 2
    SSH_MSG_IGNORE = 2
    SSH_OPEN_CONNECT_FAILED = 2
    SSH_MSG_KEXINIT = 20
    SSH_MSG_NEWKEYS = 21
    DEFAULT_PORT = 22
    SSH2_DISCONNECT_KEY_EXCHANGE_FAILED = 3
    SSH_MSG_UNIMPLEMENTED = 3
    SSH_OPEN_UNKNOWN_CHANNEL_TYPE = 3
    SSH_MSG_KEXDH_INIT = 30
    SSH_MSG_KEX_DH_GEX_REQUEST_OLD = 30
    SSH_MSG_KEX_FIRST = 30
    SSH_MSG_KEXDH_REPLY = 31
    SSH_MSG_KEX_DH_GEX_GROUP = 31
    SSH_MSG_KEX_DH_GEX_INIT = 32
    SSH_REQUIRED_PAYLOAD_PACKET_LENGTH_SUPPORT = 32768
    SSH_MSG_KEX_DH_GEX_REPLY = 33
    SSH_MSG_KEX_DH_GEX_REQUEST = 34
    SSH_REQUIRED_TOTAL_PACKET_LENGTH_SUPPORT = 35000
    SSH2_DISCONNECT_HOST_AUTHENTICATION_FAILED = 4
    SSH2_DISCONNECT_RESERVED = 4
    SSH_MSG_DEBUG = 4
    SSH_OPEN_RESOURCE_SHORTAGE = 4
    SSH_MSG_KEX_LAST = 49
    SSH2_DISCONNECT_MAC_ERROR = 5
    SSH_MSG_SERVICE_REQUEST = 5
    SSH_PACKET_HEADER_LEN = 5
    SSH_MSG_USERAUTH_REQUEST = 50
    SSH_MSG_USERAUTH_FAILURE = 51
    SSH_MSG_USERAUTH_SUCCESS = 52
    SSH_MSG_USERAUTH_BANNER = 53
    SSH2_DISCONNECT_COMPRESSION_ERROR = 6
    SSH_MSG_SERVICE_ACCEPT = 6
    SSH_MSG_USERAUTH_INFO_REQUEST = 60
    SSH_MSG_USERAUTH_PASSWD_CHANGEREQ = 60
    SSH_MSG_USERAUTH_PK_OK = 60
    SSH_MSG_USERAUTH_INFO_RESPONSE = 61
    SSH_MSG_USERAUTH_GSSAPI_MIC = 66
    SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE = 7
    SSH2_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED = 8
    SSH_MSG_GLOBAL_REQUEST = 80
    SSH_MSG_REQUEST_SUCCESS = 81
    SSH_MSG_REQUEST_FAILURE = 82
    SSH2_DISCONNECT_HOST_KEY_NOT_VERIFIABLE = 9
    SSH_MSG_CHANNEL_OPEN = 90
    SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91
    SSH_MSG_CHANNEL_OPEN_FAILURE = 92
    SSH_MSG_CHANNEL_WINDOW_ADJUST = 93
    SSH_MSG_CHANNEL_DATA = 94
    SSH_MSG_CHANNEL_EXTENDED_DATA = 95
    SSH_MSG_CHANNEL_EOF = 96
    SSH_MSG_CHANNEL_CLOSE = 97
    SSH_MSG_CHANNEL_REQUEST = 98
    SSH_MSG_CHANNEL_SUCCESS = 99




class SSHClient:
    my_ssh_version: SSHVersion = SSHVersion.from_string('SSH-2.0-LeoFedeSsh0.1 Un trabajo para un tp\r\n')
    remote_ssh_version: SSHVersion = None
    logger: logging.Logger = logging.getLogger("SSHClient")
    bytes_logger: logging.Logger = logging.getLogger("SSH_bytes")
    packet_logger: logging.Logger = logging.getLogger("SSH_packt")
    mac_algorthm: str | None = None
    mac_key: bytes | None = None
    s: socket.socket | None

    def __init__(self, host, port):
        self.s = None
        self.host = host
        self.port = port
        self.block_size = 35000
        # self.bytes_logger.setLevel(logging.DEBUG)

    def compute_session_id(self, client_version: bytes, server_version: bytes, kex_init_client: bytes, kex_init_server: bytes,
                           shared_secret: bytes) -> bytes:
        # Concatenate all the necessary components
        data = client_version + server_version + kex_init_client + kex_init_server + shared_secret
        return hashlib.sha256(data).digest()  # Using SHA-256 for session ID (as an example)

    def derive_keys(self, shared_secret: bytes, session_id: bytes) -> bytes:
        # Example: derive keys using HMAC
        key_length = 20  # For HMAC-SHA1, the key length is typically 20 bytes

        # Use a simple KDF (this is just an example; a real KDF would be more complex)
        return hmac.new(shared_secret, session_id, hashlib.sha1).digest()[:key_length]


    def create_hmac(self, key: bytes, message: bytes) -> bytes:
        return hmac.new(key, message, hashlib.sha1).digest()

    def connect(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((self.host, self.port))
        self.logger.info('Connected to server')
        self._exchange_versions()
        encryption_key = self.my_key_exchange()

        # # Use the derived key for symmetric encryption (AES for example)
        # cipher = Cipher(algorithms.AES(encryption_key), modes.CFB8(encryption_key[:16]), backend=default_backend())
        # encryptor = cipher.encryptor()
        #
        # # Placeholder: send a command (echo hi)
        # command_payload = b'echo hi'
        # encrypted_payload = encryptor.update(command_payload) + encryptor.finalize()
        # self.send_ssh_packet(encrypted_payload)
        #
        # # Placeholder for receiving command output (decryption not handled in this example)
        # response = self.recv(1024)
        # self.logger.info(f"Response: {response}")

        # The message SSH_MSG_CHANNEL_CLOSE from server indicates conection must be closed.

        # keys: bytes = self.recv()
        # self.logger.debug(f'Keys: {repr(keys)}')

    def send_ssh_packet(self, payload: bytes) -> None:
        # 4 (packet_length) + 1 (padding_length) + len(payload) + len(random padding) % 8 = 0
        # packet_length - padding_length - 1 = n1
        n1 = len(payload)
        k = 0 # Can vary this to thwart traffic analysis
        padding_length = 3 + (8 - (n1 % 8)) + 8 * k
        packet_length = n1 + padding_length + 1
        self.packet_logger.debug(f'packet_length: {packet_length}, padding_length: {padding_length}')
        self.packet_logger.debug(f'client >> server {repr(payload)}')
        self.send(packet_length.to_bytes(4, 'big'))
        self.send(padding_length.to_bytes(1, 'big'))
        self.send(payload)
        self.send(os.urandom(padding_length))
        if self.mac_algorthm is not None:
            mac = self.create_hmac(self.mac_key, payload)
            self.logger.debug(f'MAC: {repr(mac)}')
            self.send(mac)


    def send_ssh_packet2(self, payload: bytes) -> None:
        """
        Each packet is in the following format:
        uint32    packet_length
        byte      padding_length
        byte[n1]  payload; n1 = packet_length - padding_length - 1
        byte[n2]  random padding; n2 = padding_length
        byte[m]   mac (Message Authentication Code - MAC); m = mac_length

        packet_length
         The length of the packet in bytes, not including 'mac' or the
         'packet_length' field itself.

        padding_length
         Length of 'random padding' (bytes).

        payload
         The useful contents of the packet.  If compression has been
         negotiated, this field is compressed.  Initially, compression
         MUST be "none".

        random padding
         Arbitrary-length padding, such that the total length of
         (packet_length || padding_length || payload || random padding)
         is a multiple of the cipher block size or 8, whichever is
         larger.  There MUST be at least four bytes of padding.  The
         padding SHOULD consist of random bytes.  The maximum amount of
         padding is 255 bytes.

        mac
         Message Authentication Code.  If message authentication has
         been negotiated, this field contains the MAC bytes.  Initially,
         the MAC algorithm MUST be "none".

        Note that the length of the concatenation of 'packet_length',
        'padding_length', 'payload', and 'random padding' MUST be a multiple
        of the cipher block size or 8, whichever is larger.  This constraint
        MUST be enforced, even when using stream ciphers.  Note that the
        'packet_length' field is also encrypted, and processing it requires
        special care when sending or receiving packets.  Also note that the
        insertion of variable amounts of 'random padding' may help thwart
        traffic analysis.

        The minimum size of a packet is 16 (or the cipher block size,
        whichever is larger) bytes (plus 'mac').  Implementations SHOULD
        decrypt the length after receiving the first 8 (or cipher block size,
        whichever is larger) bytes of a packet.
        """

        packet_length: int = len(payload) + 1
        padding_length: int = 16 - (packet_length % 16)
        self.packet_logger.debug(f'packet_length: {packet_length}, padding_length: {padding_length}')
        self.packet_logger.debug(f'client >> server {repr(payload)}')
        self.send(packet_length.to_bytes(4, 'big'))
        self.send(padding_length.to_bytes(1, 'big'))
        self.send(payload)
        self.send(os.urandom(padding_length))
        if self.mac_algorthm is not None:
            mac = self.create_hmac(self.mac_key, payload)
            self.packet_logger.debug(f'MAC: {repr(mac)}')
            self.send(mac)

    def recv_ssh_packet(self) -> bytes:
        """
        Each packet is in the following format:
        uint32    packet_length
        byte      padding_length
        byte[n1]  payload; n1 = packet_length - padding_length - 1
        byte[n2]  random padding; n2 = padding_length
        byte[m]   mac (Message Authentication Code - MAC); m = mac_length
        """
        packet_length = int.from_bytes(self.recv(4), 'big')
        padding_length = int.from_bytes(self.recv(1), 'big')
        payload = self.recv(packet_length - padding_length - 1)
        random_padding = self.recv(padding_length)
        if self.mac_algorthm is not None:
            mac = self.recv(len(self.mac_key))
            self.packet_logger.debug(f'MAC: {repr(mac)}')
            assert mac == self.create_hmac(self.mac_key, payload), "MAC does not match"
        self.packet_logger.debug(f'client << server {repr(payload)}')
        return payload

    def my_key_exchange(self):
        """ Sends the initial key exchange message to the server with format """
        # 1. Send the initial key exchange message
        local_key = SSHKEXInitPacket(
            kex_algorithms=['diffie-hellman-group14-sha256'],
            server_host_key_algorithms=['rsa-sha2-256'],
            encryption_algorithms_client_to_server=['aes128-ctr'],
            encryption_algorithms_server_to_client=['aes128-ctr'],
            mac_algorithms_client_to_server=['hmac-sha1'],
            mac_algorithms_server_to_client=['hmac-sha1'],
            compression_algorithms_client_to_server=['none'],
            compression_algorithms_server_to_client=['none'],
            languages_client_to_server=[''],
            languages_server_to_client=[''],
            first_kex_packet_follows=False,
            reserved=0
        )
        if self.logger.level <= logging.INFO:
            console.print(f"Local key:", local_key)
        self.send_ssh_packet(local_key.to_bytes())

        # 2. Receive the server's key exchange message
        server_payload = self.recv_ssh_packet()
        remote_key = SSHKEXInitPacket.from_bytes(server_payload)
        if self.logger.level <= logging.INFO:
            console.print(f"Remote key:", remote_key)

        assert local_key.kex_algorithms[0] in remote_key.kex_algorithms, "Server does not support DH key exchange"
        assert remote_key.server_host_key_algorithms[0] in remote_key.server_host_key_algorithms, "Server does not support RSA key exchange"
        assert remote_key.encryption_algorithms_client_to_server[0] in remote_key.encryption_algorithms_client_to_server, "Server does not support AES encryption"
        assert remote_key.encryption_algorithms_server_to_client[0] in remote_key.encryption_algorithms_server_to_client, "Server does not support AES encryption"
        assert remote_key.mac_algorithms_client_to_server[0] in remote_key.mac_algorithms_client_to_server, "Server does not support HMAC-SHA1"
        assert remote_key.mac_algorithms_server_to_client[0] in remote_key.mac_algorithms_server_to_client, "Server does not support HMAC-SHA1"
        assert remote_key.compression_algorithms_client_to_server[0] in remote_key.compression_algorithms_client_to_server, "Server does not support not using compression"
        assert remote_key.compression_algorithms_server_to_client[0] in remote_key.compression_algorithms_server_to_client, "Server does not support not using compression"
        # 3. Perform the DH key exchange
        derived_key = self.perform_dh_key_exchange()

        # return derived_key

    @staticmethod
    def encode_mpint(n: int) -> bytes:
        """
        Converts an integer to a SSH MPInt

        Represents multiple precision integers in two's complement format,
        stored as a string, 8 bits per byte, MSB first.  Negative numbers
        have the value 1 as the most significant bit of the first byte of
        the data partition.  If the most significant bit would be set for
        a positive number, the number MUST be preceded by a zero byte.
        Unnecessary leading bytes with the value 0 or 255 MUST NOT be
        included.  The value zero MUST be stored as a string with zero
        bytes of data.

        By convention, a number that is used in modular computations in
        Z_n SHOULD be represented in the range 0 <= x < n.
        """

        if n == 0:
            return b'\x00\x00\x00\x00'

            # Handle positive numbers
        if n > 0:
            abs_bytes = n.to_bytes((n.bit_length() + 7) // 8, byteorder='big', signed=False)
            if abs_bytes[0] & 0x80:  # If the highest bit is set, prepend a 0x00 byte
                abs_bytes = b'\x00' + abs_bytes
        else:
            raise NotImplementedError("Negative numbers not implemented")

        length_prefix = len(abs_bytes).to_bytes(4, byteorder='big')
        return length_prefix + abs_bytes

    @staticmethod
    def decode_mpint(data: bytes) -> int:
        """
        Converts an SSH MPInt to an integer
        """
        length = int.from_bytes(data[:4], byteorder='big')
        return int.from_bytes(data[4:4 + length], byteorder='big')


    def perform_dh_key_exchange(self):
        """Run diffie-hellman-group14-sha256 kex"""
        server_public_key_bytes = self.recv_ssh_packet()
        return
        # 1. Generate the DH parameters
        parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
        private_key = parameters.generate_private_key()
        public_key = private_key.public_key()

        # 2. Send the public key to the server
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        e = int.from_bytes(public_key_bytes, 'big')

        myio = io.BytesIO()
        myio.write(bytes([SSHConstants.SSH_MSG_KEXDH_INIT]))
        myio.write(self.encode_mpint(e))
        self.send_ssh_packet(myio.getvalue())

        # 3. Receive the server's public key

        # server_public_key = serialization.load_pem_public_key(server_public_key_bytes, backend=default_backend())
        #
        # # 4. Derive the shared key
        # shared_key = private_key.exchange(server_public_key)
        # derived_key = HKDF(
        #     algorithm=hashes.SHA256(),
        #     length=32,
        #     salt=None,
        #     info=b'ssh',
        #     backend=default_backend()
        # ).derive(shared_key)
        #
        # return derived_key

    def _exchange_versions(self) -> None:
        """Exchange SSH versions with the remote server (Step 1)"""
        self.logger.debug(f'My SSH version: {repr(self.my_ssh_version)}')
        self.send_str(str(self.my_ssh_version))
        # Note, according to RFC 4253, the server could send extra lines of utf-8 text ended by crlf not starting in SSH-, which can be ignored
        remote_version: str = self.recv_str()
        self.remote_ssh_version = SSHVersion.from_string(remote_version)
        self.logger.debug(f'Remote SSH version: {repr(self.remote_ssh_version)}')

    def send_str(self, message: str) -> None:
        self.send(message.encode('utf-8'))

    def send(self, message: bytes) -> None:
        self.bytes_logger.debug(f'client >> remote: {repr(message)}')
        self.s.send(message)

    def close(self) -> None:
        self.s.close()

    def recv(self, n_bytes: int | None = None) -> bytes:
        recv = self.s.recv(n_bytes if n_bytes is not None else self.block_size)
        self.bytes_logger.debug(f'client << remote: {repr(recv)}')
        return recv

    def recv_str(self) -> str:
        data: bytes = self.recv()
        try:
            return data.decode('utf-8')
        except UnicodeDecodeError as e:
            self.logger.error(f'Error decoding: {repr(data)}', exc_info=e)
            sys.exit(-1)

    def __del__(self):
        if self.s:
            self.s.close()


def test_mpint():
    """
         value (hex)        representation (hex)
     -----------        --------------------
     0                  00 00 00 00
     9a378f9b2e332a7    00 00 00 08 09 a3 78 f9 b2 e3 32 a7
     80                 00 00 00 02 00 80
     -1234              00 00 00 02 ed cc
     -deadbeef          00 00 00 05 ff 21 52 41 11
    """
    assert SSHClient.encode_mpint(0) == b'\x00\x00\x00\x00'
    assert SSHClient.encode_mpint(0x9a378f9b2e332a7) == b'\x00\x00\x00\x08\x09\xa3\x78\xf9\xb2\xe3\x32\xa7'
    assert SSHClient.encode_mpint(0x80) == b'\x00\x00\x00\x02\x00\x80'

    assert SSHClient.decode_mpint(b'\x00\x00\x00\x00') == 0
    assert SSHClient.decode_mpint(b'\x00\x00\x00\x08\x09\xa3\x78\xf9\xb2\xe3\x32\xa7') == 0x9a378f9b2e332a7
    assert SSHClient.decode_mpint(b'\x00\x00\x00\x02\x00\x80') == 0x80

def write_byt(byt: io.BytesIO, ssh: SSHClient):
    def w(b: bytes):
        ssh.bytes_logger.info(f'Send: {repr(b)}')
        byt.write(b)
    return w

def read_byt(byt: io.BytesIO, ssh: SSHClient):
    def r(n: int = 1024) -> bytes:
        read = byt.read(n)
        ssh.bytes_logger.info(f'Recv[{n}]: {repr(read)}')
        return read
    return r

def test_ssh_packet():
    ssh = SSHClient(host='localhost', port=8022)
    for message in [
        "Hello World",
        "This is a test" * 100,
        "\x1b[33m125386721903 gernge gA\x1b[0m"
    ]:
        byt = io.BytesIO()
        ssh.send = write_byt(byt, ssh)
        ssh.send_ssh_packet(message.encode('utf-8'))
        byt = io.BytesIO(byt.getvalue())
        ssh.recv = read_byt(byt, ssh)
        value = ssh.recv_ssh_packet().decode('utf-8')
        assert message == value, f"{message} {value}"

def main():
    ssh = SSHClient(host='localhost', port=8022)
    ssh.connect()

if __name__ == '__main__':
    # test_mpint()
    # test_ssh_packet()
    main()
