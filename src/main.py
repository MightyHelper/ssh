import hashlib
import hmac
import io
import logging
from random import randint

import rich.table
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, AEADEncryptionContext, AEADDecryptionContext, modes
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from rich.console import Console
from rich.logging import RichHandler

from src.constants import SSHConstants
from src.kex_init_packet import SSHKEXInitPacket
from src.ssh_packet import SSHPacket
from src.ssh_socket_wrapper import SSHSocketWrapper
from src.version import SSHVersion

LENGTH = 257

KEY_SIZE = 2048

console = Console()
logging.basicConfig(
    level='DEBUG',
    format='%(name)s: %(message)s',
    datefmt='[%X]',
    handlers=[RichHandler(rich_tracebacks=True, console=console)],
)


def SSHMessageServiceRequestPacket(service_name: bytes) -> SSHPacket:
    return SSHPacket.create_from_bytes(SSHConstants.SSH_MSG_SERVICE_REQUEST.to_bytes() + service_name)


def SSHKexdhInitPacket(public_key_bytes: bytes) -> SSHPacket:
    myio = io.BytesIO()
    myio.write(bytes([SSHConstants.SSH_MSG_KEXDH_INIT]))
    myio.write(b'\x00\x00\x01\x01')
    myio.write(public_key_bytes)
    return SSHPacket.create_from_bytes(myio.getvalue())


def SSHNewKeysPacket() -> SSHPacket:
    return SSHPacket.create_from_bytes(SSHConstants.SSH_MSG_NEWKEYS.to_bytes())


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
        return b'\x00' + self.e.to_bytes(LENGTH - 1, 'big')

    @property
    def k_bytes(self) -> bytes:
        return self.k.to_bytes(LENGTH - 1, 'big')

    @property
    def f_bytes(self) -> bytes:
        return self.f.to_bytes(LENGTH - 1, 'big')

    @property
    def _buffer(self) -> bytes:
        parts = [
            (len(self.v_c) - 1).to_bytes(4, byteorder='big'),
            self.v_c[:-1],
            (len(self.v_s)).to_bytes(4, byteorder='big'),
            self.v_s,
            (len(self.i_c)).to_bytes(4, byteorder='big'),
            self.i_c,
            (len(self.i_s)).to_bytes(4, byteorder='big'),
            self.i_s,
            (len(self.k_s)).to_bytes(4, byteorder='big'),
            self.k_s,
            (len(self.e_bytes)).to_bytes(4, byteorder='big'),
            self.e_bytes,
            (len(self.f_bytes)).to_bytes(4, byteorder='big'),
            self.f_bytes,
            (len(self.k_bytes)).to_bytes(4, byteorder='big'),
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
        return hashlib.sha256(SSHClient.encode_mpint(self.k) + self.h_bytes + b'A' + self.session_id).digest()

    @property
    def iv0_s2c(self) -> bytes:
        """Initial IV server to client"""
        return hashlib.sha256(SSHClient.encode_mpint(self.k) + self.h_bytes + b'B' + self.session_id).digest()

    @property
    def key_c2s(self) -> bytes:
        """Encryption key client to server"""
        return hashlib.sha256(SSHClient.encode_mpint(self.k) + self.h_bytes + b'C' + self.session_id).digest()

    @property
    def key_s2c(self) -> bytes:
        """Encryption key server to client"""
        return hashlib.sha256(SSHClient.encode_mpint(self.k) + self.h_bytes + b'D' + self.session_id).digest()

    @property
    def mac_c2s(self) -> bytes:
        """MAC key client to server"""
        return hashlib.sha256(SSHClient.encode_mpint(self.k) + self.h_bytes + b'E' + self.session_id).digest()

    @property
    def mac_s2c(self) -> bytes:
        """MAC key server to client"""
        return hashlib.sha256(SSHClient.encode_mpint(self.k) + self.h_bytes + b'F' + self.session_id).digest()


class SSHClient:
    my_ssh_version: SSHVersion = SSHVersion.from_string('SSH-2.0-LeoFedeSsh0.1 Un trabajo para un tp\r\n')
    """The SSH version string for the client"""
    remote_ssh_version: SSHVersion = None
    """The SSH version string for the server"""
    s: SSHSocketWrapper | None
    """The socket connection to the server"""

    exchange_parameters: ExchangeParameters
    """The parameters for the key exchange"""

    cipher: Cipher
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

    def create_hmac(self, key: bytes, message: bytes) -> bytes:
        return hmac.new(key, message, hashlib.sha1).digest()

    def mac_applicator(self, data: bytes) -> bytes:
        sequence_ored_with_data = SSHPacket.local_to_remote_sequence_number.to_bytes(4, 'big') + data
        return self.create_hmac(self.exchange_parameters.k_bytes, sequence_ored_with_data)

    def connect(self):
        self.s = SSHSocketWrapper(self.host, self.port)
        self.logger.info('Connected to server')
        self._exchange_versions()
        self.my_key_exchange()
        self.request_service('ssh-userauth')

    def request_service(self, service_name: str) -> None:
        self.s.send_packet(SSHMessageServiceRequestPacket(service_name.encode('utf-8')))
        response = self.s.recv_packet()
        self.logger.info(f'Response: {response}')
        assert response == SSHConstants.SSH_MSG_SERVICE_ACCEPT.to_bytes() + service_name.encode(
            'utf-8'), "Service not accepted"

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
        self.exchange_parameters.i_c = local_key.to_bytes()
        self.s.send_packet(SSHPacket.create_from_bytes(self.exchange_parameters.i_c))

        # 2. Receive the server's key exchange message
        self.exchange_parameters.i_s = self.s.recv_packet().payload
        remote_key = SSHKEXInitPacket.from_bytes(self.exchange_parameters.i_s)
        if self.logger.level <= logging.INFO:
            console.print(f"Remote key:", remote_key)

        remote_key.assert_supports_algorithms(local_key)
        # 3. Perform the DH key exchange
        self.perform_dh_key_exchange()

    @staticmethod
    def encode_mpint(n: int) -> bytes:
        if n == 0:
            return b'\x00\x00\x00\x00'
        if n <= 0:
            raise NotImplementedError("Negative numbers not implemented")
        abs_bytes = n.to_bytes((n.bit_length() + 7) // 8, byteorder='big', signed=False)
        if abs_bytes[0] & 0x80:  # If the highest bit is set, prepend a 0x00 byte
            abs_bytes = b'\x00' + abs_bytes
        length_prefix = len(abs_bytes).to_bytes(4, byteorder='big')
        return length_prefix + abs_bytes

    @staticmethod
    def decode_mpint(data: bytes) -> int:
        """
        Converts an SSH MPInt to an integer
        """
        length = int.from_bytes(data[:4], byteorder='big')
        return int.from_bytes(data[4:4 + length], byteorder='big')

    def request_mpint(self, source: io.BytesIO) -> int:
        length = int.from_bytes(source.read(4), byteorder='big')
        self.logger.debug(f'Length: {length} bytes')
        read = source.read(length)
        self.logger.debug(f'And read: {len(read)} bytes')
        return int.from_bytes(read, byteorder='big')

    def request_str(self, source: io.BytesIO) -> bytes:
        length = int.from_bytes(source.read(4), byteorder='big')
        self.logger.debug(f'Length: {length} bytes')
        read = source.read(length)
        self.logger.debug(f'And read: {len(read)} bytes')
        return read

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
        self.s.mac_calculator = self.mac_applicator

    def expect_new_keys(self):
        assert self.s.recv_packet().payload == SSHConstants.SSH_MSG_NEWKEYS.to_bytes(), "Server did not send new keys"
        # Send the new keys message
        self.s.send_packet(SSHNewKeysPacket())
        self.logger.info("Habemus New Keys!")

    def derive_shared_key(self, server_f_value):
        shared_k = pow(server_f_value, self.exchange_parameters.x, self.exchange_parameters.p)

        self.exchange_parameters.k = shared_k
        self.exchange_parameters.session_id = self.exchange_parameters.h_bytes
        self.logger.info(f'Derived key: {self.exchange_parameters.k}\n{hexdump(self.exchange_parameters.k)}')
        self.logger.info(f'Buffer: {self.exchange_parameters._buffer}\n{hexdump(self.exchange_parameters._buffer)}')
        self.logger.info(f'hash: {self.exchange_parameters.h_bytes}\n{hexdump(self.exchange_parameters.h_bytes)}')
        self.logger.info(f'[A] IV0 C2S: {self.exchange_parameters.iv0_c2s}\n{hexdump(self.exchange_parameters.iv0_c2s)}')
        self.logger.info(f'[B] IV0 S2C: {self.exchange_parameters.iv0_s2c}\n{hexdump(self.exchange_parameters.iv0_s2c)}')
        self.logger.info(f'[C] Key C2S: {self.exchange_parameters.key_c2s}\n{hexdump(self.exchange_parameters.key_c2s)}')
        self.logger.info(f'[D] Key S2C: {self.exchange_parameters.key_s2c}\n{hexdump(self.exchange_parameters.key_s2c)}')
        self.cipher_c2s = Cipher(AES(self.exchange_parameters.key_c2s[16:]),
                                 modes.CTR(self.exchange_parameters.iv0_c2s[16:]), default_backend())
        self.cipher_s2c = Cipher(AES(self.exchange_parameters.key_s2c[16:]),
                                 modes.CTR(self.exchange_parameters.iv0_s2c[16:]), default_backend())
        self.encryptor = self.cipher_c2s.encryptor()
        self.decryptor = self.cipher_s2c.decryptor()

    def receive_remote_keys(self):
        self.logger.info(f'waiting for server response')
        # 3. Receive the server's public key
        server_payload = self.s.recv_packet().payload
        parse_server_payload = io.BytesIO(server_payload)
        assert parse_server_payload.read(1) == bytes([SSHConstants.SSH_MSG_KEXDH_REPLY])

        self.exchange_parameters.k_s = self.parse_server_public_key(parse_server_payload)

        self.exchange_parameters.f = self.request_mpint(parse_server_payload)
        self.logger.info(f'Server f value:\n{hexdump(self.exchange_parameters.f)}')
        server_signature = self.parse_server_signature(parse_server_payload)
        # The server signature is used to verify the server's public key authenticity
        return self.exchange_parameters.f

    def generate_local_keys(self):
        self.logger.info(f'Generating keys...')
        self.exchange_parameters.p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
        self.exchange_parameters.g = 2
        self.exchange_parameters.q = 2 ** 256 - 1
        self.exchange_parameters.x = randint(2, self.exchange_parameters.q)
        self.exchange_parameters.e = pow(self.exchange_parameters.g, self.exchange_parameters.x,
                                         self.exchange_parameters.p)
        self.logger.info(f'P: {self.exchange_parameters.p}\n{hexdump(self.exchange_parameters.p)}')
        self.logger.info(f'G: {self.exchange_parameters.g}\n{hexdump(self.exchange_parameters.g)}')
        self.logger.info(f'X: {self.exchange_parameters.x}\n{hexdump(self.exchange_parameters.x)}')
        self.logger.info(f'E: {self.exchange_parameters.e}\n{hexdump(self.exchange_parameters.e)}')
        # Add sign bit
        return self.exchange_parameters.e_bytes

    def parse_server_signature(self, parse_server_payload):
        server_signature = parse_server_payload.read()
        server_signature_b = io.BytesIO(server_signature)
        hash_h = self.request_str(server_signature_b)
        hash_h_b = io.BytesIO(hash_h)
        algorithm = self.request_str(hash_h_b)
        signature = self.request_str(hash_h_b)
        table = rich.table.Table(title="Server Signature", highlight=True)
        table.add_column("Field", overflow="fold")
        table.add_column("Value", overflow="fold")
        table.add_row("Algorithm", repr(algorithm))
        table.add_row("Signature", repr(signature))
        table.add_row("Trailing", repr(hash_h_b.read()))
        console.print(table)
        return server_signature

    def parse_server_public_key(self, parse_server_payload):
        server_public_key = self.request_str(parse_server_payload)
        server_public_key_b = io.BytesIO(server_public_key)
        pk_type = self.request_str(server_public_key_b)
        assert pk_type == b'ssh-rsa'
        e = self.request_mpint(server_public_key_b)
        pk_value = self.request_mpint(server_public_key_b)
        table = rich.table.Table(title="Server Public Key", highlight=True)
        table.add_column("Field", overflow="fold")
        table.add_column("Value", overflow="fold")
        table.add_row("Type", repr(pk_type))
        table.add_row("E", repr(e))
        table.add_row("Value", repr(pk_value))
        table.add_row("Value hexdump", hexdump(pk_value))
        table.add_row("Trailing", repr(server_public_key_b.read()))
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


def hexdump(value: bytes | int) -> str:
    if not isinstance(value, bytes):
        return hexdump(value.to_bytes((value.bit_length() + 7) // 8, byteorder='big'))
    out = ""
    for i in range(0, len(value), 16):
        chunk = value[i:i + 16]
        out += f"{i:08x}: {' '.join(f'{b:02x}' for b in chunk): <48} {''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)}\n"

    return out


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
    assert SSHClient.encode_mpint(
        0x00997731efad72192d895fcd1178720ee80cafa37481dc45920222da584c2d42bec79cd69a0a0424ae0da5bdf8239a26c5eb7d7c890f5e1c3413d0e908c815096d9df13fe1040c748ede35d17a748bcf77d031fc8d6bae2a6920af9482cd79841fb92aa63ca053ea9d01e657d6d88d5326805ad1c8486c7b85090286e53a456ba5b842e20a70b4295dc62a20a7cfe7ba76faa5c38fc6148e890d4a847592fcd8d2ae089f0604180fd2dd68a86b13b770e0fb0c6c27d56eabf79b25efd3c3ebef7cd9966a6e62533f247d8c520a8892fa36df7747b952bce23b3638ba36b1d245444e8dcd72141b46e9d47570c515fd7b9ea044a118482b4478b966435f5f7bdea1) == b"\x00\x00\x01\x01\x00\x99\x77\x31\xef\xad\x72\x19\x2d\x89\x5f\xcd\x11\x78\x72\x0e" \
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 b"\xe8\x0c\xaf\xa3\x74\x81\xdc\x45\x92\x02\x22\xda\x58\x4c\x2d\x42" \
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 b"\xbe\xc7\x9c\xd6\x9a\x0a\x04\x24\xae\x0d\xa5\xbd\xf8\x23\x9a\x26" \
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 b"\xc5\xeb\x7d\x7c\x89\x0f\x5e\x1c\x34\x13\xd0\xe9\x08\xc8\x15\x09" \
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 b"\x6d\x9d\xf1\x3f\xe1\x04\x0c\x74\x8e\xde\x35\xd1\x7a\x74\x8b\xcf" \
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 b"\x77\xd0\x31\xfc\x8d\x6b\xae\x2a\x69\x20\xaf\x94\x82\xcd\x79\x84" \
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 b"\x1f\xb9\x2a\xa6\x3c\xa0\x53\xea\x9d\x01\xe6\x57\xd6\xd8\x8d\x53" \
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 b"\x26\x80\x5a\xd1\xc8\x48\x6c\x7b\x85\x09\x02\x86\xe5\x3a\x45\x6b" \
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 b"\xa5\xb8\x42\xe2\x0a\x70\xb4\x29\x5d\xc6\x2a\x20\xa7\xcf\xe7\xba" \
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 b"\x76\xfa\xa5\xc3\x8f\xc6\x14\x8e\x89\x0d\x4a\x84\x75\x92\xfc\xd8" \
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 b"\xd2\xae\x08\x9f\x06\x04\x18\x0f\xd2\xdd\x68\xa8\x6b\x13\xb7\x70" \
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 b"\xe0\xfb\x0c\x6c\x27\xd5\x6e\xab\xf7\x9b\x25\xef\xd3\xc3\xeb\xef" \
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 b"\x7c\xd9\x96\x6a\x6e\x62\x53\x3f\x24\x7d\x8c\x52\x0a\x88\x92\xfa" \
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 b"\x36\xdf\x77\x47\xb9\x52\xbc\xe2\x3b\x36\x38\xba\x36\xb1\xd2\x45" \
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 b"\x44\x4e\x8d\xcd\x72\x14\x1b\x46\xe9\xd4\x75\x70\xc5\x15\xfd\x7b" \
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 b"\x9e\xa0\x44\xa1\x18\x48\x2b\x44\x78\xb9\x66\x43\x5f\x5f\x7b\xde\xa1"

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
    ssh = SSHClient(host='localhost', port=8222)
    for message in [
        "Hello World",
        "This is a test" * 100,
        "\x1b[33m125386721903 gernge gA\x1b[0m"
    ]:
        byt = io.BytesIO()
        ssh.send = write_byt(byt, ssh)
        ssh.s.send_packet(SSHPacket.create_from_bytes(message.encode('utf-8')))
        byt = io.BytesIO(byt.getvalue())
        ssh.recv = read_byt(byt, ssh)
        value = ssh.s.recv_packet().payload.decode('utf-8')
        assert message == value, f"{message} {value}"


def main():
    ssh = SSHClient(host='localhost', port=8222)
    ssh.connect()


if __name__ == '__main__':
    # test_mpint()
    # test_ssh_packet()
    main()
