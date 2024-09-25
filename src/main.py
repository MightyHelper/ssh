import hashlib
import hmac
import io
import logging
import os
import socket
import sys
from dataclasses import dataclass
from typing import Self

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.ciphers import Cipher, AEADEncryptionContext, AEADDecryptionContext, modes
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from rich.console import Console
from rich.logging import RichHandler

from src.constants import SSHConstants
from src.kex_init_packet import SSHKEXInitPacket
from src.version import SSHVersion

console = Console()
logging.basicConfig(
    level='DEBUG',
    format='%(name)s[%(levelname)s]: %(message)s',
    datefmt='[%X]',
    handlers=[RichHandler(rich_tracebacks=True, console=console)],
)

@dataclass
class SSHPacket:
    length: int
    padding_length: int
    payload: bytes
    random_padding: bytes
    mac: bytes = bytes()

    @classmethod
    def create_from_bytes(cls, payload: bytes) -> Self:
        n1 = len(payload)
        k = 0  # Can vary this to thwart traffic analysis
        padding_length = 3 + (8 - (n1 % 8)) + 8 * k
        packet_length = n1 + padding_length + 1
        return cls(
            length=packet_length,
            padding_length=padding_length,
            payload=payload,
            random_padding=os.urandom(padding_length),
        )

    @classmethod
    def request(cls, source: io.BufferedIOBase) -> Self:
        length = int.from_bytes(source.read(4), 'big')
        padding_length = int.from_bytes(source.read(1), 'big')
        payload = source.read(length - padding_length - 1)
        random_padding = source.read(padding_length)
        return cls(
            length=length,
            padding_length=padding_length,
            payload=payload,
            random_padding=random_padding,
        )


    def set_mac(self, derived_key: bytes) -> bytes:
        self.mac = hmac.new(derived_key, self.payload, hashlib.sha1).digest()
        return self.mac



class SSHClient:
    my_ssh_version: SSHVersion = SSHVersion.from_string('SSH-2.0-LeoFedeSsh0.1 Un trabajo para un tp\r\n')
    remote_ssh_version: SSHVersion = None
    logger: logging.Logger = logging.getLogger("SSHClient")
    bytes_logger: logging.Logger = logging.getLogger("SSH_bytes")
    packet_logger: logging.Logger = logging.getLogger("SSH_packt")
    mac_algorthm: str | None = None
    derived_key: bytes | None = None
    s: socket.socket | None
    parameters: dh.DHParameters
    private_key: dh.DHPrivateKey
    public_key: dh.DHPublicKey
    server_public_key: dh.DHPublicKey
    derived_key: bytes
    cipher: Cipher
    encryptor: AEADEncryptionContext
    decryptor: AEADDecryptionContext

    def __init__(self, host, port):
        self.s = None
        self.host = host
        self.port = port
        self.block_size = 35000
        # self.bytes_logger.setLevel(logging.DEBUG)

    def compute_session_id(self, client_version: bytes, server_version: bytes, kex_init_client: bytes,
                           kex_init_server: bytes,
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
        self.my_key_exchange()
        self.request_service('ssh-userauth')

    def request_service(self, service_name: str) -> None:
        self.send_encrypted_ssh_packet(SSHConstants.SSH_MSG_SERVICE_REQUEST.to_bytes() + service_name.encode('utf-8'))
        response = self.recv_ssh_packet()
        self.logger.info(f'Response: {response}')
        assert response == SSHConstants.SSH_MSG_SERVICE_ACCEPT.to_bytes() + service_name.encode(
            'utf-8'), "Service not accepted"

    def send_encrypted_ssh_packet(self, payload: bytes) -> None:
        # 4 (packet_length) + 1 (padding_length) + len(payload) + len(random padding) % 8 = 0
        # packet_length - padding_length - 1 = n1
        n1 = len(payload)
        k = 0  # Can vary this to thwart traffic analysis
        padding_length = 3 + (8 - (n1 % 8)) + 8 * k
        packet_length = n1 + padding_length + 1
        self.packet_logger.debug(f'packet_length: {packet_length}, padding_length: {padding_length}')
        self.packet_logger.debug(f'client >> server {repr(payload)}')
        # Encrypt the length and padding
        encrypted_length = self.encrypt(packet_length.to_bytes(4, 'big'))
        encrypted_padding = self.encrypt(padding_length.to_bytes(1, 'big'))
        self.send(encrypted_length)
        self.send(encrypted_padding)
        # Encrypt the payload
        encrypted_payload = self.encrypt(payload)
        self.send(encrypted_payload)
        # Encrypt the random padding
        random_padding = os.urandom(padding_length)
        encrypted_random_padding = self.encrypt(random_padding)
        self.send(encrypted_random_padding)
        if self.mac_algorthm is not None:
            mac = self.create_hmac(self.derived_key, payload)
            self.logger.debug(f'MAC: {repr(mac)}')
            self.send(mac)

    def recv_encrypted_ssh_packet(self) -> bytes:
        """
        Each packet is in the following format:
        uint32    packet_length
        byte      padding_length
        byte[n1]  payload; n1 = packet_length - padding_length - 1
        byte[n2]  random padding; n2 = padding_length
        byte[m]   mac (Message Authentication Code - MAC); m = mac_length
        """
        # Decrypt the length
        encrypted_length = self.recv(4)
        length = int.from_bytes(self.decrypt(encrypted_length), 'big')
        # Decrypt the padding
        encrypted_padding = self.recv(1)
        padding_length = int.from_bytes(self.decrypt(encrypted_padding), 'big')
        # Decrypt the payload
        payload = self.recv(length - padding_length - 1)
        # Decrypt the random padding
        random_padding = self.recv(padding_length)
        # Verify the MAC
        if self.mac_algorthm is not None:
            mac = self.recv(len(self.derived_key))
            self.packet_logger.debug(f'MAC: {repr(mac)}')
            expected_mac = self.create_hmac(self.derived_key, payload)
            assert mac == expected_mac, f"MAC does not match {mac} vs {expected_mac}| {self.derived_key}"
        self.packet_logger.debug(f'client << server {repr(payload)}')
        return payload




    def send_ssh_packet(self, payload: bytes) -> None:
        # 4 (packet_length) + 1 (padding_length) + len(payload) + len(random padding) % 8 = 0
        # packet_length - padding_length - 1 = n1
        n1 = len(payload)
        k = 0  # Can vary this to thwart traffic analysis
        padding_length = 3 + (8 - (n1 % 8)) + 8 * k
        packet_length = n1 + padding_length + 1
        self.packet_logger.debug(f'packet_length: {packet_length}, padding_length: {padding_length}')
        self.packet_logger.debug(f'client >> server {repr(payload)}')
        self.send(packet_length.to_bytes(4, 'big'))
        self.send(padding_length.to_bytes(1, 'big'))
        self.send(payload)
        self.send(os.urandom(padding_length))
        if self.mac_algorthm is not None:
            mac = self.create_hmac(self.derived_key, payload)
            self.logger.debug(f'MAC: {repr(mac)}')
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
        if packet_length > 100000:
            self.logger.warning(f'Packet is reported very long: {packet_length}. Probably a decoding error')
        padding_length = int.from_bytes(self.recv(1), 'big')
        payload = self.recv(packet_length - padding_length - 1)
        random_padding = self.recv(padding_length)
        if self.mac_algorthm is not None:
            mac = self.recv(len(self.derived_key))
            self.packet_logger.debug(f'MAC: {repr(mac)}')
            expected_mac = self.create_hmac(self.derived_key, payload)
            assert mac == expected_mac, f"MAC does not match {mac} vs {expected_mac}| {self.derived_key}"
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

        self.assert_server_supports_algorithms(local_key, remote_key)
        # 3. Perform the DH key exchange
        self.perform_dh_key_exchange()

    def assert_server_supports_algorithms(self, local_key, remote_key):
        assert local_key.kex_algorithms[0] in remote_key.kex_algorithms, "Server does not support DH key exchange"
        assert remote_key.server_host_key_algorithms[
                   0] in remote_key.server_host_key_algorithms, "Server does not support RSA key exchange"
        assert remote_key.encryption_algorithms_client_to_server[
                   0] in remote_key.encryption_algorithms_client_to_server, "Server does not support AES encryption"
        assert remote_key.encryption_algorithms_server_to_client[
                   0] in remote_key.encryption_algorithms_server_to_client, "Server does not support AES encryption"
        assert remote_key.mac_algorithms_client_to_server[
                   0] in remote_key.mac_algorithms_client_to_server, "Server does not support HMAC-SHA1"
        assert remote_key.mac_algorithms_server_to_client[
                   0] in remote_key.mac_algorithms_server_to_client, "Server does not support HMAC-SHA1"
        assert remote_key.compression_algorithms_client_to_server[
                   0] in remote_key.compression_algorithms_client_to_server, "Server does not support not using compression"
        assert remote_key.compression_algorithms_server_to_client[
                   0] in remote_key.compression_algorithms_server_to_client, "Server does not support not using compression"

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

    def perform_dh_key_exchange(self):
        """Run diffie-hellman-group14-sha256 kex"""
        public_key_bytes = self.generate_local_keys()
        self.send_local_keys(public_key_bytes)
        server_public_key = self.receive_remote_keys()
        self.expect_new_keys()
        self.derive_shared_key(server_public_key)

    def expect_new_keys(self):
        hopefully_new_keys = self.recv_ssh_packet()
        self.logger.info(f'New keys: {hopefully_new_keys}')
        assert hopefully_new_keys == SSHConstants.SSH_MSG_NEWKEYS.to_bytes(), "Server did not send new keys"

    def derive_shared_key(self, server_public_key):
        shared_key = self.private_key.exchange(server_public_key)
        self.derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'ssh',
            backend=default_backend()
        ).derive(shared_key)
        nonce = os.urandom(16)
        self.cipher = Cipher(AES(self.derived_key), modes.CTR(nonce), default_backend())
        self.encryptor = self.cipher.encryptor()
        self.decryptor = self.cipher.decryptor()
        self.mac_algorthm = 'hmac-sha1'
        self.logger.info(f'Derived key: {self.derived_key}')

    def receive_remote_keys(self):
        self.logger.info(f'waiting for server response')
        # 3. Receive the server's public key
        server_payload = self.recv_ssh_packet()
        parse_server_payload = io.BytesIO(server_payload)
        kexdh_reply = parse_server_payload.read(1)
        assert kexdh_reply == bytes([SSHConstants.SSH_MSG_KEXDH_REPLY])
        server_public_key = parse_server_payload.read(257)
        self.logger.info(f'Server public key: {server_public_key}')
        server_public_key = dh.DHPublicNumbers(
            SSHClient.decode_mpint(server_public_key),
            self.parameters.parameter_numbers()
        ).public_key(default_backend())
        self.server_public_key = server_public_key
        self.logger.info(f'Server public key: {server_public_key} {server_public_key.parameters()}')
        return server_public_key

    def send_local_keys(self, public_key_bytes):
        myio = io.BytesIO()
        myio.write(bytes([SSHConstants.SSH_MSG_KEXDH_INIT]))
        myio.write(b'\x00\x00\x01\x01')
        myio.write(public_key_bytes)
        self.send_ssh_packet(myio.getvalue())
        self.logger.info(f'Sent SSH_MSG_KEXDH_INIT')

    def generate_local_keys(self):
        self.logger.info(f'Generating keys...')
        self.parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
        self.private_key = self.parameters.generate_private_key()
        self.public_key = self.private_key.public_key()
        self.logger.info(f'Public key: {self.public_key} {self.public_key.parameters()}')
        # 2. Send the public key to the server
        public_key_bytes: bytes = self.public_key.public_numbers().y.to_bytes(257)
        self.logger.info(f'Public key bytes: {public_key_bytes}')
        return public_key_bytes

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

    def encrypt(self, param: bytes) -> bytes:
        return self.encryptor.update(param)

    def decrypt(self, param: bytes) -> bytes:
        return self.decryptor.update(param)

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
