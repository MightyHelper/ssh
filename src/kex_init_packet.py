import io
import os
import struct
from dataclasses import dataclass
from typing import Self

from src.constants import SSHConstants


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
        myio.write(os.urandom(16))  # Cookie
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

    def assert_supports_algorithms(self, other_key: Self):
        assert other_key.kex_algorithms[0] in self.kex_algorithms, "Server does not support DH key exchange"
        assert other_key.server_host_key_algorithms[0] in self.server_host_key_algorithms, "Server does not support RSA key exchange"
        assert other_key.encryption_algorithms_client_to_server[0] in self.encryption_algorithms_client_to_server, "Server does not support AES encryption"
        assert other_key.encryption_algorithms_server_to_client[0] in self.encryption_algorithms_server_to_client, "Server does not support AES encryption"
        assert other_key.mac_algorithms_client_to_server[0] in self.mac_algorithms_client_to_server, "Server does not support HMAC-SHA1"
        assert other_key.mac_algorithms_server_to_client[0] in self.mac_algorithms_server_to_client, "Server does not support HMAC-SHA1"
        assert other_key.compression_algorithms_client_to_server[0] in self.compression_algorithms_client_to_server, "Server does not support not using compression"
        assert other_key.compression_algorithms_server_to_client[0] in self.compression_algorithms_server_to_client, "Server does not support not using compression"

