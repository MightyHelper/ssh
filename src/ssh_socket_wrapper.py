import logging
import socket
import sys
from typing import ClassVar, Callable

from cryptography.hazmat.primitives.ciphers import AEADEncryptionContext, AEADDecryptionContext, Cipher

from src.bytes_read_writable import BytesReadWritable
from src.ssh_packet import SSHPacket


class SSHSocketWrapper(BytesReadWritable):
    logger: ClassVar[logging.Logger] = logging.getLogger("SSHSocketWrapper")
    do_encryption: bool = False
    encryptor: AEADEncryptionContext | None = None
    decryptor: AEADDecryptionContext | None = None
    cipher: Cipher | None = None
    mac_validator_s2c: Callable[[bytes, bytes], bool] | None = None
    mac_applicator_c2s: Callable[[bytes], bytes] | None = None

    def __init__(self, host: str, port: int):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((host, port))
        self.logger.setLevel(logging.ERROR)

    def send(self, message: bytes) -> None:
        self.logger.debug(f'c >> s [{len(message)}]: {message.hex(" ", bytes_per_sep=-16)}')
        self.s.send(message)

    def recv(self, n_bytes: int | None = None) -> bytes:
        if n_bytes and n_bytes < 1:
            raise ValueError(f'Invalid number of bytes to receive: {n_bytes}')
        recv = self.s.recv(n_bytes if n_bytes is not None else 35000)
        self.logger.debug(f's >> c [{len(recv)}]: {recv.hex(" ", bytes_per_sep=-16)}')
        return recv

    def send_packet(self, packet: SSHPacket) -> None:
        if self.do_encryption:
            self.send(packet.to_encrypted_bytes(self.encryptor, self.mac_applicator_c2s))
        else:
            self.send(packet.to_bytes())
        SSHPacket.local_to_remote_sequence_number += 1

    def recv_packet(self) -> SSHPacket:
        if self.do_encryption:
            packet = SSHPacket.request_encrypted(self, self.decryptor, self.mac_validator_s2c)
        else:
            packet = SSHPacket.request(self)
        self.logger.debug(f'Received packet[{SSHPacket.remote_to_local_sequence_number}]: {packet.code}')
        SSHPacket.remote_to_local_sequence_number += 1
        return packet

    def send_str(self, message: str) -> None:
        self.send(message.encode('utf-8'))

    def recv_str(self) -> str:
        data: bytes = self.recv()
        try:
            return data.decode('utf-8')
        except UnicodeDecodeError as e:
            self.logger.error(f'Error decoding: {repr(data)}', exc_info=e)
            sys.exit(-1)

    def close(self) -> None:
        self.s.close()

    def __del__(self):
        if self.s:
            self.s.close()
