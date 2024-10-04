import io
import logging
import os
from dataclasses import dataclass
from typing import ClassVar, Self, Callable

from cryptography.hazmat.primitives.ciphers import AEADDecryptionContext, AEADEncryptionContext

from src.bytes_io_read_writables import BytesIOReadWritable
from src.bytes_read_writable import BytesReadWritable
from src.common import hexdump
from src.constants import SSHConstants


@dataclass
class SSHPacket:
    """
    Each packet is in the following format on the wire:
    uint32    packet_length
    byte      padding_length
    byte[n1]  payload; n1 = packet_length - padding_length - 1
    byte[n2]  random padding; n2 = padding_length
    byte[m]   mac (Message Authentication Code - MAC); m = mac_length
    """
    length: int
    padding_length: int
    payload: bytes
    random_padding: bytes
    local_to_remote_sequence_number: ClassVar[int] = 0
    remote_to_local_sequence_number: ClassVar[int] = 0
    logger: ClassVar[logging.Logger] = logging.getLogger("SSHPacket")

    @property
    def code(self) -> str:
        try:
            constant = SSHConstants.find_by_value("SSH2_MSG", self.payload[0])
            return f"{constant.value} ({constant.name})"
        except ValueError:
            return f':c'

    @classmethod
    def create_from_bytes(cls, payload: bytes, block_size: int = 8) -> Self:
        n1 = len(payload)
        k = 1  # Can vary this to thwart traffic analysis
        old_padding_length = 3 + (8 - (n1 % 8)) + 8 * k
        b = max(block_size, 8)
        padding_length = 3 + b - ((8 + n1) % b) + b * k
        packet_length = n1 + padding_length + 1
        cls.logger.debug(f'Creating packet with length {packet_length}, padding length {padding_length} ({old_padding_length}), '
                         f'payload length {n1} - {b}')
        return cls(
            length=packet_length,
            padding_length=padding_length,
            payload=payload,
            random_padding=os.urandom(padding_length),
        )

    @classmethod
    def request(cls, source: 'BytesReadWritable') -> Self:
        length = int.from_bytes(source.recv(4), 'big')
        if length > 100000:
            cls.logger.warning(f'Packet is reported very long: {length}. Probably a decoding error')
        padding_length = int.from_bytes(source.recv(1), 'big')
        payload = source.recv(length - padding_length - 1)
        random_padding = source.recv(padding_length)
        return cls(length=length, padding_length=padding_length, payload=payload, random_padding=random_padding)

    @classmethod
    def request_encrypted(cls, source: BytesReadWritable, decryptor: AEADDecryptionContext,
                          mac_applicator: Callable[[bytes], bytes]) -> Self:
        encrypted_length = source.recv(9999999)
        decrypted_length_bytes = decryptor.update(encrypted_length)
        cls.logger.debug(f'Decrypted packet: \n{hexdump(decrypted_length_bytes)}')
        writable = BytesIOReadWritable(io.BytesIO(decrypted_length_bytes))
        packet = cls.request(writable)
        mac = writable.recv(10000)
        calculated_mac = mac_applicator(decrypted_length_bytes[:-20])
        if mac != calculated_mac:
            cls.logger.error(f'MAC mismatch: T:\n{hexdump(mac)} != \nE:\n{hexdump(calculated_mac)}')
        return packet

    def to_bytes(self) -> bytes:
        return (
                self.length.to_bytes(4, 'big')
                + self.padding_length.to_bytes(1, 'big')
                + self.payload
                + self.random_padding
        )

    def to_encrypted_bytes(self, encryptor: AEADEncryptionContext, mac_applicator: Callable[[bytes], bytes]) -> bytes:
        unencrypted_packet = self.to_bytes()
        encrypted_packet = encryptor.update(self.to_bytes())
        # mac = MAC(key, sequence_number || unencrypted_packet)
        mac = mac_applicator(unencrypted_packet)
        return encrypted_packet + mac

    def __str__(self):
        return f'SSHPacket({self.length}, {self.padding_length}, {self.payload}, {self.random_padding}, {self.code})'
