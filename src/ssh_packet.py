import logging
import os
from dataclasses import dataclass
from typing import ClassVar, Self, Callable

from cryptography.hazmat.primitives.ciphers import AEADDecryptionContext, AEADEncryptionContext

from src.bytes_read_writable import BytesReadWritable


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
    def request(cls, source: 'BytesReadWritable') -> Self:
        length = int.from_bytes(source.recv(4), 'big')
        if length > 100000:
            cls.logger.warning(f'Packet is reported very long: {length}. Probably a decoding error')
        padding_length = int.from_bytes(source.recv(1), 'big')
        payload = source.recv(length - padding_length - 1)
        random_padding = source.recv(padding_length)
        return cls(
            length=length,
            padding_length=padding_length,
            payload=payload,
            random_padding=random_padding,
        )

    @classmethod
    def request_encrypted(cls, source: BytesReadWritable, decryptor: AEADDecryptionContext, mac_applicator: Callable[[bytes], bytes]) -> Self:
        encrypted_length = source.recv(4)
        decrypted_length_bytes = decryptor.update(encrypted_length)
        length = int.from_bytes(decrypted_length_bytes, 'big')
        cls.logger.debug(f'Encrypted packet length: {length}')
        encrypted_padding_length = source.recv(1)
        decrypted_padding_length_bytes = decryptor.update(encrypted_padding_length)
        padding_length = int.from_bytes(decrypted_padding_length_bytes, 'big')
        encrypted_payload = source.recv(length - padding_length - 1)
        decrypted_payload = decryptor.update(encrypted_payload)
        encrypted_random_padding = source.recv(padding_length)
        random_padding = decryptor.update(encrypted_random_padding)
        mac = source.recv(len(mac_applicator(b'')))
        expected_mac = mac_applicator(decrypted_length_bytes + decrypted_padding_length_bytes + decrypted_payload + random_padding)
        assert mac == expected_mac, f"MAC does not match {mac} vs {expected_mac}"
        cls.logger.info("MAC is good")
        return cls(
            length=length,
            padding_length=padding_length,
            payload=decrypted_payload,
            random_padding=random_padding,
        )

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
