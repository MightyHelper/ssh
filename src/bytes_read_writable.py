from abc import ABC, abstractmethod


class BytesReadWritable(ABC):
    @abstractmethod
    def recv(self, n_bytes: int) -> bytes:
        pass

    @abstractmethod
    def send(self, message: bytes) -> None:
        pass
