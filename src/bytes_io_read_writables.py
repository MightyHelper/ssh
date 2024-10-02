import io

from src.bytes_read_writable import BytesReadWritable


class BytesIOReadWritable(BytesReadWritable):
    def __init__(self, data: io.BytesIO):
        self.data = data

    def recv(self, n_bytes: int) -> bytes:
        return self.data.read(n_bytes)

    def send(self, message: bytes) -> None:
        self.data.write(message)
