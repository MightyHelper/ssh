import re
from dataclasses import dataclass
from typing import ClassVar, Self


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
        if not self.comments:
            return f'SSH-{self.proto_version}-{self.software_version}'
        return f'SSH-{self.proto_version}-{self.software_version} {self.comments}'

    @classmethod
    def from_string(cls, data: str) -> Self:
        match = cls.PATTERN.match(data)
        if not match:
            raise ValueError(f'Invalid SSH version string: {data}')
        return cls(**match.groupdict())
