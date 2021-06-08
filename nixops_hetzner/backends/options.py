from typing import (
    Optional,
    Sequence,
    Union,
    Mapping,
)
from typing_extensions import Literal
from nixops.resources import ResourceOptions


class HetznerOptions(ResourceOptions):
    mainIPv4: str
    createSubAccount: bool
    robotUser: str
    robotPass: str
    partitions: str
