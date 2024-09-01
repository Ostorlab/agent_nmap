"""
.. codeauthor:: Tsuyoshi Hombashi <tsuyoshi.hombashi@gmail.com>
"""

import abc
from typing import Optional

from typepy import Typecode

from ._align import Align


class DataPeropertyInterface(metaclass=abc.ABCMeta):
    __slots__ = ()

    @abc.abstractproperty
    def align(self) -> Align:  # pragma: no cover
        pass

    @abc.abstractproperty
    def decimal_places(self) -> Optional[int]:  # pragma: no cover
        pass

    @abc.abstractproperty
    def typecode(self) -> Typecode:  # pragma: no cover
        pass

    @abc.abstractproperty
    def typename(self) -> str:  # pragma: no cover
        pass
