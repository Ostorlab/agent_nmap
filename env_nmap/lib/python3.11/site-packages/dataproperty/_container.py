"""
.. codeauthor:: Tsuyoshi Hombashi <tsuyoshi.hombashi@gmail.com>
"""

import abc
from decimal import Decimal
from typing import Any, List, Optional, Sequence, Union

from typepy import RealNumber


T = Union[int, float, Decimal]
NAN = Decimal("nan")


class AbstractContainer(metaclass=abc.ABCMeta):
    @abc.abstractproperty
    def min_value(self) -> Optional[Decimal]:  # pragma: no cover
        pass

    @abc.abstractproperty
    def max_value(self) -> Optional[Decimal]:  # pragma: no cover
        pass

    @abc.abstractmethod
    def mean(self) -> Decimal:  # pragma: no cover
        pass

    @abc.abstractmethod
    def update(self, value: Optional[T]) -> None:  # pragma: no cover
        pass

    @abc.abstractmethod
    def merge(self, value: "AbstractContainer") -> None:  # pragma: no cover
        pass

    def __repr__(self) -> str:
        if not self.has_value():
            return "None"

        return ", ".join([f"min={self.min_value}", f"max={self.max_value}"])

    def has_value(self) -> bool:
        return self.min_value is not None and self.max_value is not None

    def is_same_value(self) -> bool:
        return self.has_value() and self.min_value == self.max_value

    def is_zero(self) -> bool:
        return self.has_value() and self.min_value == 0 and self.max_value == 0


class ListContainer(AbstractContainer):
    __slots__ = ("__value_list",)

    @property
    def min_value(self) -> Optional[Decimal]:
        try:
            return min(self.__value_list)
        except ValueError:
            return None

    @property
    def max_value(self) -> Optional[Decimal]:
        try:
            return max(self.__value_list)
        except ValueError:
            return None

    @property
    def value_list(self) -> List[Decimal]:
        return self.__value_list

    def __init__(self, value_list: Optional[List[Decimal]] = None) -> None:
        if value_list is None:
            self.__value_list: List[Decimal] = []
            return

        for value in value_list:
            self.update(value)

    def mean(self) -> Decimal:
        try:
            return Decimal(sum(self.__value_list) / len(self.__value_list))
        except ZeroDivisionError:
            return NAN

    def update(self, value: Union[int, float, Decimal, None]) -> None:
        if value is None:
            return

        store_value = RealNumber(value).try_convert()
        if store_value is None:
            return

        self.__value_list.append(store_value)

    def merge(self, value: "AbstractContainer") -> None:
        if not isinstance(value, ListContainer):
            return

        for v in value.value_list:
            self.update(v)


class MinMaxContainer(AbstractContainer):
    __slots__ = ("__min_value", "__max_value")

    def __init__(self, value_list: Optional[Sequence[Decimal]] = None) -> None:
        self.__min_value: Optional[Decimal] = None
        self.__max_value: Optional[Decimal] = None

        if value_list is None:
            return

        for value in value_list:
            self.update(value)

    @property
    def min_value(self) -> Optional[Decimal]:
        return self.__min_value

    @property
    def max_value(self) -> Optional[Decimal]:
        return self.__max_value

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, MinMaxContainer):
            return False

        return all([self.min_value == other.min_value, self.max_value == other.max_value])

    def __ne__(self, other: Any) -> bool:
        if not isinstance(other, MinMaxContainer):
            return True

        return any([self.min_value != other.min_value, self.max_value != other.max_value])

    def __contains__(self, x: T) -> bool:
        if self.min_value is None:
            return False

        if self.max_value is None:
            return False

        return self.min_value <= x <= self.max_value

    def diff(self) -> Decimal:
        if self.min_value is None:
            return NAN

        if self.max_value is None:
            return NAN

        try:
            return self.max_value - self.min_value
        except TypeError:
            return NAN

    def mean(self) -> Decimal:
        if self.min_value is None:
            return NAN

        if self.max_value is None:
            return NAN

        try:
            return (self.max_value + self.min_value) * Decimal("0.5")
        except TypeError:
            return NAN

    def update(self, value: Optional[T]) -> None:
        if value is None:
            return

        decimal_value = Decimal(value)

        if self.__min_value is None:
            self.__min_value = decimal_value
        else:
            self.__min_value = min(self.__min_value, decimal_value)

        if self.__max_value is None:
            self.__max_value = decimal_value
        else:
            self.__max_value = max(self.__max_value, decimal_value)

    def merge(self, value: "AbstractContainer") -> None:
        if not isinstance(value, MinMaxContainer):
            return

        self.update(value.min_value)
        self.update(value.max_value)
