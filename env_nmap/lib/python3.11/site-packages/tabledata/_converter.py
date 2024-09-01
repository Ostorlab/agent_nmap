"""
.. codeauthor:: Tsuyoshi Hombashi <tsuyoshi.hombashi@gmail.com>
"""

from typing import Any, List, Sequence, Tuple

from .error import DataError


Row = Tuple[int, Any]


def to_value_matrix(headers: Sequence[str], value_matrix: Sequence[Any]) -> List[Row]:
    if not value_matrix:
        return []

    return [_to_row(headers, values, row_idx)[1] for row_idx, values in enumerate(value_matrix)]


def _to_row(headers: Sequence[str], values: Any, row_idx: int) -> Row:
    if headers:
        try:
            values = values._asdict()
        except AttributeError:
            pass

        try:
            return (row_idx, [values.get(header) for header in headers])
        except (TypeError, AttributeError):
            pass

    if not isinstance(values, (tuple, list)):
        raise DataError(f"row must be a list or tuple: actual={type(values)}")

    return (row_idx, values)
