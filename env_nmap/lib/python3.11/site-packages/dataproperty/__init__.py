"""
.. codeauthor:: Tsuyoshi Hombashi <tsuyoshi.hombashi@gmail.com>
"""

from .__version__ import __author__, __copyright__, __email__, __license__, __version__
from ._align import Align
from ._align_getter import align_getter
from ._column import ColumnDataProperty
from ._common import MAX_STRICT_LEVEL_MAP, MIN_STRICT_LEVEL_MAP, NOT_QUOTING_FLAGS, DefaultValue
from ._container import MinMaxContainer
from ._dataproperty import DataProperty
from ._extractor import DataPropertyExtractor, DataPropertyMatrix, MatrixFormatting
from ._formatter import Format
from ._function import calc_ascii_char_width, get_integer_digit, get_number_of_digit
from ._line_break import LineBreakHandling
from ._preprocessor import Preprocessor
from .logger import set_logger


__all__ = (
    "Align",
    "align_getter",
    "ColumnDataProperty",
    "DataProperty",
    "DataPropertyExtractor",
    "DataPropertyMatrix",
    "Format",
    "LineBreakHandling",
    "MatrixFormatting",
    "MinMaxContainer",
    "Preprocessor",
    "calc_ascii_char_width",
    "get_integer_digit",
    "get_number_of_digit",
    "MAX_STRICT_LEVEL_MAP",
    "MIN_STRICT_LEVEL_MAP",
    "NOT_QUOTING_FLAGS",
    "DefaultValue",
    "set_logger",
    "__author__",
    "__copyright__",
    "__email__",
    "__license__",
    "__version__",
)
