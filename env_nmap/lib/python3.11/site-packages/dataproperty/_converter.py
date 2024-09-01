"""
.. codeauthor:: Tsuyoshi Hombashi <tsuyoshi.hombashi@gmail.com>
"""

import re
from typing import Any, Dict, Optional

from typepy import Typecode, TypeConversionError

from ._common import MAX_STRICT_LEVEL_MAP, DefaultValue
from ._dataproperty import DataProperty
from ._preprocessor import Preprocessor
from .typing import DateTimeFormatter, FloatType, StrictLevelMap, TypeValueMap


class DataPropertyConverter:
    __RE_QUOTE_LINE = re.compile(r"^\s*[\"'].*[\"']\s*$")  # noqa: w605
    __RE_QUOTE_CHAR = re.compile("[\"']")

    def __init__(
        self,
        preprocessor: Preprocessor,
        datetime_format_str: str,
        datetime_formatter: Optional[DateTimeFormatter] = None,
        type_value_map: Optional[TypeValueMap] = None,
        quoting_flags: Optional[Dict[Typecode, bool]] = None,
        float_type: Optional[FloatType] = None,
        strict_level_map: Optional[StrictLevelMap] = None,
    ) -> None:
        self.__preprocessor = preprocessor
        self.__type_value_map: TypeValueMap = (
            type_value_map if type_value_map else DefaultValue.TYPE_VALUE_MAP
        )
        self.__quoting_flags: Dict[Typecode, bool] = (
            quoting_flags if quoting_flags else DefaultValue.QUOTING_FLAGS
        )

        self.__datetime_formatter = datetime_formatter
        self.__datetime_format_str = datetime_format_str
        self.__float_type = float_type
        self.__strict_level_map = strict_level_map

    def convert(self, dp_value: DataProperty) -> DataProperty:
        try:
            return self.__create_dataproperty(self.__convert_value(dp_value))
        except TypeConversionError:
            pass

        if not self.__quoting_flags.get(dp_value.typecode):
            if self.__preprocessor.is_escape_html_tag:
                return self.__create_dataproperty(dp_value.to_str())

            return dp_value

        return self.__create_dataproperty(self.__apply_quote(dp_value.typecode, dp_value.to_str()))

    def __create_dataproperty(self, value: Any) -> DataProperty:
        return DataProperty(
            value,
            preprocessor=self.__preprocessor,
            float_type=self.__float_type,
            datetime_format_str=self.__datetime_format_str,
            strict_level_map=MAX_STRICT_LEVEL_MAP,
        )

    def __apply_quote(self, typecode: Typecode, data: Any) -> Any:
        if not self.__quoting_flags.get(typecode):
            return data

        try:
            if self.__RE_QUOTE_LINE.search(data):
                return data
        except TypeError:
            return data

        return '"{}"'.format(self.__RE_QUOTE_CHAR.sub('\\"', data.replace("\\", "\\\\")))

    def __convert_value(self, dp_value: DataProperty) -> Any:
        if dp_value.typecode in self.__type_value_map:
            return self.__apply_quote(dp_value.typecode, self.__type_value_map[dp_value.typecode])

        if dp_value.typecode == Typecode.DATETIME and self.__datetime_formatter:
            try:
                return self.__apply_quote(
                    dp_value.typecode, self.__datetime_formatter(dp_value.data)
                )
            except TypeError:
                raise TypeConversionError

        raise TypeConversionError("no need to convert")
