"""
.. codeauthor:: Tsuyoshi Hombashi <tsuyoshi.hombashi@gmail.com>
"""

import warnings

import dataproperty

from ._null_logger import NullLogger  # type: ignore


MODULE_NAME = "tabledata"

try:
    from loguru import logger

    logger.disable(MODULE_NAME)
except ImportError:
    logger = NullLogger()


def set_logger(is_enable: bool, propagation_depth: int = 1) -> None:
    if is_enable:
        logger.enable(MODULE_NAME)
    else:
        logger.disable(MODULE_NAME)

    if propagation_depth <= 0:
        return

    dataproperty.set_logger(is_enable, propagation_depth - 1)


def set_log_level(log_level):  # type: ignore
    warnings.warn(
        "'set_log_level' method is deprecated and will be removed in the future. ",
        DeprecationWarning,
    )
    return
