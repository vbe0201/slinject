# -*- coding: utf-8 -*-

from collections import namedtuple
import sys

__all__ = (
    'is_windows',
    'is_linux',
)


def is_windows() -> bool:
    """Checks whether the program is being executed on a Windows machine."""

    return sys.platform == 'win32'


def is_linux() -> bool:
    """Checks whether the program is being executed on a Linux machine."""

    return sys.platform.startswith('linux')


# Windows-exclusive utils.
if is_windows():
    __all__ += (
        'get_system_info',
        'SystemInfo',
    )


#: Representation of the system information forwarded by `GetSystemInfo()`.
#:
#: NOTE: This type is only meant for Windows systems.
SystemInfo = namedtuple(
    'SystemInfo',
    [
        'architecture', 'page_size', 'min_address', 'max_address',
        'processor_mask', 'num_processors', 'processor_type', 'alloc_size',
        'processor_info',
    ]
)


def get_system_info() -> SystemInfo:
    """Retrieves system information for a Windows platform.

    .. note::

        Due to a dependency on the ``GetSystemInfo()`` function
        from the Windows API, the function is only exposed to
        Windows systems as a result of that.

    Returns
    -------
    :class:`~slinject.utils.SystemInfo`
        The system information.
    """

    assert is_windows(), 'This function is only available on Windows systems'

    from win32api import GetSystemInfo
    return SystemInfo(*GetSystemInfo())
