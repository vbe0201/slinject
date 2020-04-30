# -*- coding: utf-8 -*-

from .utils import is_windows, is_linux

if is_windows():
    from ._inject_windows import *
elif is_linux():
    from ._inject_linux import *
else:
    raise RuntimeError('Unsupported platform')

__all__ = ()
