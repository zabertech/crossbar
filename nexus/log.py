import pprint
import json
import sys
import os
import re
import logging

__all__ = ['log', 'Logger']

class Logger:

    _log = None

    def __init__(self):
        self._log = None

    def set_logger(self, logger):
        self._log = logger

    def str(self, fmt, *a, **kw):
        # fmt is a string, not an object or anything else
        if isinstance(fmt, str):
            return fmt

        # base primitives we just pretty print
        elif isinstance( fmt, (dict, list, tuple ) ):
            return pprint.pformat(fmt)

        # fmt is an object, we do something else with this
        s = f"\nObject: {type(fmt)}\n"
        #s += f"Declared: {fmt.__class__.__file__}"
        for k in dir(fmt):

            # ignore dunder methods
            if re.match('^__.*__$', k):
                 continue
            v = getattr(fmt, k)
            s += f" - `{k}`{type(v)}: {v}\n"

        return s

    def log_action( self, level, fmt, *a, **kw ):
        s = self.str(fmt, *a, **kw)
        s = s.replace('{',r'{{')
        s = s.replace('}',r'}}')

        # If we don't have a logging function defined we just print it out
        if not self._log:
            print(s)
            return

        # If we do have a looking function, then pass the data to that function
        logging_func = getattr(self._log, level)
        logging_func(s)

    def __getattr__(self, k):
        if k in [
              'critical',
              'error',
              'warn',
              'warning',
              'info',
              'debug',
              'trace',
            ]:

            # Sometimes we're dealing with txaio.tx.Logger which doesn't
            # have warning. So we do a remap here
            if k == 'warning':
                k = 'warn'
            return lambda *a, **kw: self.log_action(k, *a, **kw)

log = Logger()

