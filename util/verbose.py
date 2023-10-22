#!/usr/bin/python3

import sys

def verbose(level, current, *args, **kwargs):
    """Show infirmation per verbose level

    util.verbose(3, self.verbosity, f'Parameter is {param}')
    """
    if level <= current:
        print(f'#[{level}]', *args, file=sys.stderr, **kwargs)
