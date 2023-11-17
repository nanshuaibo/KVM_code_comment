#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Generate .stp file (DTrace with SystemTAP only).
"""

__author__     = "Lluís Vilanova <vilanova@ac.upc.edu>"
__copyright__  = "Copyright 2012-2014, Lluís Vilanova <vilanova@ac.upc.edu>"
__license__    = "GPL version 2 or (at your option) any later version"

__maintainer__ = "Stefan Hajnoczi"
__email__      = "stefanha@linux.vnet.ibm.com"


from tracetool import out
from tracetool.backend.dtrace import binary, probeprefix


# Technically 'self' is not used by systemtap yet, but
# they recommended we keep it in the reserved list anyway
RESERVED_WORDS = (
    'break', 'catch', 'continue', 'delete', 'else', 'for',
    'foreach', 'function', 'global', 'if', 'in', 'limit',
    'long', 'next', 'probe', 'return', 'self', 'string',
    'try', 'while'
    )


def stap_escape(identifier):
    # Append underscore to reserved keywords
    if identifier in RESERVED_WORDS:
        return identifier + '_'
    return identifier


def generate(events, backend, group):
    events = [e for e in events
              if "disable" not in e.properties]

    out('/* This file is autogenerated by tracetool, do not edit. */',
        '')

    for e in events:
        # Define prototype for probe arguments
        out('probe %(probeprefix)s.%(name)s = process("%(binary)s").mark("%(name)s")',
            '{',
            probeprefix=probeprefix(),
            name=e.name,
            binary=binary())

        i = 1
        if len(e.args) > 0:
            for name in e.args.names():
                name = stap_escape(name)
                out('  %s = $arg%d;' % (name, i))
                i += 1

        out('}')

    out()
