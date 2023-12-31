#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Generate trace/generated-helpers-wrappers.h.
"""

__author__     = "Lluís Vilanova <vilanova@ac.upc.edu>"
__copyright__  = "Copyright 2012-2016, Lluís Vilanova <vilanova@ac.upc.edu>"
__license__    = "GPL version 2 or (at your option) any later version"

__maintainer__ = "Stefan Hajnoczi"
__email__      = "stefanha@linux.vnet.ibm.com"


from tracetool import out
from tracetool.transform import *
import tracetool.vcpu


def generate(events, backend, group):
    events = [e for e in events
              if "disable" not in e.properties]

    out('/* This file is autogenerated by tracetool, do not edit. */',
        '',
        '#define tcg_temp_new_nop(v) (v)',
        '#define tcg_temp_free_nop(v)',
        '',
        )

    for e in events:
        if "tcg-exec" not in e.properties:
            continue

        # tracetool.generate always transforms types to host
        e_args = tracetool.vcpu.transform_args("tcg_helper_c", e.original, "wrapper")

        # mixed-type to TCG helper bridge
        args_tcg_compat = e_args.transform(HOST_2_TCG_COMPAT)

        code_new = [
            "%(tcg_type)s __%(name)s = %(tcg_func)s(%(name)s);" %
            {"tcg_type": transform_type(type_, HOST_2_TCG),
             "tcg_func": transform_type(type_, HOST_2_TCG_TMP_NEW),
             "name": name}
            for (type_, name) in args_tcg_compat
        ]

        code_free = [
            "%(tcg_func)s(__%(name)s);" %
            {"tcg_func": transform_type(type_, HOST_2_TCG_TMP_FREE),
             "name": name}
            for (type_, name) in args_tcg_compat
        ]

        gen_name = "gen_helper_" + e.api()

        out('static inline void %(name)s(%(args)s)',
            '{',
            '    %(code_new)s',
            '    %(proxy_name)s(%(tmp_names)s);',
            '    %(code_free)s',
            '}',
            name=gen_name,
            args=e_args,
            proxy_name=gen_name + "_proxy",
            code_new="\n    ".join(code_new),
            code_free="\n    ".join(code_free),
            tmp_names=", ".join(["__%s" % name for _, name in e_args]),
            )
