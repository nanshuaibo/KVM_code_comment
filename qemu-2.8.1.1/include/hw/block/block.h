/*
 * Common code for block device models
 *
 * Copyright (C) 2012 Red Hat, Inc.
 * Copyright (c) 2003-2008 Fabrice Bellard
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * later.  See the COPYING file in the top-level directory.
 */

#ifndef HW_BLOCK_H
#define HW_BLOCK_H

#include "qemu-common.h"

/* Configuration */

typedef struct BlockConf {
    BlockBackend *blk;
    uint16_t physical_block_size;
    uint16_t logical_block_size;
    uint16_t min_io_size;
    uint32_t opt_io_size;
    int32_t bootindex;
    uint32_t discard_granularity;
    /* geometry, not all devices use this */
    uint32_t cyls, heads, secs;
    OnOffAuto wce;
    BlockdevOnError rerror;
    BlockdevOnError werror;
} BlockConf;

static inline unsigned int get_physical_block_exp(BlockConf *conf)
{
    unsigned int exp = 0, size;

    for (size = conf->physical_block_size;
        size > conf->logical_block_size;
        size >>= 1) {
        exp++;
    }

    return exp;
}

#define DEFINE_BLOCK_PROPERTIES(_state, _conf)                          \
    DEFINE_PROP_DRIVE("drive", _state, _conf.blk),                      \
    DEFINE_PROP_BLOCKSIZE("logical_block_size", _state,                 \
                          _conf.logical_block_size),                    \
    DEFINE_PROP_BLOCKSIZE("physical_block_size", _state,                \
                          _conf.physical_block_size),                   \
    DEFINE_PROP_UINT16("min_io_size", _state, _conf.min_io_size, 0),  \
    DEFINE_PROP_UINT32("opt_io_size", _state, _conf.opt_io_size, 0),    \
    DEFINE_PROP_UINT32("discard_granularity", _state, \
                       _conf.discard_granularity, -1), \
    DEFINE_PROP_ON_OFF_AUTO("write-cache", _state, _conf.wce, ON_OFF_AUTO_AUTO)

#define DEFINE_BLOCK_CHS_PROPERTIES(_state, _conf)      \
    DEFINE_PROP_UINT32("cyls", _state, _conf.cyls, 0),  \
    DEFINE_PROP_UINT32("heads", _state, _conf.heads, 0), \
    DEFINE_PROP_UINT32("secs", _state, _conf.secs, 0)

#define DEFINE_BLOCK_ERROR_PROPERTIES(_state, _conf)                    \
    DEFINE_PROP_BLOCKDEV_ON_ERROR("rerror", _state, _conf.rerror,       \
                                  BLOCKDEV_ON_ERROR_AUTO),              \
    DEFINE_PROP_BLOCKDEV_ON_ERROR("werror", _state, _conf.werror,       \
                                  BLOCKDEV_ON_ERROR_AUTO)

/* Configuration helpers */

void blkconf_serial(BlockConf *conf, char **serial);
void blkconf_geometry(BlockConf *conf, int *trans,
                      unsigned cyls_max, unsigned heads_max, unsigned secs_max,
                      Error **errp);
void blkconf_blocksizes(BlockConf *conf);
void blkconf_apply_backend_options(BlockConf *conf);

/* Hard disk geometry */

void hd_geometry_guess(BlockBackend *blk,
                       uint32_t *pcyls, uint32_t *pheads, uint32_t *psecs,
                       int *ptrans);
int hd_bios_chs_auto_trans(uint32_t cyls, uint32_t heads, uint32_t secs);

#endif
