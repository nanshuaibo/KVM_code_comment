/*
 * QEMU Crypto cipher algorithms
 *
 * Copyright (c) 2015 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "crypto/cipher.h"


static size_t alg_key_len[QCRYPTO_CIPHER_ALG__MAX] = {
    [QCRYPTO_CIPHER_ALG_AES_128] = 16,
    [QCRYPTO_CIPHER_ALG_AES_192] = 24,
    [QCRYPTO_CIPHER_ALG_AES_256] = 32,
    [QCRYPTO_CIPHER_ALG_DES_RFB] = 8,
    [QCRYPTO_CIPHER_ALG_CAST5_128] = 16,
    [QCRYPTO_CIPHER_ALG_SERPENT_128] = 16,
    [QCRYPTO_CIPHER_ALG_SERPENT_192] = 24,
    [QCRYPTO_CIPHER_ALG_SERPENT_256] = 32,
    [QCRYPTO_CIPHER_ALG_TWOFISH_128] = 16,
    [QCRYPTO_CIPHER_ALG_TWOFISH_192] = 24,
    [QCRYPTO_CIPHER_ALG_TWOFISH_256] = 32,
};

static size_t alg_block_len[QCRYPTO_CIPHER_ALG__MAX] = {
    [QCRYPTO_CIPHER_ALG_AES_128] = 16,
    [QCRYPTO_CIPHER_ALG_AES_192] = 16,
    [QCRYPTO_CIPHER_ALG_AES_256] = 16,
    [QCRYPTO_CIPHER_ALG_DES_RFB] = 8,
    [QCRYPTO_CIPHER_ALG_CAST5_128] = 8,
    [QCRYPTO_CIPHER_ALG_SERPENT_128] = 16,
    [QCRYPTO_CIPHER_ALG_SERPENT_192] = 16,
    [QCRYPTO_CIPHER_ALG_SERPENT_256] = 16,
    [QCRYPTO_CIPHER_ALG_TWOFISH_128] = 16,
    [QCRYPTO_CIPHER_ALG_TWOFISH_192] = 16,
    [QCRYPTO_CIPHER_ALG_TWOFISH_256] = 16,
};

static bool mode_need_iv[QCRYPTO_CIPHER_MODE__MAX] = {
    [QCRYPTO_CIPHER_MODE_ECB] = false,
    [QCRYPTO_CIPHER_MODE_CBC] = true,
    [QCRYPTO_CIPHER_MODE_XTS] = true,
    [QCRYPTO_CIPHER_MODE_CTR] = true,
};


size_t qcrypto_cipher_get_block_len(QCryptoCipherAlgorithm alg)
{
    if (alg >= G_N_ELEMENTS(alg_key_len)) {
        return 0;
    }
    return alg_block_len[alg];
}


size_t qcrypto_cipher_get_key_len(QCryptoCipherAlgorithm alg)
{
    if (alg >= G_N_ELEMENTS(alg_key_len)) {
        return 0;
    }
    return alg_key_len[alg];
}


size_t qcrypto_cipher_get_iv_len(QCryptoCipherAlgorithm alg,
                                 QCryptoCipherMode mode)
{
    if (alg >= G_N_ELEMENTS(alg_block_len)) {
        return 0;
    }
    if (mode >= G_N_ELEMENTS(mode_need_iv)) {
        return 0;
    }

    if (mode_need_iv[mode]) {
        return alg_block_len[alg];
    }
    return 0;
}


static bool
qcrypto_cipher_validate_key_length(QCryptoCipherAlgorithm alg,
                                   QCryptoCipherMode mode,
                                   size_t nkey,
                                   Error **errp)
{
    if ((unsigned)alg >= QCRYPTO_CIPHER_ALG__MAX) {
        error_setg(errp, "Cipher algorithm %d out of range",
                   alg);
        return false;
    }

    if (mode == QCRYPTO_CIPHER_MODE_XTS) {
        if (alg == QCRYPTO_CIPHER_ALG_DES_RFB) {
            error_setg(errp, "XTS mode not compatible with DES-RFB");
            return false;
        }
        if (nkey % 2) {
            error_setg(errp, "XTS cipher key length should be a multiple of 2");
            return false;
        }

        if (alg_key_len[alg] != (nkey / 2)) {
            error_setg(errp, "Cipher key length %zu should be %zu",
                       nkey, alg_key_len[alg] * 2);
            return false;
        }
    } else {
        if (alg_key_len[alg] != nkey) {
            error_setg(errp, "Cipher key length %zu should be %zu",
                       nkey, alg_key_len[alg]);
            return false;
        }
    }
    return true;
}

#if defined(CONFIG_GCRYPT) || defined(CONFIG_NETTLE)
static uint8_t *
qcrypto_cipher_munge_des_rfb_key(const uint8_t *key,
                                 size_t nkey)
{
    uint8_t *ret = g_new0(uint8_t, nkey);
    size_t i;
    for (i = 0; i < nkey; i++) {
        uint8_t r = key[i];
        r = (r & 0xf0) >> 4 | (r & 0x0f) << 4;
        r = (r & 0xcc) >> 2 | (r & 0x33) << 2;
        r = (r & 0xaa) >> 1 | (r & 0x55) << 1;
        ret[i] = r;
    }
    return ret;
}
#endif /* CONFIG_GCRYPT || CONFIG_NETTLE */

#ifdef CONFIG_GCRYPT
#include "crypto/cipher-gcrypt.c"
#elif defined CONFIG_NETTLE
#include "crypto/cipher-nettle.c"
#else
#include "crypto/cipher-builtin.c"
#endif
