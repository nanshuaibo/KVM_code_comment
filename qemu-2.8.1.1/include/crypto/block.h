/*
 * QEMU Crypto block device encryption
 *
 * Copyright (c) 2015-2016 Red Hat, Inc.
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

#ifndef QCRYPTO_BLOCK_H
#define QCRYPTO_BLOCK_H

#include "crypto/cipher.h"
#include "crypto/ivgen.h"

typedef struct QCryptoBlock QCryptoBlock;

/* See also QCryptoBlockFormat, QCryptoBlockCreateOptions
 * and QCryptoBlockOpenOptions in qapi/crypto.json */

typedef ssize_t (*QCryptoBlockReadFunc)(QCryptoBlock *block,
                                        size_t offset,
                                        uint8_t *buf,
                                        size_t buflen,
                                        Error **errp,
                                        void *opaque);

typedef ssize_t (*QCryptoBlockInitFunc)(QCryptoBlock *block,
                                        size_t headerlen,
                                        Error **errp,
                                        void *opaque);

typedef ssize_t (*QCryptoBlockWriteFunc)(QCryptoBlock *block,
                                         size_t offset,
                                         const uint8_t *buf,
                                         size_t buflen,
                                         Error **errp,
                                         void *opaque);

/**
 * qcrypto_block_has_format:
 * @format: the encryption format
 * @buf: the data from head of the volume
 * @len: the length of @buf in bytes
 *
 * Given @len bytes of data from the head of a storage volume
 * in @buf, probe to determine if the volume has the encryption
 * format specified in @format.
 *
 * Returns: true if the data in @buf matches @format
 */
bool qcrypto_block_has_format(QCryptoBlockFormat format,
                              const uint8_t *buf,
                              size_t buflen);

typedef enum {
    QCRYPTO_BLOCK_OPEN_NO_IO = (1 << 0),
} QCryptoBlockOpenFlags;

/**
 * qcrypto_block_open:
 * @options: the encryption options
 * @readfunc: callback for reading data from the volume
 * @opaque: data to pass to @readfunc
 * @flags: bitmask of QCryptoBlockOpenFlags values
 * @errp: pointer to a NULL-initialized error object
 *
 * Create a new block encryption object for an existing
 * storage volume encrypted with format identified by
 * the parameters in @options.
 *
 * This will use @readfunc to initialize the encryption
 * context based on the volume header(s), extracting the
 * master key(s) as required.
 *
 * If @flags contains QCRYPTO_BLOCK_OPEN_NO_IO then
 * the open process will be optimized to skip any parts
 * that are only required to perform I/O. In particular
 * this would usually avoid the need to decrypt any
 * master keys. The only thing that can be done with
 * the resulting QCryptoBlock object would be to query
 * metadata such as the payload offset. There will be
 * no cipher or ivgen objects available.
 *
 * If any part of initializing the encryption context
 * fails an error will be returned. This could be due
 * to the volume being in the wrong format, a cipher
 * or IV generator algorithm that is not supported,
 * or incorrect passphrases.
 *
 * Returns: a block encryption format, or NULL on error
 */
QCryptoBlock *qcrypto_block_open(QCryptoBlockOpenOptions *options,
                                 QCryptoBlockReadFunc readfunc,
                                 void *opaque,
                                 unsigned int flags,
                                 Error **errp);

/**
 * qcrypto_block_create:
 * @format: the encryption format
 * @initfunc: callback for initializing volume header
 * @writefunc: callback for writing data to the volume header
 * @opaque: data to pass to @initfunc and @writefunc
 * @errp: pointer to a NULL-initialized error object
 *
 * Create a new block encryption object for initializing
 * a storage volume to be encrypted with format identified
 * by the parameters in @options.
 *
 * This method will allocate space for a new volume header
 * using @initfunc and then write header data using @writefunc,
 * generating new master keys, etc as required. Any existing
 * data present on the volume will be irrevocably destroyed.
 *
 * If any part of initializing the encryption context
 * fails an error will be returned. This could be due
 * to the volume being in the wrong format, a cipher
 * or IV generator algorithm that is not supported,
 * or incorrect passphrases.
 *
 * Returns: a block encryption format, or NULL on error
 */
QCryptoBlock *qcrypto_block_create(QCryptoBlockCreateOptions *options,
                                   QCryptoBlockInitFunc initfunc,
                                   QCryptoBlockWriteFunc writefunc,
                                   void *opaque,
                                   Error **errp);


/**
 * qcrypto_block_get_info:
 * @block: the block encryption object
 * @errp: pointer to a NULL-initialized error object
 *
 * Get information about the configuration options for the
 * block encryption object. This includes details such as
 * the cipher algorithms, modes, and initialization vector
 * generators.
 *
 * Returns: a block encryption info object, or NULL on error
 */
QCryptoBlockInfo *qcrypto_block_get_info(QCryptoBlock *block,
                                         Error **errp);

/**
 * @qcrypto_block_decrypt:
 * @block: the block encryption object
 * @startsector: the sector from which @buf was read
 * @buf: the buffer to decrypt
 * @len: the length of @buf in bytes
 * @errp: pointer to a NULL-initialized error object
 *
 * Decrypt @len bytes of cipher text in @buf, writing
 * plain text back into @buf
 *
 * Returns 0 on success, -1 on failure
 */
int qcrypto_block_decrypt(QCryptoBlock *block,
                          uint64_t startsector,
                          uint8_t *buf,
                          size_t len,
                          Error **errp);

/**
 * @qcrypto_block_encrypt:
 * @block: the block encryption object
 * @startsector: the sector to which @buf will be written
 * @buf: the buffer to decrypt
 * @len: the length of @buf in bytes
 * @errp: pointer to a NULL-initialized error object
 *
 * Encrypt @len bytes of plain text in @buf, writing
 * cipher text back into @buf
 *
 * Returns 0 on success, -1 on failure
 */
int qcrypto_block_encrypt(QCryptoBlock *block,
                          uint64_t startsector,
                          uint8_t *buf,
                          size_t len,
                          Error **errp);

/**
 * qcrypto_block_get_cipher:
 * @block: the block encryption object
 *
 * Get the cipher to use for payload encryption
 *
 * Returns: the cipher object
 */
QCryptoCipher *qcrypto_block_get_cipher(QCryptoBlock *block);

/**
 * qcrypto_block_get_ivgen:
 * @block: the block encryption object
 *
 * Get the initialization vector generator to use for
 * payload encryption
 *
 * Returns: the IV generator object
 */
QCryptoIVGen *qcrypto_block_get_ivgen(QCryptoBlock *block);


/**
 * qcrypto_block_get_kdf_hash:
 * @block: the block encryption object
 *
 * Get the hash algorithm used with the key derivation
 * function
 *
 * Returns: the hash algorithm
 */
QCryptoHashAlgorithm qcrypto_block_get_kdf_hash(QCryptoBlock *block);

/**
 * qcrypto_block_get_payload_offset:
 * @block: the block encryption object
 *
 * Get the offset to the payload indicated by the
 * encryption header, in bytes.
 *
 * Returns: the payload offset in bytes
 */
uint64_t qcrypto_block_get_payload_offset(QCryptoBlock *block);

/**
 * qcrypto_block_free:
 * @block: the block encryption object
 *
 * Release all resources associated with the encryption
 * object
 */
void qcrypto_block_free(QCryptoBlock *block);

#endif /* QCRYPTO_BLOCK_H */
