/**
 * \file cmac.h
 *
 * \brief This file contains CMAC definitions and functions.
 *
 * The Cipher-based Message Authentication Code (CMAC) Mode for
 * Authentication is defined in <em>RFC-4493: The AES-CMAC Algorithm</em>.
 */
/*
 *  Copyright (C) 2015-2018, Arm Limited (or its affiliates), All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of Mbed TLS (https://tls.mbed.org)
 */

#ifndef JHD_TLS_CMAC_H
#define JHD_TLS_CMAC_H

#include "jhd_tls_cipher.h"



#define JHD_TLS_ERR_CMAC_HW_ACCEL_FAILED -0x007A  /**< CMAC hardware accelerator failed. */

#define JHD_TLS_AES_BLOCK_SIZE          16
#define JHD_TLS_DES3_BLOCK_SIZE         8

#if defined(JHD_TLS_AES_C)
#define JHD_TLS_CIPHER_BLKSIZE_MAX      16  /**< The longest block used by CMAC is that of AES. */
#else
#define JHD_TLS_CIPHER_BLKSIZE_MAX      8   /**< The longest block used by CMAC is that of 3DES. */
#endif

#if !defined(JHD_TLS_CMAC_ALT)

/**
 * The CMAC context structure.
 */
struct jhd_tls_cmac_context_t
{
    /** The internal state of the CMAC algorithm.  */
    unsigned char       state[JHD_TLS_CIPHER_BLKSIZE_MAX];

    /** Unprocessed data - either data that was not block aligned and is still
     *  pending processing, or the final block. */
    unsigned char       unprocessed_block[JHD_TLS_CIPHER_BLKSIZE_MAX];

    /** The length of data pending processing. */
    size_t              unprocessed_len;
};

#else  /* !JHD_TLS_CMAC_ALT */
#include "cmac_alt.h"
#endif /* !JHD_TLS_CMAC_ALT */

/**
 * \brief               This function sets the CMAC key, and prepares to authenticate
 *                      the input data.
 *                      Must be called with an initialized cipher context.
 *
 * \param ctx           The cipher context used for the CMAC operation, initialized
 *                      as one of the following types: JHD_TLS_CIPHER_AES_128_ECB,
 *                      JHD_TLS_CIPHER_AES_192_ECB, JHD_TLS_CIPHER_AES_256_ECB,
 *                      or JHD_TLS_CIPHER_DES_EDE3_ECB.
 * \param key           The CMAC key.
 * \param keybits       The length of the CMAC key in bits.
 *                      Must be supported by the cipher.
 *
 * \return              \c 0 on success.
 * \return              A cipher-specific error code on failure.
 */
int jhd_tls_cipher_cmac_starts( jhd_tls_cipher_context_t *ctx,
                                const unsigned char *key, size_t keybits );

/**
 * \brief               This function feeds an input buffer into an ongoing CMAC
 *                      computation.
 *
 *                      It is called between jhd_tls_cipher_cmac_starts() or
 *                      jhd_tls_cipher_cmac_reset(), and jhd_tls_cipher_cmac_finish().
 *                      Can be called repeatedly.
 *
 * \param ctx           The cipher context used for the CMAC operation.
 * \param input         The buffer holding the input data.
 * \param ilen          The length of the input data.
 *
 * \return             \c 0 on success.
 * \return             #JHD_TLS_ERR_MD_BAD_INPUT_DATA
 *                     if parameter verification fails.
 */
int jhd_tls_cipher_cmac_update( jhd_tls_cipher_context_t *ctx,
                                const unsigned char *input, size_t ilen );

/**
 * \brief               This function finishes the CMAC operation, and writes
 *                      the result to the output buffer.
 *
 *                      It is called after jhd_tls_cipher_cmac_update().
 *                      It can be followed by jhd_tls_cipher_cmac_reset() and
 *                      jhd_tls_cipher_cmac_update(), or jhd_tls_cipher_free().
 *
 * \param ctx           The cipher context used for the CMAC operation.
 * \param output        The output buffer for the CMAC checksum result.
 *
 * \return              \c 0 on success.
 * \return              #JHD_TLS_ERR_MD_BAD_INPUT_DATA
 *                      if parameter verification fails.
 */
int jhd_tls_cipher_cmac_finish( jhd_tls_cipher_context_t *ctx,
                                unsigned char *output );

/**
 * \brief               This function prepares the authentication of another
 *                      message with the same key as the previous CMAC
 *                      operation.
 *
 *                      It is called after jhd_tls_cipher_cmac_finish()
 *                      and before jhd_tls_cipher_cmac_update().
 *
 * \param ctx           The cipher context used for the CMAC operation.
 *
 * \return              \c 0 on success.
 * \return              #JHD_TLS_ERR_MD_BAD_INPUT_DATA
 *                      if parameter verification fails.
 */
int jhd_tls_cipher_cmac_reset( jhd_tls_cipher_context_t *ctx );

/**
 * \brief               This function calculates the full generic CMAC
 *                      on the input buffer with the provided key.
 *
 *                      The function allocates the context, performs the
 *                      calculation, and frees the context.
 *
 *                      The CMAC result is calculated as
 *                      output = generic CMAC(cmac key, input buffer).
 *
 *
 * \param cipher_info   The cipher information.
 * \param key           The CMAC key.
 * \param keylen        The length of the CMAC key in bits.
 * \param input         The buffer holding the input data.
 * \param ilen          The length of the input data.
 * \param output        The buffer for the generic CMAC result.
 *
 * \return              \c 0 on success.
 * \return              #JHD_TLS_ERR_MD_BAD_INPUT_DATA
 *                      if parameter verification fails.
 */
int jhd_tls_cipher_cmac( const jhd_tls_cipher_info_t *cipher_info,
                         const unsigned char *key, size_t keylen,
                         const unsigned char *input, size_t ilen,
                         unsigned char *output );

#if defined(JHD_TLS_AES_C)
/**
 * \brief           This function implements the AES-CMAC-PRF-128 pseudorandom
 *                  function, as defined in
 *                  <em>RFC-4615: The Advanced Encryption Standard-Cipher-based
 *                  Message Authentication Code-Pseudo-Random Function-128
 *                  (AES-CMAC-PRF-128) Algorithm for the Internet Key
 *                  Exchange Protocol (IKE).</em>
 *
 * \param key       The key to use.
 * \param key_len   The key length in Bytes.
 * \param input     The buffer holding the input data.
 * \param in_len    The length of the input data in Bytes.
 * \param output    The buffer holding the generated 16 Bytes of
 *                  pseudorandom output.
 *
 * \return          \c 0 on success.
 */
int jhd_tls_aes_cmac_prf_128( const unsigned char *key, size_t key_len,
                              const unsigned char *input, size_t in_len,
                              unsigned char output[16] );
#endif /* JHD_TLS_AES_C */

#if defined(JHD_TLS_SELF_TEST) && ( defined(JHD_TLS_AES_C) || defined(JHD_TLS_DES_C) )
/**
 * \brief          The CMAC checkup routine.
 *
 * \return         \c 0 on success.
 * \return         \c 1 on failure.
 */
int jhd_tls_cmac_self_test( int verbose );
#endif /* JHD_TLS_SELF_TEST && ( JHD_TLS_AES_C || JHD_TLS_DES_C ) */



#endif /* JHD_TLS_CMAC_H */