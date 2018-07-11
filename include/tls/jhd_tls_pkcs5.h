/**
 * \file pkcs5.h
 *
 * \brief PKCS#5 functions
 *
 * \author Mathias Olsson <mathias@kompetensum.com>
 */
/*
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
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
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
#ifndef JHD_TLS_PKCS5_H
#define JHD_TLS_PKCS5_H

#include <stddef.h>
#include <stdint.h>
#include <tls/jhd_tls_asn1.h>
#include <tls/jhd_tls_md.h>

#define JHD_TLS_ERR_PKCS5_BAD_INPUT_DATA                  -0x2f80  /**< Bad input parameters to function. */
#define JHD_TLS_ERR_PKCS5_INVALID_FORMAT                  -0x2f00  /**< Unexpected ASN.1 data. */
#define JHD_TLS_ERR_PKCS5_FEATURE_UNAVAILABLE             -0x2e80  /**< Requested encryption or digest alg not available. */
#define JHD_TLS_ERR_PKCS5_PASSWORD_MISMATCH               -0x2e00  /**< Given private key password does not allow for correct decryption. */

#define JHD_TLS_PKCS5_DECRYPT      0
#define JHD_TLS_PKCS5_ENCRYPT      1


/**
 * \brief          PKCS#5 PBES2 function
 *
 * \param pbe_params the ASN.1 algorithm parameters
 * \param mode       either JHD_TLS_PKCS5_DECRYPT or JHD_TLS_PKCS5_ENCRYPT
 * \param pwd        password to use when generating key
 * \param pwdlen     length of password
 * \param data       data to process
 * \param datalen    length of data
 * \param output     output buffer
 *
 * \returns        0 on success, or a JHD_TLS_ERR_XXX code if verification fails.
 */
int jhd_tls_pkcs5_pbes2( const jhd_tls_asn1_buf *pbe_params, int mode,
                 const unsigned char *pwd,  size_t pwdlen,
                 const unsigned char *data, size_t datalen,
                 unsigned char *output );

/**
 * \brief          PKCS#5 PBKDF2 using HMAC
 *
 * \param ctx      Generic HMAC context
 * \param password Password to use when generating key
 * \param plen     Length of password
 * \param salt     Salt to use when generating key
 * \param slen     Length of salt
 * \param iteration_count       Iteration count
 * \param key_length            Length of generated key in bytes
 * \param output   Generated key. Must be at least as big as key_length
 *
 * \returns        0 on success, or a JHD_TLS_ERR_XXX code if verification fails.
 */
int jhd_tls_pkcs5_pbkdf2_hmac( jhd_tls_md_context_t *ctx, const unsigned char *password,
                       size_t plen, const unsigned char *salt, size_t slen,
                       unsigned int iteration_count,
                       uint32_t key_length, unsigned char *output );

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
int jhd_tls_pkcs5_self_test( int verbose );


#endif /* pkcs5.h */
