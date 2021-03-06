/**
 * \file pem.h
 *
 * \brief Privacy Enhanced Mail (PEM) decoding
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
#ifndef JHD_TLS_PEM_H
#define JHD_TLS_PEM_H

#include <stddef.h>

/**
 * \name PEM Error codes
 * These error codes are returned in case of errors reading the
 * PEM data.
 * \{
 */
#define JHD_TLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT          -0x1080  /**< No PEM header or footer found. */
#define JHD_TLS_ERR_PEM_INVALID_DATA                      -0x1100  /**< PEM string is not as expected. */
#define JHD_TLS_ERR_PEM_ALLOC_FAILED                      -0x1180  /**< Failed to allocate memory. */
#define JHD_TLS_ERR_PEM_INVALID_ENC_IV                    -0x1200  /**< RSA IV is not in hex-format. */
#define JHD_TLS_ERR_PEM_UNKNOWN_ENC_ALG                   -0x1280  /**< Unsupported key encryption algorithm. */
#define JHD_TLS_ERR_PEM_PASSWORD_REQUIRED                 -0x1300  /**< Private key password can't be empty. */
#define JHD_TLS_ERR_PEM_PASSWORD_MISMATCH                 -0x1380  /**< Given private key password does not allow for correct decryption. */
#define JHD_TLS_ERR_PEM_FEATURE_UNAVAILABLE               -0x1400  /**< Unavailable feature, e.g. hashing/encryption combination. */
#define JHD_TLS_ERR_PEM_BAD_INPUT_DATA                    -0x1480  /**< Bad input parameters to function. */
/* \} name */



/**
 * \brief       PEM context structure
 */
typedef struct
{
    unsigned char *buf;     /*!< buffer for decoded data             */
    size_t buflen;          /*!< length of the buffer                */
    unsigned char *info;    /*!< buffer for extra header information */
}
jhd_tls_pem_context;

#if !defined(JHD_TLS_INLINE)
/**
 * \brief       PEM context setup
 *
 * \param ctx   context to be initialized
 */
void jhd_tls_pem_init( jhd_tls_pem_context *ctx );
#else
#define jhd_tls_pem_init(ctx) 	memset(ctx, 0, sizeof(jhd_tls_pem_context))
#endif



int jhd_tls_pem_read_buffer(unsigned char *buf, size_t *buf_len, const char *header, const char *footer,const unsigned char *data,size_t *use_len);


/**
 * \brief       PEM context memory freeing
 *
 * \param ctx   context to be freed
 */
void jhd_tls_pem_free( jhd_tls_pem_context *ctx );



/**
 * \brief           Write a buffer of PEM information from a DER encoded
 *                  buffer.
 *
 * \param header    header string to write
 * \param footer    footer string to write
 * \param der_data  DER data to write
 * \param der_len   length of the DER data
 * \param buf       buffer to write to
 * \param buf_len   length of output buffer
 * \param olen      total length written / required (if buf_len is not enough)
 *
 * \return          0 on success, or a specific PEM or BASE64 error code. On
 *                  JHD_TLS_ERR_BASE64_BUFFER_TOO_SMALL olen is the required
 *                  size.
 */
int jhd_tls_pem_write_buffer( const char *header, const char *footer,
                      const unsigned char *der_data, size_t der_len,
                      unsigned char *buf, size_t buf_len, size_t *olen );




#endif /* pem.h */
