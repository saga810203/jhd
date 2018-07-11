/**
 * \file ripemd160.h
 *
 * \brief RIPE MD-160 message digest
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
#ifndef JHD_TLS_RIPEMD160_H
#define JHD_TLS_RIPEMD160_H

#if !defined(JHD_TLS_CONFIG_FILE)
#include <tls/jhd_tls_config.h>
#else
#include JHD_TLS_CONFIG_FILE
#endif

#include <stddef.h>
#include <stdint.h>

#define JHD_TLS_ERR_RIPEMD160_HW_ACCEL_FAILED             -0x0031  /**< RIPEMD160 hardware accelerator failed */

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(JHD_TLS_RIPEMD160_ALT)
// Regular implementation
//

/**
 * \brief          RIPEMD-160 context structure
 */
typedef struct
{
    uint32_t total[2];          /*!< number of bytes processed  */
    uint32_t state[5];          /*!< intermediate digest state  */
    unsigned char buffer[64];   /*!< data block being processed */
}
jhd_tls_ripemd160_context;

#else  /* JHD_TLS_RIPEMD160_ALT */
#include <tls/jhd_tls_ripemd160.h>
#endif /* JHD_TLS_RIPEMD160_ALT */

/**
 * \brief          Initialize RIPEMD-160 context
 *
 * \param ctx      RIPEMD-160 context to be initialized
 */
void jhd_tls_ripemd160_init( jhd_tls_ripemd160_context *ctx );

/**
 * \brief          Clear RIPEMD-160 context
 *
 * \param ctx      RIPEMD-160 context to be cleared
 */
void jhd_tls_ripemd160_free( jhd_tls_ripemd160_context *ctx );

/**
 * \brief          Clone (the state of) an RIPEMD-160 context
 *
 * \param dst      The destination context
 * \param src      The context to be cloned
 */
void jhd_tls_ripemd160_clone( jhd_tls_ripemd160_context *dst,
                        const jhd_tls_ripemd160_context *src );

/**
 * \brief          RIPEMD-160 context setup
 *
 * \param ctx      context to be initialized
 *
 * \return         0 if successful
 */
int jhd_tls_ripemd160_starts_ret( jhd_tls_ripemd160_context *ctx );

/**
 * \brief          RIPEMD-160 process buffer
 *
 * \param ctx      RIPEMD-160 context
 * \param input    buffer holding the data
 * \param ilen     length of the input data
 *
 * \return         0 if successful
 */
int jhd_tls_ripemd160_update_ret( jhd_tls_ripemd160_context *ctx,
                                  const unsigned char *input,
                                  size_t ilen );

/**
 * \brief          RIPEMD-160 final digest
 *
 * \param ctx      RIPEMD-160 context
 * \param output   RIPEMD-160 checksum result
 *
 * \return         0 if successful
 */
int jhd_tls_ripemd160_finish_ret( jhd_tls_ripemd160_context *ctx,
                                  unsigned char output[20] );

/**
 * \brief          RIPEMD-160 process data block (internal use only)
 *
 * \param ctx      RIPEMD-160 context
 * \param data     buffer holding one block of data
 *
 * \return         0 if successful
 */
int jhd_tls_internal_ripemd160_process( jhd_tls_ripemd160_context *ctx,
                                        const unsigned char data[64] );

#if !defined(JHD_TLS_DEPRECATED_REMOVED)
#if defined(JHD_TLS_DEPRECATED_WARNING)
#define JHD_TLS_DEPRECATED      __attribute__((deprecated))
#else
#define JHD_TLS_DEPRECATED
#endif
/**
 * \brief          RIPEMD-160 context setup
 *
 * \deprecated     Superseded by jhd_tls_ripemd160_starts_ret() in 2.7.0
 *
 * \param ctx      context to be initialized
 */
JHD_TLS_DEPRECATED void jhd_tls_ripemd160_starts(
                                            jhd_tls_ripemd160_context *ctx );

/**
 * \brief          RIPEMD-160 process buffer
 *
 * \deprecated     Superseded by jhd_tls_ripemd160_update_ret() in 2.7.0
 *
 * \param ctx      RIPEMD-160 context
 * \param input    buffer holding the data
 * \param ilen     length of the input data
 */
JHD_TLS_DEPRECATED void jhd_tls_ripemd160_update(
                                                jhd_tls_ripemd160_context *ctx,
                                                const unsigned char *input,
                                                size_t ilen );

/**
 * \brief          RIPEMD-160 final digest
 *
 * \deprecated     Superseded by jhd_tls_ripemd160_finish_ret() in 2.7.0
 *
 * \param ctx      RIPEMD-160 context
 * \param output   RIPEMD-160 checksum result
 */
JHD_TLS_DEPRECATED void jhd_tls_ripemd160_finish(
                                                jhd_tls_ripemd160_context *ctx,
                                                unsigned char output[20] );

/**
 * \brief          RIPEMD-160 process data block (internal use only)
 *
 * \deprecated     Superseded by jhd_tls_internal_ripemd160_process() in 2.7.0
 *
 * \param ctx      RIPEMD-160 context
 * \param data     buffer holding one block of data
 */
JHD_TLS_DEPRECATED void jhd_tls_ripemd160_process(
                                            jhd_tls_ripemd160_context *ctx,
                                            const unsigned char data[64] );

#undef JHD_TLS_DEPRECATED
#endif /* !JHD_TLS_DEPRECATED_REMOVED */

/**
 * \brief          Output = RIPEMD-160( input buffer )
 *
 * \param input    buffer holding the data
 * \param ilen     length of the input data
 * \param output   RIPEMD-160 checksum result
 *
 * \return         0 if successful
 */
int jhd_tls_ripemd160_ret( const unsigned char *input,
                           size_t ilen,
                           unsigned char output[20] );

#if !defined(JHD_TLS_DEPRECATED_REMOVED)
#if defined(JHD_TLS_DEPRECATED_WARNING)
#define JHD_TLS_DEPRECATED      __attribute__((deprecated))
#else
#define JHD_TLS_DEPRECATED
#endif
/**
 * \brief          Output = RIPEMD-160( input buffer )
 *
 * \deprecated     Superseded by jhd_tls_ripemd160_ret() in 2.7.0
 *
 * \param input    buffer holding the data
 * \param ilen     length of the input data
 * \param output   RIPEMD-160 checksum result
 */
JHD_TLS_DEPRECATED void jhd_tls_ripemd160( const unsigned char *input,
                                           size_t ilen,
                                           unsigned char output[20] );

#undef JHD_TLS_DEPRECATED
#endif /* !JHD_TLS_DEPRECATED_REMOVED */

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
int jhd_tls_ripemd160_self_test( int verbose );

#ifdef __cplusplus
}
#endif

#endif /* jhd_tls_ripemd160.h */
