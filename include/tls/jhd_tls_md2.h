/**
 * \file md2.h
 *
 * \brief MD2 message digest algorithm (hash function)
 *
 * \warning MD2 is considered a weak message digest and its use constitutes a
 *          security risk. We recommend considering stronger message digests
 *          instead.
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
 *
 */
#ifndef JHD_TLS_MD2_H
#define JHD_TLS_MD2_H

#if !defined(JHD_TLS_CONFIG_FILE)
#include <tls/jhd_tls_config.h>
#else
#include JHD_TLS_CONFIG_FILE
#endif

#include <stddef.h>

#define JHD_TLS_ERR_MD2_HW_ACCEL_FAILED                   -0x002B  /**< MD2 hardware accelerator failed */



#if !defined(JHD_TLS_MD2_ALT)
// Regular implementation
//

/**
 * \brief          MD2 context structure
 *
 * \warning        MD2 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
typedef struct
{
    unsigned char cksum[16];    /*!< checksum of the data block */
    unsigned char state[48];    /*!< intermediate digest state  */
    unsigned char buffer[16];   /*!< data block being processed */
    size_t left;                /*!< amount of data in buffer   */
}
jhd_tls_md2_context;

#else  /* JHD_TLS_MD2_ALT */
#include "md2_alt.h"
#endif /* JHD_TLS_MD2_ALT */

/**
 * \brief          Initialize MD2 context
 *
 * \param ctx      MD2 context to be initialized
 *
 * \warning        MD2 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
void jhd_tls_md2_init( jhd_tls_md2_context *ctx );

/**
 * \brief          Clear MD2 context
 *
 * \param ctx      MD2 context to be cleared
 *
 * \warning        MD2 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
void jhd_tls_md2_free( jhd_tls_md2_context *ctx );

/**
 * \brief          Clone (the state of) an MD2 context
 *
 * \param dst      The destination context
 * \param src      The context to be cloned
 *
 * \warning        MD2 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
void jhd_tls_md2_clone( jhd_tls_md2_context *dst,
                        const jhd_tls_md2_context *src );

/**
 * \brief          MD2 context setup
 *
 * \param ctx      context to be initialized
 *
 * \return         0 if successful
 *
 * \warning        MD2 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
int jhd_tls_md2_starts_ret( jhd_tls_md2_context *ctx );

/**
 * \brief          MD2 process buffer
 *
 * \param ctx      MD2 context
 * \param input    buffer holding the data
 * \param ilen     length of the input data
 *
 * \return         0 if successful
 *
 * \warning        MD2 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
int jhd_tls_md2_update_ret( jhd_tls_md2_context *ctx,
                            const unsigned char *input,
                            size_t ilen );

/**
 * \brief          MD2 final digest
 *
 * \param ctx      MD2 context
 * \param output   MD2 checksum result
 *
 * \return         0 if successful
 *
 * \warning        MD2 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
int jhd_tls_md2_finish_ret( jhd_tls_md2_context *ctx,
                            unsigned char output[16] );

/**
 * \brief          MD2 process data block (internal use only)
 *
 * \param ctx      MD2 context
 *
 * \return         0 if successful
 *
 * \warning        MD2 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
int jhd_tls_internal_md2_process( jhd_tls_md2_context *ctx );

#if !defined(JHD_TLS_DEPRECATED_REMOVED)
#if defined(JHD_TLS_DEPRECATED_WARNING)
#define JHD_TLS_DEPRECATED      __attribute__((deprecated))
#else
#define JHD_TLS_DEPRECATED
#endif
/**
 * \brief          MD2 context setup
 *
 * \deprecated     Superseded by jhd_tls_md2_starts_ret() in 2.7.0
 *
 * \param ctx      context to be initialized
 *
 * \warning        MD2 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
JHD_TLS_DEPRECATED void jhd_tls_md2_starts( jhd_tls_md2_context *ctx );

/**
 * \brief          MD2 process buffer
 *
 * \deprecated     Superseded by jhd_tls_md2_update_ret() in 2.7.0
 *
 * \param ctx      MD2 context
 * \param input    buffer holding the data
 * \param ilen     length of the input data
 *
 * \warning        MD2 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
JHD_TLS_DEPRECATED void jhd_tls_md2_update( jhd_tls_md2_context *ctx,
                                            const unsigned char *input,
                                            size_t ilen );

/**
 * \brief          MD2 final digest
 *
 * \deprecated     Superseded by jhd_tls_md2_finish_ret() in 2.7.0
 *
 * \param ctx      MD2 context
 * \param output   MD2 checksum result
 *
 * \warning        MD2 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
JHD_TLS_DEPRECATED void jhd_tls_md2_finish( jhd_tls_md2_context *ctx,
                                            unsigned char output[16] );

/**
 * \brief          MD2 process data block (internal use only)
 *
 * \deprecated     Superseded by jhd_tls_internal_md2_process() in 2.7.0
 *
 * \param ctx      MD2 context
 *
 * \warning        MD2 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
JHD_TLS_DEPRECATED void jhd_tls_md2_process( jhd_tls_md2_context *ctx );

#undef JHD_TLS_DEPRECATED
#endif /* !JHD_TLS_DEPRECATED_REMOVED */

/**
 * \brief          Output = MD2( input buffer )
 *
 * \param input    buffer holding the data
 * \param ilen     length of the input data
 * \param output   MD2 checksum result
 *
 * \warning        MD2 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
int jhd_tls_md2_ret( const unsigned char *input,
                     size_t ilen,
                     unsigned char output[16] );

#if !defined(JHD_TLS_DEPRECATED_REMOVED)
#if defined(JHD_TLS_DEPRECATED_WARNING)
#define JHD_TLS_DEPRECATED      __attribute__((deprecated))
#else
#define JHD_TLS_DEPRECATED
#endif
/**
 * \brief          Output = MD2( input buffer )
 *
 * \deprecated     Superseded by jhd_tls_md2_ret() in 2.7.0
 *
 * \param input    buffer holding the data
 * \param ilen     length of the input data
 * \param output   MD2 checksum result
 *
 * \warning        MD2 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
JHD_TLS_DEPRECATED void jhd_tls_md2( const unsigned char *input,
                                     size_t ilen,
                                     unsigned char output[16] );

#undef JHD_TLS_DEPRECATED
#endif /* !JHD_TLS_DEPRECATED_REMOVED */

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 *
 * \warning        MD2 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
int jhd_tls_md2_self_test( int verbose );



#endif /* jhd_tls_md2.h */
