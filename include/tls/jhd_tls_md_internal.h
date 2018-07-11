/**
 * \file md_internal.h
 *
 * \brief Message digest wrappers.
 *
 * \warning This in an internal header. Do not include directly.
 *
 * \author Adriaan de Jong <dejong@fox-it.com>
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
#ifndef JHD_TLS_MD_WRAP_H
#define JHD_TLS_MD_WRAP_H

#if !defined(JHD_TLS_CONFIG_FILE)
#include <tls/jhd_tls_config.h>
#else
#include JHD_TLS_CONFIG_FILE
#endif

#include <tls/jhd_tls_md.h>



/**
 * Message digest information.
 * Allows message digest functions to be called in a generic way.
 */
struct jhd_tls_md_info_t
{
    /** Digest identifier */
    jhd_tls_md_type_t type;

    /** Name of the message digest */
    const char * name;

    /** Output length of the digest function in bytes */
    int size;

    /** Block length of the digest function in bytes */
    int block_size;

    /** Digest initialisation function */
    int (*starts_func)( void *ctx );

    /** Digest update function */
    int (*update_func)( void *ctx, const unsigned char *input, size_t ilen );

    /** Digest finalisation function */
    int (*finish_func)( void *ctx, unsigned char *output );

    /** Generic digest function */
    int (*digest_func)( const unsigned char *input, size_t ilen,
                        unsigned char *output );

    /** Allocate a new context */
    void * (*ctx_alloc_func)( void );

    /** Free the given context */
    void (*ctx_free_func)( void *ctx );

    /** Clone state from a context */
    void (*clone_func)( void *dst, const void *src );

    /** Internal use only */
    int (*process_func)( void *ctx, const unsigned char *input );
};

#if defined(JHD_TLS_MD2_C)
extern const jhd_tls_md_info_t jhd_tls_md2_info;
#endif
#if defined(JHD_TLS_MD4_C)
extern const jhd_tls_md_info_t jhd_tls_md4_info;
#endif
#if defined(JHD_TLS_MD5_C)
extern const jhd_tls_md_info_t jhd_tls_md5_info;
#endif
#if defined(JHD_TLS_RIPEMD160_C)
extern const jhd_tls_md_info_t jhd_tls_ripemd160_info;
#endif
#if defined(JHD_TLS_SHA1_C)
extern const jhd_tls_md_info_t jhd_tls_sha1_info;
#endif
#if defined(JHD_TLS_SHA256_C)
extern const jhd_tls_md_info_t jhd_tls_sha224_info;
extern const jhd_tls_md_info_t jhd_tls_sha256_info;
#endif
#if defined(JHD_TLS_SHA512_C)
extern const jhd_tls_md_info_t jhd_tls_sha384_info;
extern const jhd_tls_md_info_t jhd_tls_sha512_info;
#endif



#endif /* JHD_TLS_MD_WRAP_H */
