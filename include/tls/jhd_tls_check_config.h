/**
 * \file check_config.h
 *
 * \brief Consistency checks for configuration options
 */
/*
 *  Copyright (C) 2006-2018, ARM Limited, All Rights Reserved
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

/*
 * It is recommended to include this file from your config.h
 * in order to catch dependency issues early.
 */

#ifndef JHD_TLS_CHECK_CONFIG_H
#define JHD_TLS_CHECK_CONFIG_H

/*
 * We assume CHAR_BIT is 8 in many places. In practice, this is true on our
 * target platforms, so not an issue, but let's just be extra sure.
 */
#include <limits.h>
#if CHAR_BIT != 8
#error "mbed TLS requires a platform with 8-bit chars"
#endif

#if defined(_WIN32)
#if !defined(JHD_TLS_PLATFORM_C)
#error "JHD_TLS_PLATFORM_C is required on Windows"
#endif

/* Fix the config here. Not convenient to put an #ifdef _WIN32 in config.h as
 * it would confuse config.pl. */
#if !defined(JHD_TLS_PLATFORM_SNPRINTF_ALT) && \
    !defined(JHD_TLS_PLATFORM_SNPRINTF_MACRO)
#define JHD_TLS_PLATFORM_SNPRINTF_ALT
#endif
#endif /* _WIN32 */

#if defined(TARGET_LIKE_MBED) && \
    ( defined(JHD_TLS_NET_C) || defined(JHD_TLS_TIMING_C) )
#error "The NET and TIMING modules are not available for mbed OS - please use the network and timing functions provided by mbed OS"
#endif

#if defined(JHD_TLS_DEPRECATED_WARNING) && \
    !defined(__GNUC__) && !defined(__clang__)
#error "JHD_TLS_DEPRECATED_WARNING only works with GCC and Clang"
#endif

#if defined(JHD_TLS_HAVE_TIME_DATE) && !defined(JHD_TLS_HAVE_TIME)
#error "JHD_TLS_HAVE_TIME_DATE without JHD_TLS_HAVE_TIME does not make sense"
#endif

#if defined(JHD_TLS_AESNI_C) && !defined(JHD_TLS_HAVE_ASM)
#error "JHD_TLS_AESNI_C defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_CTR_DRBG_C) && !defined(JHD_TLS_AES_C)
#error "JHD_TLS_CTR_DRBG_C defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_DHM_C) && !defined(JHD_TLS_BIGNUM_C)
#error "JHD_TLS_DHM_C defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_SSL_TRUNCATED_HMAC_COMPAT) && !defined(JHD_TLS_SSL_TRUNCATED_HMAC)
#error "JHD_TLS_SSL_TRUNCATED_HMAC_COMPAT defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_CMAC_C) && \
    !defined(JHD_TLS_AES_C) && !defined(JHD_TLS_DES_C)
#error "JHD_TLS_CMAC_C defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_ECDH_C) && !defined(JHD_TLS_ECP_C)
#error "JHD_TLS_ECDH_C defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_ECDSA_C) &&            \
    ( !defined(JHD_TLS_ECP_C) ||           \
      !defined(JHD_TLS_ASN1_PARSE_C) ||    \
      !defined(JHD_TLS_ASN1_WRITE_C) )
#error "JHD_TLS_ECDSA_C defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_ECJPAKE_C) &&           \
    ( !defined(JHD_TLS_ECP_C) || !defined(JHD_TLS_MD_C) )
#error "JHD_TLS_ECJPAKE_C defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_ECDSA_DETERMINISTIC) && !defined(JHD_TLS_HMAC_DRBG_C)
#error "JHD_TLS_ECDSA_DETERMINISTIC defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_ECP_C) && ( !defined(JHD_TLS_BIGNUM_C) || (   \
    !defined(JHD_TLS_ECP_DP_SECP192R1_ENABLED) &&                  \
    !defined(JHD_TLS_ECP_DP_SECP224R1_ENABLED) &&                  \
    !defined(JHD_TLS_ECP_DP_SECP256R1_ENABLED) &&                  \
    !defined(JHD_TLS_ECP_DP_SECP384R1_ENABLED) &&                  \
    !defined(JHD_TLS_ECP_DP_SECP521R1_ENABLED) &&                  \
    !defined(JHD_TLS_ECP_DP_BP256R1_ENABLED)   &&                  \
    !defined(JHD_TLS_ECP_DP_BP384R1_ENABLED)   &&                  \
    !defined(JHD_TLS_ECP_DP_BP512R1_ENABLED)   &&                  \
    !defined(JHD_TLS_ECP_DP_SECP192K1_ENABLED) &&                  \
    !defined(JHD_TLS_ECP_DP_SECP224K1_ENABLED) &&                  \
    !defined(JHD_TLS_ECP_DP_SECP256K1_ENABLED) ) )
#error "JHD_TLS_ECP_C defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_ENTROPY_C) && (!defined(JHD_TLS_SHA512_C) &&      \
                                    !defined(JHD_TLS_SHA256_C))
#error "JHD_TLS_ENTROPY_C defined, but not all prerequisites"
#endif
#if defined(JHD_TLS_ENTROPY_C) && defined(JHD_TLS_SHA512_C) &&         \
    defined(JHD_TLS_CTR_DRBG_ENTROPY_LEN) && (JHD_TLS_CTR_DRBG_ENTROPY_LEN > 64)
#error "JHD_TLS_CTR_DRBG_ENTROPY_LEN value too high"
#endif
#if defined(JHD_TLS_ENTROPY_C) &&                                            \
    ( !defined(JHD_TLS_SHA512_C) || defined(JHD_TLS_ENTROPY_FORCE_SHA256) ) \
    && defined(JHD_TLS_CTR_DRBG_ENTROPY_LEN) && (JHD_TLS_CTR_DRBG_ENTROPY_LEN > 32)
#error "JHD_TLS_CTR_DRBG_ENTROPY_LEN value too high"
#endif
#if defined(JHD_TLS_ENTROPY_C) && \
    defined(JHD_TLS_ENTROPY_FORCE_SHA256) && !defined(JHD_TLS_SHA256_C)
#error "JHD_TLS_ENTROPY_FORCE_SHA256 defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_TEST_NULL_ENTROPY) && \
    ( !defined(JHD_TLS_ENTROPY_C) || !defined(JHD_TLS_NO_DEFAULT_ENTROPY_SOURCES) )
#error "JHD_TLS_TEST_NULL_ENTROPY defined, but not all prerequisites"
#endif
#if defined(JHD_TLS_TEST_NULL_ENTROPY) && \
     ( defined(JHD_TLS_ENTROPY_NV_SEED) || defined(JHD_TLS_ENTROPY_HARDWARE_ALT) || \
    defined(JHD_TLS_HAVEGE_C) )
#error "JHD_TLS_TEST_NULL_ENTROPY defined, but entropy sources too"
#endif

#if defined(JHD_TLS_GCM_C) && (                                        \
        !defined(JHD_TLS_AES_C) && !defined(JHD_TLS_CAMELLIA_C) )
#error "JHD_TLS_GCM_C defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_ECP_RANDOMIZE_JAC_ALT) && !defined(JHD_TLS_ECP_INTERNAL_ALT)
#error "JHD_TLS_ECP_RANDOMIZE_JAC_ALT defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_ECP_ADD_MIXED_ALT) && !defined(JHD_TLS_ECP_INTERNAL_ALT)
#error "JHD_TLS_ECP_ADD_MIXED_ALT defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_ECP_DOUBLE_JAC_ALT) && !defined(JHD_TLS_ECP_INTERNAL_ALT)
#error "JHD_TLS_ECP_DOUBLE_JAC_ALT defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_ECP_NORMALIZE_JAC_MANY_ALT) && !defined(JHD_TLS_ECP_INTERNAL_ALT)
#error "JHD_TLS_ECP_NORMALIZE_JAC_MANY_ALT defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_ECP_NORMALIZE_JAC_ALT) && !defined(JHD_TLS_ECP_INTERNAL_ALT)
#error "JHD_TLS_ECP_NORMALIZE_JAC_ALT defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_ECP_DOUBLE_ADD_MXZ_ALT) && !defined(JHD_TLS_ECP_INTERNAL_ALT)
#error "JHD_TLS_ECP_DOUBLE_ADD_MXZ_ALT defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_ECP_RANDOMIZE_MXZ_ALT) && !defined(JHD_TLS_ECP_INTERNAL_ALT)
#error "JHD_TLS_ECP_RANDOMIZE_MXZ_ALT defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_ECP_NORMALIZE_MXZ_ALT) && !defined(JHD_TLS_ECP_INTERNAL_ALT)
#error "JHD_TLS_ECP_NORMALIZE_MXZ_ALT defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_HAVEGE_C) && !defined(JHD_TLS_TIMING_C)
#error "JHD_TLS_HAVEGE_C defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_HKDF_C) && !defined(JHD_TLS_MD_C)
#error "JHD_TLS_HKDF_C defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_HMAC_DRBG_C) && !defined(JHD_TLS_MD_C)
#error "JHD_TLS_HMAC_DRBG_C defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED) &&                 \
    ( !defined(JHD_TLS_ECDH_C) || !defined(JHD_TLS_X509_CRT_PARSE_C) )
#error "JHD_TLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_KEY_EXCHANGE_ECDH_RSA_ENABLED) &&                 \
    ( !defined(JHD_TLS_ECDH_C) || !defined(JHD_TLS_X509_CRT_PARSE_C) )
#error "JHD_TLS_KEY_EXCHANGE_ECDH_RSA_ENABLED defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_KEY_EXCHANGE_DHE_PSK_ENABLED) && !defined(JHD_TLS_DHM_C)
#error "JHD_TLS_KEY_EXCHANGE_DHE_PSK_ENABLED defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED) &&                     \
    !defined(JHD_TLS_ECDH_C)
#error "JHD_TLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_KEY_EXCHANGE_DHE_RSA_ENABLED) &&                   \
    ( !defined(JHD_TLS_DHM_C) || !defined(JHD_TLS_RSA_C) ||           \
      !defined(JHD_TLS_X509_CRT_PARSE_C) || !defined(JHD_TLS_PKCS1_V15) )
#error "JHD_TLS_KEY_EXCHANGE_DHE_RSA_ENABLED defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED) &&                 \
    ( !defined(JHD_TLS_ECDH_C) || !defined(JHD_TLS_RSA_C) ||          \
      !defined(JHD_TLS_X509_CRT_PARSE_C) || !defined(JHD_TLS_PKCS1_V15) )
#error "JHD_TLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED) &&                 \
    ( !defined(JHD_TLS_ECDH_C) || !defined(JHD_TLS_ECDSA_C) ||          \
      !defined(JHD_TLS_X509_CRT_PARSE_C) )
#error "JHD_TLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_KEY_EXCHANGE_RSA_PSK_ENABLED) &&                   \
    ( !defined(JHD_TLS_RSA_C) || !defined(JHD_TLS_X509_CRT_PARSE_C) || \
      !defined(JHD_TLS_PKCS1_V15) )
#error "JHD_TLS_KEY_EXCHANGE_RSA_PSK_ENABLED defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_KEY_EXCHANGE_RSA_ENABLED) &&                       \
    ( !defined(JHD_TLS_RSA_C) || !defined(JHD_TLS_X509_CRT_PARSE_C) || \
      !defined(JHD_TLS_PKCS1_V15) )
#error "JHD_TLS_KEY_EXCHANGE_RSA_ENABLED defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_KEY_EXCHANGE_ECJPAKE_ENABLED) &&                    \
    ( !defined(JHD_TLS_ECJPAKE_C) || !defined(JHD_TLS_SHA256_C) ||      \
      !defined(JHD_TLS_ECP_DP_SECP256R1_ENABLED) )
#error "JHD_TLS_KEY_EXCHANGE_ECJPAKE_ENABLED defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_MEMORY_BUFFER_ALLOC_C) &&                          \
    ( !defined(JHD_TLS_PLATFORM_C) || !defined(JHD_TLS_PLATFORM_MEMORY) )
#error "JHD_TLS_MEMORY_BUFFER_ALLOC_C defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_PADLOCK_C) && !defined(JHD_TLS_HAVE_ASM)
#error "JHD_TLS_PADLOCK_C defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_PEM_PARSE_C) && !defined(JHD_TLS_BASE64_C)
#error "JHD_TLS_PEM_PARSE_C defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_PEM_WRITE_C) && !defined(JHD_TLS_BASE64_C)
#error "JHD_TLS_PEM_WRITE_C defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_PK_C) && \
    ( !defined(JHD_TLS_RSA_C) && !defined(JHD_TLS_ECP_C) )
#error "JHD_TLS_PK_C defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_PK_PARSE_C) && !defined(JHD_TLS_PK_C)
#error "JHD_TLS_PK_PARSE_C defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_PK_WRITE_C) && !defined(JHD_TLS_PK_C)
#error "JHD_TLS_PK_WRITE_C defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_PKCS11_C) && !defined(JHD_TLS_PK_C)
#error "JHD_TLS_PKCS11_C defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_PLATFORM_EXIT_ALT) && !defined(JHD_TLS_PLATFORM_C)
#error "JHD_TLS_PLATFORM_EXIT_ALT defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_PLATFORM_EXIT_MACRO) && !defined(JHD_TLS_PLATFORM_C)
#error "JHD_TLS_PLATFORM_EXIT_MACRO defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_PLATFORM_EXIT_MACRO) &&\
    ( defined(JHD_TLS_PLATFORM_STD_EXIT) ||\
        defined(JHD_TLS_PLATFORM_EXIT_ALT) )
#error "JHD_TLS_PLATFORM_EXIT_MACRO and JHD_TLS_PLATFORM_STD_EXIT/JHD_TLS_PLATFORM_EXIT_ALT cannot be defined simultaneously"
#endif

#if defined(JHD_TLS_PLATFORM_TIME_ALT) &&\
    ( !defined(JHD_TLS_PLATFORM_C) ||\
        !defined(JHD_TLS_HAVE_TIME) )
#error "JHD_TLS_PLATFORM_TIME_ALT defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_PLATFORM_TIME_MACRO) &&\
    ( !defined(JHD_TLS_PLATFORM_C) ||\
        !defined(JHD_TLS_HAVE_TIME) )
#error "JHD_TLS_PLATFORM_TIME_MACRO defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_PLATFORM_TIME_TYPE_MACRO) &&\
    ( !defined(JHD_TLS_PLATFORM_C) ||\
        !defined(JHD_TLS_HAVE_TIME) )
#error "JHD_TLS_PLATFORM_TIME_TYPE_MACRO defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_PLATFORM_TIME_MACRO) &&\
    ( defined(JHD_TLS_PLATFORM_STD_TIME) ||\
        defined(JHD_TLS_PLATFORM_TIME_ALT) )
#error "JHD_TLS_PLATFORM_TIME_MACRO and JHD_TLS_PLATFORM_STD_TIME/JHD_TLS_PLATFORM_TIME_ALT cannot be defined simultaneously"
#endif

#if defined(JHD_TLS_PLATFORM_TIME_TYPE_MACRO) &&\
    ( defined(JHD_TLS_PLATFORM_STD_TIME) ||\
        defined(JHD_TLS_PLATFORM_TIME_ALT) )
#error "JHD_TLS_PLATFORM_TIME_TYPE_MACRO and JHD_TLS_PLATFORM_STD_TIME/JHD_TLS_PLATFORM_TIME_ALT cannot be defined simultaneously"
#endif

#if defined(JHD_TLS_PLATFORM_FPRINTF_ALT) && !defined(JHD_TLS_PLATFORM_C)
#error "JHD_TLS_PLATFORM_FPRINTF_ALT defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_PLATFORM_FPRINTF_MACRO) && !defined(JHD_TLS_PLATFORM_C)
#error "JHD_TLS_PLATFORM_FPRINTF_MACRO defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_PLATFORM_FPRINTF_MACRO) &&\
    ( defined(JHD_TLS_PLATFORM_STD_FPRINTF) ||\
        defined(JHD_TLS_PLATFORM_FPRINTF_ALT) )
#error "JHD_TLS_PLATFORM_FPRINTF_MACRO and JHD_TLS_PLATFORM_STD_FPRINTF/JHD_TLS_PLATFORM_FPRINTF_ALT cannot be defined simultaneously"
#endif

#if defined(JHD_TLS_PLATFORM_FREE_MACRO) &&\
    ( !defined(JHD_TLS_PLATFORM_C) || !defined(JHD_TLS_PLATFORM_MEMORY) )
#error "JHD_TLS_PLATFORM_FREE_MACRO defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_PLATFORM_FREE_MACRO) &&\
    defined(JHD_TLS_PLATFORM_STD_FREE)
#error "JHD_TLS_PLATFORM_FREE_MACRO and JHD_TLS_PLATFORM_STD_FREE cannot be defined simultaneously"
#endif

#if defined(JHD_TLS_PLATFORM_FREE_MACRO) && !defined(JHD_TLS_PLATFORM_CALLOC_MACRO)
#error "JHD_TLS_PLATFORM_CALLOC_MACRO must be defined if JHD_TLS_PLATFORM_FREE_MACRO is"
#endif

#if defined(JHD_TLS_PLATFORM_CALLOC_MACRO) &&\
    ( !defined(JHD_TLS_PLATFORM_C) || !defined(JHD_TLS_PLATFORM_MEMORY) )
#error "JHD_TLS_PLATFORM_CALLOC_MACRO defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_PLATFORM_CALLOC_MACRO) &&\
    defined(JHD_TLS_PLATFORM_STD_CALLOC)
#error "JHD_TLS_PLATFORM_CALLOC_MACRO and JHD_TLS_PLATFORM_STD_CALLOC cannot be defined simultaneously"
#endif

#if defined(JHD_TLS_PLATFORM_CALLOC_MACRO) && !defined(JHD_TLS_PLATFORM_FREE_MACRO)
#error "JHD_TLS_PLATFORM_FREE_MACRO must be defined if JHD_TLS_PLATFORM_CALLOC_MACRO is"
#endif

#if defined(JHD_TLS_PLATFORM_MEMORY) && !defined(JHD_TLS_PLATFORM_C)
#error "JHD_TLS_PLATFORM_MEMORY defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_PLATFORM_PRINTF_ALT) && !defined(JHD_TLS_PLATFORM_C)
#error "JHD_TLS_PLATFORM_PRINTF_ALT defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_PLATFORM_PRINTF_MACRO) && !defined(JHD_TLS_PLATFORM_C)
#error "JHD_TLS_PLATFORM_PRINTF_MACRO defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_PLATFORM_PRINTF_MACRO) &&\
    ( defined(JHD_TLS_PLATFORM_STD_PRINTF) ||\
        defined(JHD_TLS_PLATFORM_PRINTF_ALT) )
#error "JHD_TLS_PLATFORM_PRINTF_MACRO and JHD_TLS_PLATFORM_STD_PRINTF/JHD_TLS_PLATFORM_PRINTF_ALT cannot be defined simultaneously"
#endif

#if defined(JHD_TLS_PLATFORM_SNPRINTF_ALT) && !defined(JHD_TLS_PLATFORM_C)
#error "JHD_TLS_PLATFORM_SNPRINTF_ALT defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_PLATFORM_SNPRINTF_MACRO) && !defined(JHD_TLS_PLATFORM_C)
#error "JHD_TLS_PLATFORM_SNPRINTF_MACRO defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_PLATFORM_SNPRINTF_MACRO) &&\
    ( defined(JHD_TLS_PLATFORM_STD_SNPRINTF) ||\
        defined(JHD_TLS_PLATFORM_SNPRINTF_ALT) )
#error "JHD_TLS_PLATFORM_SNPRINTF_MACRO and JHD_TLS_PLATFORM_STD_SNPRINTF/JHD_TLS_PLATFORM_SNPRINTF_ALT cannot be defined simultaneously"
#endif

#if defined(JHD_TLS_PLATFORM_STD_MEM_HDR) &&\
    !defined(JHD_TLS_PLATFORM_NO_STD_FUNCTIONS)
#error "JHD_TLS_PLATFORM_STD_MEM_HDR defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_PLATFORM_STD_CALLOC) && !defined(JHD_TLS_PLATFORM_MEMORY)
#error "JHD_TLS_PLATFORM_STD_CALLOC defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_PLATFORM_STD_CALLOC) && !defined(JHD_TLS_PLATFORM_MEMORY)
#error "JHD_TLS_PLATFORM_STD_CALLOC defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_PLATFORM_STD_FREE) && !defined(JHD_TLS_PLATFORM_MEMORY)
#error "JHD_TLS_PLATFORM_STD_FREE defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_PLATFORM_STD_EXIT) &&\
    !defined(JHD_TLS_PLATFORM_EXIT_ALT)
#error "JHD_TLS_PLATFORM_STD_EXIT defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_PLATFORM_STD_TIME) &&\
    ( !defined(JHD_TLS_PLATFORM_TIME_ALT) ||\
        !defined(JHD_TLS_HAVE_TIME) )
#error "JHD_TLS_PLATFORM_STD_TIME defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_PLATFORM_STD_FPRINTF) &&\
    !defined(JHD_TLS_PLATFORM_FPRINTF_ALT)
#error "JHD_TLS_PLATFORM_STD_FPRINTF defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_PLATFORM_STD_PRINTF) &&\
    !defined(JHD_TLS_PLATFORM_PRINTF_ALT)
#error "JHD_TLS_PLATFORM_STD_PRINTF defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_PLATFORM_STD_SNPRINTF) &&\
    !defined(JHD_TLS_PLATFORM_SNPRINTF_ALT)
#error "JHD_TLS_PLATFORM_STD_SNPRINTF defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_ENTROPY_NV_SEED) &&\
    ( !defined(JHD_TLS_PLATFORM_C) || !defined(JHD_TLS_ENTROPY_C) )
#error "JHD_TLS_ENTROPY_NV_SEED defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_PLATFORM_NV_SEED_ALT) &&\
    !defined(JHD_TLS_ENTROPY_NV_SEED)
#error "JHD_TLS_PLATFORM_NV_SEED_ALT defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_PLATFORM_STD_NV_SEED_READ) &&\
    !defined(JHD_TLS_PLATFORM_NV_SEED_ALT)
#error "JHD_TLS_PLATFORM_STD_NV_SEED_READ defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_PLATFORM_STD_NV_SEED_WRITE) &&\
    !defined(JHD_TLS_PLATFORM_NV_SEED_ALT)
#error "JHD_TLS_PLATFORM_STD_NV_SEED_WRITE defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_PLATFORM_NV_SEED_READ_MACRO) &&\
    ( defined(JHD_TLS_PLATFORM_STD_NV_SEED_READ) ||\
      defined(JHD_TLS_PLATFORM_NV_SEED_ALT) )
#error "JHD_TLS_PLATFORM_NV_SEED_READ_MACRO and JHD_TLS_PLATFORM_STD_NV_SEED_READ cannot be defined simultaneously"
#endif

#if defined(JHD_TLS_PLATFORM_NV_SEED_WRITE_MACRO) &&\
    ( defined(JHD_TLS_PLATFORM_STD_NV_SEED_WRITE) ||\
      defined(JHD_TLS_PLATFORM_NV_SEED_ALT) )
#error "JHD_TLS_PLATFORM_NV_SEED_WRITE_MACRO and JHD_TLS_PLATFORM_STD_NV_SEED_WRITE cannot be defined simultaneously"
#endif

#if defined(JHD_TLS_RSA_C) && ( !defined(JHD_TLS_BIGNUM_C) ||         \
    !defined(JHD_TLS_OID_C) )
#error "JHD_TLS_RSA_C defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_RSA_C) && ( !defined(JHD_TLS_PKCS1_V21) &&         \
    !defined(JHD_TLS_PKCS1_V15) )
#error "JHD_TLS_RSA_C defined, but none of the PKCS1 versions enabled"
#endif

#if defined(JHD_TLS_X509_RSASSA_PSS_SUPPORT) &&                        \
    ( !defined(JHD_TLS_RSA_C) || !defined(JHD_TLS_PKCS1_V21) )
#error "JHD_TLS_X509_RSASSA_PSS_SUPPORT defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_SSL_PROTO_SSL3) && ( !defined(JHD_TLS_MD5_C) ||     \
    !defined(JHD_TLS_SHA1_C) )
#error "JHD_TLS_SSL_PROTO_SSL3 defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_SSL_PROTO_TLS1) && ( !defined(JHD_TLS_MD5_C) ||     \
    !defined(JHD_TLS_SHA1_C) )
#error "JHD_TLS_SSL_PROTO_TLS1 defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_SSL_PROTO_TLS1_1) && ( !defined(JHD_TLS_MD5_C) ||     \
    !defined(JHD_TLS_SHA1_C) )
#error "JHD_TLS_SSL_PROTO_TLS1_1 defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_SSL_PROTO_TLS1_2) && ( !defined(JHD_TLS_SHA1_C) &&     \
    !defined(JHD_TLS_SHA256_C) && !defined(JHD_TLS_SHA512_C) )
#error "JHD_TLS_SSL_PROTO_TLS1_2 defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_SSL_PROTO_DTLS)     && \
    !defined(JHD_TLS_SSL_PROTO_TLS1_1)  && \
    !defined(JHD_TLS_SSL_PROTO_TLS1_2)
#error "JHD_TLS_SSL_PROTO_DTLS defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_SSL_CLI_C) && !defined(JHD_TLS_SSL_TLS_C)
#error "JHD_TLS_SSL_CLI_C defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_SSL_TLS_C) && ( !defined(JHD_TLS_CIPHER_C) ||     \
    !defined(JHD_TLS_MD_C) )
#error "JHD_TLS_SSL_TLS_C defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_SSL_SRV_C) && !defined(JHD_TLS_SSL_TLS_C)
#error "JHD_TLS_SSL_SRV_C defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_SSL_TLS_C) && (!defined(JHD_TLS_SSL_PROTO_SSL3) && \
    !defined(JHD_TLS_SSL_PROTO_TLS1) && !defined(JHD_TLS_SSL_PROTO_TLS1_1) && \
    !defined(JHD_TLS_SSL_PROTO_TLS1_2))
#error "JHD_TLS_SSL_TLS_C defined, but no protocols are active"
#endif

#if defined(JHD_TLS_SSL_TLS_C) && (defined(JHD_TLS_SSL_PROTO_SSL3) && \
    defined(JHD_TLS_SSL_PROTO_TLS1_1) && !defined(JHD_TLS_SSL_PROTO_TLS1))
#error "Illegal protocol selection"
#endif

#if defined(JHD_TLS_SSL_TLS_C) && (defined(JHD_TLS_SSL_PROTO_TLS1) && \
    defined(JHD_TLS_SSL_PROTO_TLS1_2) && !defined(JHD_TLS_SSL_PROTO_TLS1_1))
#error "Illegal protocol selection"
#endif

#if defined(JHD_TLS_SSL_TLS_C) && (defined(JHD_TLS_SSL_PROTO_SSL3) && \
    defined(JHD_TLS_SSL_PROTO_TLS1_2) && (!defined(JHD_TLS_SSL_PROTO_TLS1) || \
    !defined(JHD_TLS_SSL_PROTO_TLS1_1)))
#error "Illegal protocol selection"
#endif

#if defined(JHD_TLS_SSL_DTLS_HELLO_VERIFY) && !defined(JHD_TLS_SSL_PROTO_DTLS)
#error "JHD_TLS_SSL_DTLS_HELLO_VERIFY  defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_SSL_DTLS_CLIENT_PORT_REUSE) && \
    !defined(JHD_TLS_SSL_DTLS_HELLO_VERIFY)
#error "JHD_TLS_SSL_DTLS_CLIENT_PORT_REUSE  defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_SSL_DTLS_ANTI_REPLAY) &&                              \
    ( !defined(JHD_TLS_SSL_TLS_C) || !defined(JHD_TLS_SSL_PROTO_DTLS) )
#error "JHD_TLS_SSL_DTLS_ANTI_REPLAY  defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_SSL_DTLS_BADMAC_LIMIT) &&                              \
    ( !defined(JHD_TLS_SSL_TLS_C) || !defined(JHD_TLS_SSL_PROTO_DTLS) )
#error "JHD_TLS_SSL_DTLS_BADMAC_LIMIT  defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_SSL_ENCRYPT_THEN_MAC) &&   \
    !defined(JHD_TLS_SSL_PROTO_TLS1)   &&      \
    !defined(JHD_TLS_SSL_PROTO_TLS1_1) &&      \
    !defined(JHD_TLS_SSL_PROTO_TLS1_2)
#error "JHD_TLS_SSL_ENCRYPT_THEN_MAC defined, but not all prerequsites"
#endif

#if defined(JHD_TLS_SSL_EXTENDED_MASTER_SECRET) && \
    !defined(JHD_TLS_SSL_PROTO_TLS1)   &&          \
    !defined(JHD_TLS_SSL_PROTO_TLS1_1) &&          \
    !defined(JHD_TLS_SSL_PROTO_TLS1_2)
#error "JHD_TLS_SSL_EXTENDED_MASTER_SECRET defined, but not all prerequsites"
#endif

#if defined(JHD_TLS_SSL_TICKET_C) && !defined(JHD_TLS_CIPHER_C)
#error "JHD_TLS_SSL_TICKET_C defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_SSL_CBC_RECORD_SPLITTING) && \
    !defined(JHD_TLS_SSL_PROTO_SSL3) && !defined(JHD_TLS_SSL_PROTO_TLS1)
#error "JHD_TLS_SSL_CBC_RECORD_SPLITTING defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_SSL_SERVER_NAME_INDICATION) && \
        !defined(JHD_TLS_X509_CRT_PARSE_C)
#error "JHD_TLS_SSL_SERVER_NAME_INDICATION defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_THREADING_PTHREAD)
#if !defined(JHD_TLS_THREADING_C) || defined(JHD_TLS_THREADING_IMPL)
#error "JHD_TLS_THREADING_PTHREAD defined, but not all prerequisites"
#endif
#define JHD_TLS_THREADING_IMPL
#endif

#if defined(JHD_TLS_THREADING_ALT)
#if !defined(JHD_TLS_THREADING_C) || defined(JHD_TLS_THREADING_IMPL)
#error "JHD_TLS_THREADING_ALT defined, but not all prerequisites"
#endif
#define JHD_TLS_THREADING_IMPL
#endif

#if defined(JHD_TLS_THREADING_C) && !defined(JHD_TLS_THREADING_IMPL)
#error "JHD_TLS_THREADING_C defined, single threading implementation required"
#endif
#undef JHD_TLS_THREADING_IMPL

#if defined(JHD_TLS_VERSION_FEATURES) && !defined(JHD_TLS_VERSION_C)
#error "JHD_TLS_VERSION_FEATURES defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_X509_USE_C) && ( !defined(JHD_TLS_BIGNUM_C) ||  \
    !defined(JHD_TLS_OID_C) || !defined(JHD_TLS_ASN1_PARSE_C) ||      \
    !defined(JHD_TLS_PK_PARSE_C) )
#error "JHD_TLS_X509_USE_C defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_X509_CREATE_C) && ( !defined(JHD_TLS_BIGNUM_C) ||  \
    !defined(JHD_TLS_OID_C) || !defined(JHD_TLS_ASN1_WRITE_C) ||       \
    !defined(JHD_TLS_PK_WRITE_C) )
#error "JHD_TLS_X509_CREATE_C defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_X509_CRT_PARSE_C) && ( !defined(JHD_TLS_X509_USE_C) )
#error "JHD_TLS_X509_CRT_PARSE_C defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_X509_CRL_PARSE_C) && ( !defined(JHD_TLS_X509_USE_C) )
#error "JHD_TLS_X509_CRL_PARSE_C defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_X509_CSR_PARSE_C) && ( !defined(JHD_TLS_X509_USE_C) )
#error "JHD_TLS_X509_CSR_PARSE_C defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_X509_CRT_WRITE_C) && ( !defined(JHD_TLS_X509_CREATE_C) )
#error "JHD_TLS_X509_CRT_WRITE_C defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_X509_CSR_WRITE_C) && ( !defined(JHD_TLS_X509_CREATE_C) )
#error "JHD_TLS_X509_CSR_WRITE_C defined, but not all prerequisites"
#endif

#if defined(JHD_TLS_HAVE_INT32) && defined(JHD_TLS_HAVE_INT64)
#error "JHD_TLS_HAVE_INT32 and JHD_TLS_HAVE_INT64 cannot be defined simultaneously"
#endif /* JHD_TLS_HAVE_INT32 && JHD_TLS_HAVE_INT64 */

#if ( defined(JHD_TLS_HAVE_INT32) || defined(JHD_TLS_HAVE_INT64) ) && \
    defined(JHD_TLS_HAVE_ASM)
#error "JHD_TLS_HAVE_INT32/JHD_TLS_HAVE_INT64 and JHD_TLS_HAVE_ASM cannot be defined simultaneously"
#endif /* (JHD_TLS_HAVE_INT32 || JHD_TLS_HAVE_INT64) && JHD_TLS_HAVE_ASM */

/*
 * Avoid warning from -pedantic. This is a convenient place for this
 * workaround since this is included by every single file before the
 * #if defined(JHD_TLS_xxx_C) that results in emtpy translation units.
 */
typedef int jhd_tls_iso_c_forbids_empty_translation_units;

#endif /* JHD_TLS_CHECK_CONFIG_H */
