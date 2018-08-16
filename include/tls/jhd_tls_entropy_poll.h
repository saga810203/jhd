/**
 * \file entropy_poll.h
 *
 * \brief Platform-specific and custom entropy polling functions
 */
/*
 *  Copyright (C) 2006-2016, ARM Limited, All Rights Reserved
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
#ifndef JHD_TLS_ENTROPY_POLL_H
#define JHD_TLS_ENTROPY_POLL_H

#if !defined(JHD_TLS_CONFIG_FILE)
#include <tls/jhd_tls_config.h>
#else
#include JHD_TLS_CONFIG_FILE
#endif

#include <stddef.h>


/*
 * Default thresholds for built-in sources, in bytes
 */
#define JHD_TLS_ENTROPY_MIN_PLATFORM     32     /**< Minimum for platform source    */
#define JHD_TLS_ENTROPY_MIN_HAVEGE       32     /**< Minimum for HAVEGE             */
#define JHD_TLS_ENTROPY_MIN_HARDCLOCK     4     /**< Minimum for jhd_tls_timing_hardclock()        */
#if !defined(JHD_TLS_ENTROPY_MIN_HARDWARE)
#define JHD_TLS_ENTROPY_MIN_HARDWARE     32     /**< Minimum for the hardware source */
#endif

/**
 * \brief           Entropy poll callback that provides 0 entropy.
 */
#if defined(JHD_TLS_TEST_NULL_ENTROPY)
    int jhd_tls_null_entropy_poll( void *data,
                                unsigned char *output, size_t len, size_t *olen );
#endif

#if !defined(JHD_TLS_NO_PLATFORM_ENTROPY)
/**
 * \brief           Platform-specific entropy poll callback
 */
int jhd_tls_platform_entropy_poll( void *data,
                           unsigned char *output, size_t len, size_t *olen );
#endif

#if defined(JHD_TLS_HAVEGE_C)
/**
 * \brief           HAVEGE based entropy poll callback
 *
 * Requires an HAVEGE state as its data pointer.
 */
int jhd_tls_havege_poll( void *data,
                 unsigned char *output, size_t len, size_t *olen );
#endif

#if defined(JHD_TLS_TIMING_C)
/**
 * \brief           jhd_tls_timing_hardclock-based entropy poll callback
 */
int jhd_tls_hardclock_poll( void *data,
                    unsigned char *output, size_t len, size_t *olen );
#endif

#if defined(JHD_TLS_ENTROPY_HARDWARE_ALT)
/**
 * \brief           Entropy poll callback for a hardware source
 *
 * \warning         This is not provided by mbed TLS!
 *                  See \c JHD_TLS_ENTROPY_HARDWARE_ALT in config.h.
 *
 * \note            This must accept NULL as its first argument.
 */
int jhd_tls_hardware_poll( void *data,
                           unsigned char *output, size_t len, size_t *olen );
#endif

#if defined(JHD_TLS_ENTROPY_NV_SEED)
/**
 * \brief           Entropy poll callback for a non-volatile seed file
 *
 * \note            This must accept NULL as its first argument.
 */
int jhd_tls_nv_seed_poll( void *data,
                          unsigned char *output, size_t len, size_t *olen );
#endif



#endif /* entropy_poll.h */