/**
 * \file entropy.h
 *
 * \brief Entropy accumulator implementation
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
#ifndef JHD_TLS_ENTROPY_H
#define JHD_TLS_ENTROPY_H

#if !defined(JHD_TLS_CONFIG_FILE)
#include <tls/jhd_tls_config.h>
#else
#include JHD_TLS_CONFIG_FILE
#endif

#include <stddef.h>

#if defined(JHD_TLS_SHA512_C) && !defined(JHD_TLS_ENTROPY_FORCE_SHA256)
#include <tls/jhd_tls_sha512.h>
#define JHD_TLS_ENTROPY_SHA512_ACCUMULATOR
#else
#if defined(JHD_TLS_SHA256_C)
#define JHD_TLS_ENTROPY_SHA256_ACCUMULATOR
#include "sha256.h"
#endif
#endif



#if defined(JHD_TLS_HAVEGE_C)
#include "havege.h"
#endif

#define JHD_TLS_ERR_ENTROPY_SOURCE_FAILED                 -0x003C  /**< Critical entropy source failure. */
#define JHD_TLS_ERR_ENTROPY_MAX_SOURCES                   -0x003E  /**< No more sources can be added. */
#define JHD_TLS_ERR_ENTROPY_NO_SOURCES_DEFINED            -0x0040  /**< No sources have been added to poll. */
#define JHD_TLS_ERR_ENTROPY_NO_STRONG_SOURCE              -0x003D  /**< No strong sources have been added to poll. */
#define JHD_TLS_ERR_ENTROPY_FILE_IO_ERROR                 -0x003F  /**< Read/write error in file. */

/**
 * \name SECTION: Module settings
 *
 * The configuration options you can set for this module are in this section.
 * Either change them in config.h or define them on the compiler command line.
 * \{
 */

#if !defined(JHD_TLS_ENTROPY_MAX_SOURCES)
#define JHD_TLS_ENTROPY_MAX_SOURCES     20      /**< Maximum number of sources supported */
#endif

#if !defined(JHD_TLS_ENTROPY_MAX_GATHER)
#define JHD_TLS_ENTROPY_MAX_GATHER      128     /**< Maximum amount requested from entropy sources */
#endif

/* \} name SECTION: Module settings */

#if defined(JHD_TLS_ENTROPY_SHA512_ACCUMULATOR)
#define JHD_TLS_ENTROPY_BLOCK_SIZE      64      /**< Block size of entropy accumulator (SHA-512) */
#else
#define JHD_TLS_ENTROPY_BLOCK_SIZE      32      /**< Block size of entropy accumulator (SHA-256) */
#endif

#define JHD_TLS_ENTROPY_MAX_SEED_SIZE   1024    /**< Maximum size of seed we read from seed file */
#define JHD_TLS_ENTROPY_SOURCE_MANUAL   JHD_TLS_ENTROPY_MAX_SOURCES

#define JHD_TLS_ENTROPY_SOURCE_STRONG   1       /**< Entropy source is strong   */
#define JHD_TLS_ENTROPY_SOURCE_WEAK     0       /**< Entropy source is weak     */



/**
 * \brief           Entropy poll callback pointer
 *
 * \param data      Callback-specific data pointer
 * \param output    Data to fill
 * \param len       Maximum size to provide
 * \param olen      The actual amount of bytes put into the buffer (Can be 0)
 *
 * \return          0 if no critical failures occurred,
 *                  JHD_TLS_ERR_ENTROPY_SOURCE_FAILED otherwise
 */
typedef int (*jhd_tls_entropy_f_source_ptr)(void *data, unsigned char *output, size_t len,
                            size_t *olen);

/**
 * \brief           Entropy source state
 */
typedef struct
{
    jhd_tls_entropy_f_source_ptr    f_source;   /**< The entropy source callback */
    void *          p_source;   /**< The callback data pointer */
    size_t          size;       /**< Amount received in bytes */
    size_t          threshold;  /**< Minimum bytes required before release */
    int             strong;     /**< Is the source strong? */
}
jhd_tls_entropy_source_state;

/**
 * \brief           Entropy context structure
 */
typedef struct
{
    int accumulator_started;
#if defined(JHD_TLS_ENTROPY_SHA512_ACCUMULATOR)
    jhd_tls_sha512_context  accumulator;
#else
    jhd_tls_sha256_context  accumulator;
#endif
    int             source_count;
    jhd_tls_entropy_source_state    source[JHD_TLS_ENTROPY_MAX_SOURCES];
#if defined(JHD_TLS_HAVEGE_C)
    jhd_tls_havege_state    havege_data;
#endif
#if defined(JHD_TLS_THREADING_C)
    jhd_tls_threading_mutex_t mutex;    /*!< mutex                  */
#endif
#if defined(JHD_TLS_ENTROPY_NV_SEED)
    int initial_entropy_run;
#endif
}
jhd_tls_entropy_context;

/**
 * \brief           Initialize the context
 *
 * \param ctx       Entropy context to initialize
 */
void jhd_tls_entropy_init( jhd_tls_entropy_context *ctx );

/**
 * \brief           Free the data in the context
 *
 * \param ctx       Entropy context to free
 */
void jhd_tls_entropy_free( jhd_tls_entropy_context *ctx );

/**
 * \brief           Adds an entropy source to poll
 *                  (Thread-safe if JHD_TLS_THREADING_C is enabled)
 *
 * \param ctx       Entropy context
 * \param f_source  Entropy function
 * \param p_source  Function data
 * \param threshold Minimum required from source before entropy is released
 *                  ( with jhd_tls_entropy_func() ) (in bytes)
 * \param strong    JHD_TLS_ENTROPY_SOURCE_STRONG or
 *                  JHD_TLS_ENTROPY_SOURCE_WEAK.
 *                  At least one strong source needs to be added.
 *                  Weaker sources (such as the cycle counter) can be used as
 *                  a complement.
 *
 * \return          0 if successful or JHD_TLS_ERR_ENTROPY_MAX_SOURCES
 */
int jhd_tls_entropy_add_source( jhd_tls_entropy_context *ctx,
                        jhd_tls_entropy_f_source_ptr f_source, void *p_source,
                        size_t threshold, int strong );

/**
 * \brief           Trigger an extra gather poll for the accumulator
 *                  (Thread-safe if JHD_TLS_THREADING_C is enabled)
 *
 * \param ctx       Entropy context
 *
 * \return          0 if successful, or JHD_TLS_ERR_ENTROPY_SOURCE_FAILED
 */
int jhd_tls_entropy_gather( jhd_tls_entropy_context *ctx );

/**
 * \brief           Retrieve entropy from the accumulator
 *                  (Maximum length: JHD_TLS_ENTROPY_BLOCK_SIZE)
 *                  (Thread-safe if JHD_TLS_THREADING_C is enabled)
 *
 * \param data      Entropy context
 * \param output    Buffer to fill
 * \param len       Number of bytes desired, must be at most JHD_TLS_ENTROPY_BLOCK_SIZE
 *
 * \return          0 if successful, or JHD_TLS_ERR_ENTROPY_SOURCE_FAILED
 */
int jhd_tls_entropy_func( void *data, unsigned char *output, size_t len );

/**
 * \brief           Add data to the accumulator manually
 *                  (Thread-safe if JHD_TLS_THREADING_C is enabled)
 *
 * \param ctx       Entropy context
 * \param data      Data to add
 * \param len       Length of data
 *
 * \return          0 if successful
 */
int jhd_tls_entropy_update_manual( jhd_tls_entropy_context *ctx,
                           const unsigned char *data, size_t len );

#if defined(JHD_TLS_ENTROPY_NV_SEED)
/**
 * \brief           Trigger an update of the seed file in NV by using the
 *                  current entropy pool.
 *
 * \param ctx       Entropy context
 *
 * \return          0 if successful
 */
int jhd_tls_entropy_update_nv_seed( jhd_tls_entropy_context *ctx );
#endif /* JHD_TLS_ENTROPY_NV_SEED */

#if defined(JHD_TLS_FS_IO)
/**
 * \brief               Write a seed file
 *
 * \param ctx           Entropy context
 * \param path          Name of the file
 *
 * \return              0 if successful,
 *                      JHD_TLS_ERR_ENTROPY_FILE_IO_ERROR on file error, or
 *                      JHD_TLS_ERR_ENTROPY_SOURCE_FAILED
 */
int jhd_tls_entropy_write_seed_file( jhd_tls_entropy_context *ctx, const char *path );

/**
 * \brief               Read and update a seed file. Seed is added to this
 *                      instance. No more than JHD_TLS_ENTROPY_MAX_SEED_SIZE bytes are
 *                      read from the seed file. The rest is ignored.
 *
 * \param ctx           Entropy context
 * \param path          Name of the file
 *
 * \return              0 if successful,
 *                      JHD_TLS_ERR_ENTROPY_FILE_IO_ERROR on file error,
 *                      JHD_TLS_ERR_ENTROPY_SOURCE_FAILED
 */
int jhd_tls_entropy_update_seed_file( jhd_tls_entropy_context *ctx, const char *path );
#endif /* JHD_TLS_FS_IO */

#if defined(JHD_TLS_SELF_TEST)
/**
 * \brief          Checkup routine
 *
 *                 This module self-test also calls the entropy self-test,
 *                 jhd_tls_entropy_source_self_test();
 *
 * \return         0 if successful, or 1 if a test failed
 */
int jhd_tls_entropy_self_test( int verbose );

#if defined(JHD_TLS_ENTROPY_HARDWARE_ALT)
/**
 * \brief          Checkup routine
 *
 *                 Verifies the integrity of the hardware entropy source
 *                 provided by the function 'jhd_tls_hardware_poll()'.
 *
 *                 Note this is the only hardware entropy source that is known
 *                 at link time, and other entropy sources configured
 *                 dynamically at runtime by the function
 *                 jhd_tls_entropy_add_source() will not be tested.
 *
 * \return         0 if successful, or 1 if a test failed
 */
int jhd_tls_entropy_source_self_test( int verbose );
#endif /* JHD_TLS_ENTROPY_HARDWARE_ALT */
#endif /* JHD_TLS_SELF_TEST */



#endif /* entropy.h */
