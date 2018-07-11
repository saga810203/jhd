/**
 * \file memory_buffer_alloc.h
 *
 * \brief Buffer-based memory allocator
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
#ifndef JHD_TLS_MEMORY_BUFFER_ALLOC_H
#define JHD_TLS_MEMORY_BUFFER_ALLOC_H

#if !defined(JHD_TLS_CONFIG_FILE)
#include <tls/jhd_tls_config.h>
#else
#include JHD_TLS_CONFIG_FILE
#endif

#include <stddef.h>

/**
 * \name SECTION: Module settings
 *
 * The configuration options you can set for this module are in this section.
 * Either change them in config.h or define them on the compiler command line.
 * \{
 */

#if !defined(JHD_TLS_MEMORY_ALIGN_MULTIPLE)
#define JHD_TLS_MEMORY_ALIGN_MULTIPLE       4 /**< Align on multiples of this value */
#endif

/* \} name SECTION: Module settings */

#define JHD_TLS_MEMORY_VERIFY_NONE         0
#define JHD_TLS_MEMORY_VERIFY_ALLOC        (1 << 0)
#define JHD_TLS_MEMORY_VERIFY_FREE         (1 << 1)
#define JHD_TLS_MEMORY_VERIFY_ALWAYS       (JHD_TLS_MEMORY_VERIFY_ALLOC | JHD_TLS_MEMORY_VERIFY_FREE)



/**
 * \brief   Initialize use of stack-based memory allocator.
 *          The stack-based allocator does memory management inside the
 *          presented buffer and does not call calloc() and free().
 *          It sets the global jhd_tls_calloc() and jhd_tls_free() pointers
 *          to its own functions.
 *          (Provided jhd_tls_calloc() and jhd_tls_free() are thread-safe if
 *           JHD_TLS_THREADING_C is defined)
 *
 * \note    This code is not optimized and provides a straight-forward
 *          implementation of a stack-based memory allocator.
 *
 * \param buf   buffer to use as heap
 * \param len   size of the buffer
 */
void jhd_tls_memory_buffer_alloc_init( unsigned char *buf, size_t len );

/**
 * \brief   Free the mutex for thread-safety and clear remaining memory
 */
void jhd_tls_memory_buffer_alloc_free( void );

/**
 * \brief   Determine when the allocator should automatically verify the state
 *          of the entire chain of headers / meta-data.
 *          (Default: JHD_TLS_MEMORY_VERIFY_NONE)
 *
 * \param verify    One of JHD_TLS_MEMORY_VERIFY_NONE, JHD_TLS_MEMORY_VERIFY_ALLOC,
 *                  JHD_TLS_MEMORY_VERIFY_FREE or JHD_TLS_MEMORY_VERIFY_ALWAYS
 */
void jhd_tls_memory_buffer_set_verify( int verify );

#if defined(JHD_TLS_MEMORY_DEBUG)
/**
 * \brief   Print out the status of the allocated memory (primarily for use
 *          after a program should have de-allocated all memory)
 *          Prints out a list of 'still allocated' blocks and their stack
 *          trace if JHD_TLS_MEMORY_BACKTRACE is defined.
 */
void jhd_tls_memory_buffer_alloc_status( void );

/**
 * \brief   Get the peak heap usage so far
 *
 * \param max_used      Peak number of bytes in use or committed. This
 *                      includes bytes in allocated blocks too small to split
 *                      into smaller blocks but larger than the requested size.
 * \param max_blocks    Peak number of blocks in use, including free and used
 */
void jhd_tls_memory_buffer_alloc_max_get( size_t *max_used, size_t *max_blocks );

/**
 * \brief   Reset peak statistics
 */
void jhd_tls_memory_buffer_alloc_max_reset( void );

/**
 * \brief   Get the current heap usage
 *
 * \param cur_used      Current number of bytes in use or committed. This
 *                      includes bytes in allocated blocks too small to split
 *                      into smaller blocks but larger than the requested size.
 * \param cur_blocks    Current number of blocks in use, including free and used
 */
void jhd_tls_memory_buffer_alloc_cur_get( size_t *cur_used, size_t *cur_blocks );
#endif /* JHD_TLS_MEMORY_DEBUG */

/**
 * \brief   Verifies that all headers in the memory buffer are correct
 *          and contain sane values. Helps debug buffer-overflow errors.
 *
 *          Prints out first failure if JHD_TLS_MEMORY_DEBUG is defined.
 *          Prints out full header information if JHD_TLS_MEMORY_DEBUG
 *          is defined. (Includes stack trace information for each block if
 *          JHD_TLS_MEMORY_BACKTRACE is defined as well).
 *
 * \return             0 if verified, 1 otherwise
 */
int jhd_tls_memory_buffer_alloc_verify( void );

#if defined(JHD_TLS_SELF_TEST)
/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if a test failed
 */
int jhd_tls_memory_buffer_alloc_self_test( int verbose );
#endif



#endif /* memory_buffer_alloc.h */
