/**
 * \file platform.h
 *
 * \brief This file contains the definitions and functions of the
 *        Mbed TLS platform abstraction layer.
 *
 *        The platform abstraction layer removes the need for the library
 *        to directly link to standard C library functions or operating
 *        system services, making the library easier to port and embed.
 *        Application developers and users of the library can provide their own
 *        implementations of these functions, or implementations specific to
 *        their platform, which can be statically linked to the library or
 *        dynamically configured at runtime.
 */
/*
 *  Copyright (C) 2006-2018, Arm Limited (or its affiliates), All Rights Reserved
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
#ifndef JHD_TLS_PLATFORM_H
#define JHD_TLS_PLATFORM_H

#if !defined(JHD_TLS_CONFIG_FILE)
#include <tls/jhd_tls_config.h>
#else
#include JHD_TLS_CONFIG_FILE
#endif

#if defined(JHD_TLS_HAVE_TIME)
#include <tls/jhd_tls_platform_time.h>
#endif




/**
 * \name SECTION: Module settings
 *
 * The configuration options you can set for this module are in this section.
 * Either change them in config.h or define them on the compiler command line.
 * \{
 */

#if !defined(JHD_TLS_PLATFORM_NO_STD_FUNCTIONS)
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#if !defined(JHD_TLS_PLATFORM_STD_SNPRINTF)
#if defined(_WIN32)
#define JHD_TLS_PLATFORM_STD_SNPRINTF   jhd_tls_platform_win32_snprintf /**< The default \c snprintf function to use.  */
#else
#define JHD_TLS_PLATFORM_STD_SNPRINTF   snprintf /**< The default \c snprintf function to use.  */
#endif
#endif
#if !defined(JHD_TLS_PLATFORM_STD_PRINTF)
#define JHD_TLS_PLATFORM_STD_PRINTF   printf /**< The default \c printf function to use. */
#endif
#if !defined(JHD_TLS_PLATFORM_STD_FPRINTF)
#define JHD_TLS_PLATFORM_STD_FPRINTF fprintf /**< The default \c fprintf function to use. */
#endif
#if !defined(JHD_TLS_PLATFORM_STD_CALLOC)
#define JHD_TLS_PLATFORM_STD_CALLOC   calloc /**< The default \c calloc function to use. */
#endif
#if !defined(JHD_TLS_PLATFORM_STD_FREE)
#define JHD_TLS_PLATFORM_STD_FREE       free /**< The default \c free function to use. */
#endif
#if !defined(JHD_TLS_PLATFORM_STD_EXIT)
#define JHD_TLS_PLATFORM_STD_EXIT      exit /**< The default \c exit function to use. */
#endif
#if !defined(JHD_TLS_PLATFORM_STD_TIME)
#define JHD_TLS_PLATFORM_STD_TIME       time    /**< The default \c time function to use. */
#endif
#if !defined(JHD_TLS_PLATFORM_STD_EXIT_SUCCESS)
#define JHD_TLS_PLATFORM_STD_EXIT_SUCCESS  EXIT_SUCCESS /**< The default exit value to use. */
#endif
#if !defined(JHD_TLS_PLATFORM_STD_EXIT_FAILURE)
#define JHD_TLS_PLATFORM_STD_EXIT_FAILURE  EXIT_FAILURE /**< The default exit value to use. */
#endif
#if defined(JHD_TLS_FS_IO)
#if !defined(JHD_TLS_PLATFORM_STD_NV_SEED_READ)
#define JHD_TLS_PLATFORM_STD_NV_SEED_READ   jhd_tls_platform_std_nv_seed_read
#endif
#if !defined(JHD_TLS_PLATFORM_STD_NV_SEED_WRITE)
#define JHD_TLS_PLATFORM_STD_NV_SEED_WRITE  jhd_tls_platform_std_nv_seed_write
#endif
#if !defined(JHD_TLS_PLATFORM_STD_NV_SEED_FILE)
#define JHD_TLS_PLATFORM_STD_NV_SEED_FILE   "seedfile"
#endif
#endif /* JHD_TLS_FS_IO */
#else /* JHD_TLS_PLATFORM_NO_STD_FUNCTIONS */
#if defined(JHD_TLS_PLATFORM_STD_MEM_HDR)
#include JHD_TLS_PLATFORM_STD_MEM_HDR
#endif
#endif /* JHD_TLS_PLATFORM_NO_STD_FUNCTIONS */


/* \} name SECTION: Module settings */

/*
 * The function pointers for calloc and free.
 */
#if defined(JHD_TLS_PLATFORM_MEMORY)
#if defined(JHD_TLS_PLATFORM_FREE_MACRO) && \
    defined(JHD_TLS_PLATFORM_CALLOC_MACRO)
#define jhd_tls_free       JHD_TLS_PLATFORM_FREE_MACRO
#define jhd_tls_calloc     JHD_TLS_PLATFORM_CALLOC_MACRO
#else
/* For size_t */
#include <stddef.h>
extern void *jhd_tls_calloc( size_t n, size_t size );
extern void jhd_tls_free( void *ptr );

/**
 * \brief               This function dynamically sets the memory-management
 *                      functions used by the library, during runtime.
 *
 * \param calloc_func   The \c calloc function implementation.
 * \param free_func     The \c free function implementation.
 *
 * \return              \c 0.
 */
int jhd_tls_platform_set_calloc_free( void * (*calloc_func)( size_t, size_t ),
                              void (*free_func)( void * ) );
#endif /* JHD_TLS_PLATFORM_FREE_MACRO && JHD_TLS_PLATFORM_CALLOC_MACRO */
#else /* !JHD_TLS_PLATFORM_MEMORY */
#define jhd_tls_free       free
#define jhd_tls_calloc     calloc
#endif /* JHD_TLS_PLATFORM_MEMORY && !JHD_TLS_PLATFORM_{FREE,CALLOC}_MACRO */

/*
 * The function pointers for fprintf
 */
#if defined(JHD_TLS_PLATFORM_FPRINTF_ALT)
/* We need FILE * */
#include <stdio.h>
extern int (*jhd_tls_fprintf)( FILE *stream, const char *format, ... );

/**
 * \brief                This function dynamically configures the fprintf
 *                       function that is called when the
 *                       jhd_tls_fprintf() function is invoked by the library.
 *
 * \param fprintf_func   The \c fprintf function implementation.
 *
 * \return               \c 0.
 */
int jhd_tls_platform_set_fprintf( int (*fprintf_func)( FILE *stream, const char *,
                                               ... ) );
#else
#if defined(JHD_TLS_PLATFORM_FPRINTF_MACRO)
#define jhd_tls_fprintf    JHD_TLS_PLATFORM_FPRINTF_MACRO
#else
#define jhd_tls_fprintf    fprintf
#endif /* JHD_TLS_PLATFORM_FPRINTF_MACRO */
#endif /* JHD_TLS_PLATFORM_FPRINTF_ALT */

/*
 * The function pointers for printf
 */
#if defined(JHD_TLS_PLATFORM_PRINTF_ALT)
extern int (*jhd_tls_printf)( const char *format, ... );

/**
 * \brief               This function dynamically configures the snprintf
 *                      function that is called when the jhd_tls_snprintf()
 *                      function is invoked by the library.
 *
 * \param printf_func   The \c printf function implementation.
 *
 * \return              \c 0 on success.
 */
int jhd_tls_platform_set_printf( int (*printf_func)( const char *, ... ) );
#else /* !JHD_TLS_PLATFORM_PRINTF_ALT */
#if defined(JHD_TLS_PLATFORM_PRINTF_MACRO)
#define jhd_tls_printf     JHD_TLS_PLATFORM_PRINTF_MACRO
#else
#define jhd_tls_printf     printf
#endif /* JHD_TLS_PLATFORM_PRINTF_MACRO */
#endif /* JHD_TLS_PLATFORM_PRINTF_ALT */

/*
 * The function pointers for snprintf
 *
 * The snprintf implementation should conform to C99:
 * - it *must* always correctly zero-terminate the buffer
 *   (except when n == 0, then it must leave the buffer untouched)
 * - however it is acceptable to return -1 instead of the required length when
 *   the destination buffer is too short.
 */
#if defined(_WIN32)
/* For Windows (inc. MSYS2), we provide our own fixed implementation */
int jhd_tls_platform_win32_snprintf( char *s, size_t n, const char *fmt, ... );
#endif

#if defined(JHD_TLS_PLATFORM_SNPRINTF_ALT)
extern int (*jhd_tls_snprintf)( char * s, size_t n, const char * format, ... );

/**
 * \brief                 This function allows configuring a custom
 *                        \c snprintf function pointer.
 *
 * \param snprintf_func   The \c snprintf function implementation.
 *
 * \return                \c 0 on success.
 */
int jhd_tls_platform_set_snprintf( int (*snprintf_func)( char * s, size_t n,
                                                 const char * format, ... ) );
#else /* JHD_TLS_PLATFORM_SNPRINTF_ALT */
#if defined(JHD_TLS_PLATFORM_SNPRINTF_MACRO)
#define jhd_tls_snprintf   JHD_TLS_PLATFORM_SNPRINTF_MACRO
#else
#define jhd_tls_snprintf   JHD_TLS_PLATFORM_STD_SNPRINTF
#endif /* JHD_TLS_PLATFORM_SNPRINTF_MACRO */
#endif /* JHD_TLS_PLATFORM_SNPRINTF_ALT */

/*
 * The function pointers for exit
 */
#if defined(JHD_TLS_PLATFORM_EXIT_ALT)
extern void (*jhd_tls_exit)( int status );

/**
 * \brief             This function dynamically configures the exit
 *                    function that is called when the jhd_tls_exit()
 *                    function is invoked by the library.
 *
 * \param exit_func   The \c exit function implementation.
 *
 * \return            \c 0 on success.
 */
int jhd_tls_platform_set_exit( void (*exit_func)( int status ) );
#else
#if defined(JHD_TLS_PLATFORM_EXIT_MACRO)
#define jhd_tls_exit   JHD_TLS_PLATFORM_EXIT_MACRO
#else
#define jhd_tls_exit   exit
#endif /* JHD_TLS_PLATFORM_EXIT_MACRO */
#endif /* JHD_TLS_PLATFORM_EXIT_ALT */

/*
 * The default exit values
 */
#if defined(JHD_TLS_PLATFORM_STD_EXIT_SUCCESS)
#define JHD_TLS_EXIT_SUCCESS JHD_TLS_PLATFORM_STD_EXIT_SUCCESS
#else
#define JHD_TLS_EXIT_SUCCESS 0
#endif
#if defined(JHD_TLS_PLATFORM_STD_EXIT_FAILURE)
#define JHD_TLS_EXIT_FAILURE JHD_TLS_PLATFORM_STD_EXIT_FAILURE
#else
#define JHD_TLS_EXIT_FAILURE 1
#endif

/*
 * The function pointers for reading from and writing a seed file to
 * Non-Volatile storage (NV) in a platform-independent way
 *
 * Only enabled when the NV seed entropy source is enabled
 */
#if defined(JHD_TLS_ENTROPY_NV_SEED)
#if !defined(JHD_TLS_PLATFORM_NO_STD_FUNCTIONS) && defined(JHD_TLS_FS_IO)
/* Internal standard platform definitions */
int jhd_tls_platform_std_nv_seed_read( unsigned char *buf, size_t buf_len );
int jhd_tls_platform_std_nv_seed_write( unsigned char *buf, size_t buf_len );
#endif

#if defined(JHD_TLS_PLATFORM_NV_SEED_ALT)
extern int (*jhd_tls_nv_seed_read)( unsigned char *buf, size_t buf_len );
extern int (*jhd_tls_nv_seed_write)( unsigned char *buf, size_t buf_len );

/**
 * \brief   This function allows configuring custom seed file writing and
 *          reading functions.
 *
 * \param   nv_seed_read_func   The seed reading function implementation.
 * \param   nv_seed_write_func  The seed writing function implementation.
 *
 * \return  \c 0 on success.
 */
int jhd_tls_platform_set_nv_seed(
            int (*nv_seed_read_func)( unsigned char *buf, size_t buf_len ),
            int (*nv_seed_write_func)( unsigned char *buf, size_t buf_len )
            );
#else
#if defined(JHD_TLS_PLATFORM_NV_SEED_READ_MACRO) && \
    defined(JHD_TLS_PLATFORM_NV_SEED_WRITE_MACRO)
#define jhd_tls_nv_seed_read    JHD_TLS_PLATFORM_NV_SEED_READ_MACRO
#define jhd_tls_nv_seed_write   JHD_TLS_PLATFORM_NV_SEED_WRITE_MACRO
#else
#define jhd_tls_nv_seed_read    jhd_tls_platform_std_nv_seed_read
#define jhd_tls_nv_seed_write   jhd_tls_platform_std_nv_seed_write
#endif
#endif /* JHD_TLS_PLATFORM_NV_SEED_ALT */
#endif /* JHD_TLS_ENTROPY_NV_SEED */

#if !defined(JHD_TLS_PLATFORM_SETUP_TEARDOWN_ALT)

/**
 * \brief   The platform context structure.
 *
 * \note    This structure may be used to assist platform-specific
 *          setup or teardown operations.
 */
typedef struct {
    char dummy; /**< A placeholder member, as empty structs are not portable. */
}
jhd_tls_platform_context;

#else
#include <tls/jhd_tls_platform_alt.h>
#endif /* !JHD_TLS_PLATFORM_SETUP_TEARDOWN_ALT */

/**
 * \brief   This function performs any platform-specific initialization
 *          operations.
 *
 * \note    This function should be called before any other library functions.
 *
 *          Its implementation is platform-specific, and unless
 *          platform-specific code is provided, it does nothing.
 *
 * \note    The usage and necessity of this function is dependent on the platform.
 *
 * \param   ctx     The platform context.
 *
 * \return  \c 0 on success.
 */
int jhd_tls_platform_setup( jhd_tls_platform_context *ctx );
/**
 * \brief   This function performs any platform teardown operations.
 *
 * \note    This function should be called after every other Mbed TLS module
 *          has been correctly freed using the appropriate free function.
 *
 *          Its implementation is platform-specific, and unless
 *          platform-specific code is provided, it does nothing.
 *
 * \note    The usage and necessity of this function is dependent on the platform.
 *
 * \param   ctx     The platform context.
 *
 */
void jhd_tls_platform_teardown( jhd_tls_platform_context *ctx );



#endif /* platform.h */
