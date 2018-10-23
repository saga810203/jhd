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




#if defined(JHD_TLS_TEST_NULL_ENTROPY) &&  defined(JHD_TLS_ENTROPY_HARDWARE_ALT)
#error "JHD_TLS_TEST_NULL_ENTROPY defined, but entropy sources too"
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








#if defined(JHD_TLS_MEMORY_BUFFER_ALLOC_C) &&                          \
    ( !defined(JHD_TLS_PLATFORM_C) || !defined(JHD_TLS_PLATFORM_MEMORY) )
#error "JHD_TLS_MEMORY_BUFFER_ALLOC_C defined, but not all prerequisites"
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
