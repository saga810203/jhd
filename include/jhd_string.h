/*
 * jhd_string.h
 *
 *  Created on: May 14, 2018
 *      Author: root
 */

#ifndef JHD_STRING_H_
#define JHD_STRING_H_

#include <jhd_config.h>



int jhd_chars_to_u64(u_char *chars, size_t n,uint64_t *result);
int jhd_hex_to_u64(u_char *chars,size_t n,uint64_t *result);
int jhd_chars_to_u16(u_char *chars, size_t n,uint16_t *result);
int jhd_hex_to_u16(u_char *chars,size_t n,uint16_t *result);


u_char* jhd_u64_to_hex(u_char* last,uint64_t val);

u_char* jhd_u64_to_string(u_char *last,uint64_t val);

#endif /* JHD_STRING_H_ */
