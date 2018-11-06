/*
 * jhd_string.c
 *
 *  Created on: 2018年5月18日
 *      Author: root
 */
#include<jhd_string.h>
#include<jhd_pool.h>
#include <jhd_log.h>

int jhd_chars_to_u64(u_char *chars, size_t n,uint64_t *result){
	uint64_t value, cutoff, cutlim;
	log_assert(n>0);
	log_assert(chars  != NULL);
	log_assert(result != NULL);

	cutoff = (uint64_t)(0xFFFFFFFFFFFFFFFFULL / 10);
	cutlim = (uint64_t)(0xFFFFFFFFFFFFFFFFULL % 10);

	for (value = 0; n--; ++chars) {
		if (*chars < '0' || *chars > '9') {
			return JHD_ERROR;
		}
		if (value > cutoff || ((value == cutoff) && (((u_char)(*chars - '0')) > cutlim))) {
			return JHD_ERROR;
		}
		value = value * 10 + (*chars - '0');
	}
	*result = value;
	return JHD_OK;
}
int jhd_hex_to_u64(u_char *chars,size_t n,uint64_t *result){
	u_char ch;
	int i;
	uint64_t value;
	log_assert(n>0);
	log_assert(chars  != NULL);
	log_assert(result != NULL);
	if(n>16){
		return JHD_ERROR;
	}
	value = 0;
	i = n;
	while(i >0){
		ch = *chars;
		--i;
		if (ch >= '0' && ch <= '9') {
			value <<=4;
			value += (ch - '0');
			continue;
		}
		ch |= 0x20;
		if (ch >= 'a' && ch <= 'f') {
			value <<=4;
			value += (ch - 'a' + 10);
			continue;
		}
		return JHD_ERROR;
	}
	*result = value;
	return JHD_OK;
}

int jhd_chars_to_u16(u_char *chars, size_t n,uint16_t *result){
	uint16_t value, cutoff, cutlim;
	log_assert(n>0);
	log_assert(chars  != NULL);
	log_assert(result != NULL);

	cutoff = 0xFFFF / 10;
	cutlim = 0xFFFF % 10;

	for (value = 0; n--; ++chars) {
		if (*chars < '0' || *chars > '9') {
			return JHD_ERROR;
		}

		if (value > cutoff || ((value == cutoff) && (*chars - '0' > cutlim))) {
			return JHD_ERROR;
		}
		value = value * 10 + (*chars - '0');
	}
	*result = value;
	return JHD_OK;
}
int jhd_hex_to_u16(u_char *chars,size_t n,uint16_t *result){
	u_char ch;
	int i;
	uint16_t value;
	log_assert(n>0);
	log_assert(chars  != NULL);
	log_assert(result != NULL);
	if(n>4){
		return JHD_ERROR;
	}
	value = 0;
	i = n;
	while(i >0){
		ch = *chars;
		--i;
		if (ch >= '0' && ch <= '9') {
			value <<=4;
			value += (ch - '0');
			continue;
		}
		ch |= 0x20;
		if (ch >= 'a' && ch <= 'f') {
			value <<=4;
			value += (ch - 'a' + 10);
			continue;
		}
		return JHD_ERROR;
	}
	*result = value;
	return JHD_OK;
}


u_char* jhd_u64_to_hex(u_char* last,uint64_t val){
	do {
		--last;
		*last = jhd_g_hex_char[(uint32_t)(val & 0xf)];
	} while (val >>= 4);
	return last;
}
