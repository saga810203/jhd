/*
 * jhd_log.c
 *
 *  Created on: May 11, 2018
 *      Author: root
 */

#include <jhd_core.h>

uint16_t jhd_common_log_mask = JHD_LOG_MASK_IN_MASTER;

jhd_log_t  * jhd_top_log;


static char *jhd_log_level_enum[] = { "STDERR", " EMERG", " ALERT", "  CRIT",
		"   ERR", "  WARN", "NOTICE", "  INFO", " DEBUG", };

void _log_out(u_char* file_name, u_char *func_name, int line, jhd_log_t *log,
		uint16_t log_mask, uint16_t level, const u_char* fmt, ...) {
	va_list args;

	u_char *p;

	u_char errstr[JHD_MAX_ERROR_STR];


	size_t len, slen;
	len = JHD_MAX_ERROR_STR;
	if(log)
	slen = snprintf("%s %s file:%s function:%s line:%6d\n", jhd_cache_log_time,
			jhd_log_level_enum[level], file_name, func_name, line);

	va_start(args, fmt);
	len = snprintf(&errstr[slen], JHD_MAX_ERROR_STR - slen, fmt, args);
	va_end(args);
	len += slen;
	if (len >= JHD_MAX_ERROR_STR) {
		len = JHD_MAX_ERROR_STR - 1;
		errstr[JHD_MAX_ERROR_STR - 1] = '\0';
	}
	while (log &&(log->mask & jhd_common_log_mask)&& (log->mask & log_mask) && (log->level >= log->level)
			&& (log->handler) && (!log->handler(log, &errstr[0], len))) {
		log = log->next;
	}
}


int jhd_std_log_handler(jhd_log_t  *log,u_char* buf,size_t len){
	write(2,buf,len);
	return JHD_OK;
}
