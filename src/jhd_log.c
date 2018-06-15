/*
 * jhd_log.c
 *
 *  Created on: May 11, 2018
 *      Author: root
 */

#include <jhd_config.h>
#include <jhd_log.h>
#include <jhd_process.h>
#include <jhd_core.h>


static u_char   jhd_top_log_file_name[1024];

static jhd_log_t jhd_top_log;

static char *jhd_log_level_enum[] = { "STDERR", " EMERG", " ALERT", "  CRIT", "   ERR", "  WARN", "NOTICE", "  INFO", " DEBUG", };

void _log_out(u_char* file_name, u_char *func_name, int line, uint16_t level, const u_char* fmt, ...) {
	va_list args;

	u_char *p;

	u_char errstr[JHD_MAX_ERROR_STR];

	size_t len, slen;
	jhd_log_t *log;
	log = &jhd_top_log;

	len = JHD_MAX_ERROR_STR;
	slen = snprintf("%s %s file:%s function:%s line:%6d\n", jhd_cache_log_time, jhd_log_level_enum[level], file_name, func_name, line);

	va_start(args, fmt);
	len = snprintf(&errstr[slen], JHD_MAX_ERROR_STR - slen, fmt, args);
	va_end(args);
	len += slen;
	if (len >= JHD_MAX_ERROR_STR) {
		len = JHD_MAX_ERROR_STR - 1;
		errstr[JHD_MAX_ERROR_STR - 1] = '\0';
	}
	while (log) {
		if ((log->level >= log->level) && (log->handler)) {
			log->handler(log, &errstr[0], len, file_name, func_name, line);
		}
		log = log->next;
	}
}



void jhd_log_default_handler(jhd_log_t *log, u_char* buf, size_t len, u_char* file_name, u_char *func_name, int line) {
	int fd;
	fd =open(&jhd_top_log_file_name,O_APPEND | O_CREAT , 0644);
	if(fd== (-1)){
		return;
	}
	write(fd,buf,len);
	close(fd);
	return;
}
void jhd_std_log_handler(jhd_log_t *log, u_char* buf, size_t len, u_char* file_name, u_char *func_name, int line) {
	write(2, buf, len);
}
void jhd_log_close() {
	jhd_log_t *log, *next;
	log = &jhd_top_log;

	while (log) {
		next = log->next;
		if (log->close) {
			log->close(log);
		}
		log = next;
	}
}

void jhd_log_replace(uint16_t level, log_handler_pt handler, void *data, jhd_obj_free_pt close) {
	if (jhd_top_log.close) {
		jhd_top_log.close(&jhd_top_log);
	}
	jhd_top_log.level = level;
	jhd_top_log.data = data;
	jhd_top_log.handler = handler;
	jhd_top_log.close = close;
}

void jhd_log_add(jhd_log_t *log) {
	jhd_log_t *ml = &jhd_top_log;

	for (;;) {
		if (ml->next) {
			ml = ml->next;
		} else {
			ml->next = log;
		}
	}

}

void jhd_log_init(){
	memset(&jhd_top_log,0,sizeof(jhd_log_t));
	jhd_top_log.handler = jhd_std_log_handler;
	strcpy(&jhd_top_log_file_name,"/var/jhttpd/jhttpd.log");
}


void jhd_log_change_file(u_char* fn,size_t len){
	if(len<1024){
		strncpy(&jhd_top_log_file_name,fn,len);
	}
}
void jhd_log_swtich_file(){
	u_char   pid_text[20];

	if(jhd_process == JHD_PROCESS_WORKER){
		sprintf(&pid_text,".%d",jhd_pid);
		strcat(&jhd_top_log_file_name,&pid_text);
	}
	jhd_top_log.handler = jhd_log_default_handler;
}


