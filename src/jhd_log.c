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

static char *jhd_log_level_enum[] = {"ASSERT" "STDERR", " EMERG", " ALERT", "  CRIT", "   ERR", "  WARN", "NOTICE", "  INFO", " DEBUG", };

void _log_out(const char* file_name, const char *func_name, const int line, const uint16_t level,const char* fmt, ...) {
	va_list args;
	char errstr[JHD_MAX_ERROR_STR];
	char **p;
	size_t len;
	jhd_log_t *log;
	log = &jhd_top_log;
 	va_start(args, fmt);
	len = vsnprintf(((char*)errstr), (size_t)(JHD_MAX_ERROR_STR), fmt, args);
	va_end(args);

	if (len >= JHD_MAX_ERROR_STR) {
		len = JHD_MAX_ERROR_STR - 1;
		errstr[JHD_MAX_ERROR_STR - 1] = '\0';
	}
	while(log){
		if(log->level >= level){
			log->handler(log,errstr,len,level,file_name,func_name,line);
		}
		log = log->next;
	}
}
#define ASSERT_MSG_LEN (1024 *10)
#define  JHD_TEMP_ONCE_DEINFE_IN_FUNCTION  200
void _log_assert(const char* file_name, const char *func_name, const int line) {
	int i,j, npstr;
	void* buffer[JHD_TEMP_ONCE_DEINFE_IN_FUNCTION];
	u_char errstr[ASSERT_MSG_LEN],*p;
	char** strings;
	size_t len;
	jhd_log_t *log;
	log = &jhd_top_log;

	p = errstr;

	len = vsnprintf(errstr,ASSERT_MSG_LEN,"^^^^^^^^^^^^^^^^^!!BUGGER!!^^^^^^^^^^^^^^^^^\n");

	npstr = backtrace(buffer, JHD_TEMP_ONCE_DEINFE_IN_FUNCTION);
	strings = backtrace_symbols(buffer, npstr);
	if (strings == NULL) {
		len = vsnprintf(&errstr[len],ASSERT_MSG_LEN - len,"backtrace return 0\n");
	} else {
		len = vsnprintf(&errstr[len],ASSERT_MSG_LEN - len,"===================backtrace===============================\n");
		for (i = 0; i < npstr; i++) {
			for(j=0; j < i;++j){
				if(len <= (ASSERT_MSG_LEN-2)){
					len = vsnprintf(&errstr[len],ASSERT_MSG_LEN - len,"\t");
				}else{
					goto do_print;
				}
			}
			if(len <= (ASSERT_MSG_LEN-2)){
				len = vsnprintf(&errstr[len],ASSERT_MSG_LEN - len,"==> %s\n",strings[i]);
			}else{
				goto do_print;
			}
		}
	}
	if(len < (ASSERT_MSG_LEN-2)){
		errstr[len] = 0;
	}else{
		errstr[ASSERT_MSG_LEN-1] = 0;
	}
	do_print:
	while(log){
		log->handler(log,errstr,len,0,file_name,func_name,line);
		log = log->next;
	}
	exit(1);
}
#undef  JHD_TEMP_ONCE_DEINFE_IN_FUNCTION

#ifdef JHD_LOG_ASSERT_ENABLE
#define  log_assert(ASSERT_VAL) if(!(ASSERT_VAL)) _log_assert((const char*)__FILE__,(const char*)__FUNCTION__ ,(const int)__LINE__)
void log_assert_msg(const char *fmt,...){
  	va_list args;
  	size_t len;
  	jhd_log_t *log;
  	log = &jhd_top_log;
  	char errstr[JHD_MAX_ERROR_STR];
  	len = JHD_MAX_ERROR_STR;
   	va_start(args, fmt);
  	len = vsnprintf(((char*)errstr), (size_t)(JHD_MAX_ERROR_STR), fmt, args);
  	va_end(args);
  	if (len >= JHD_MAX_ERROR_STR) {
  		len = JHD_MAX_ERROR_STR - 1;
  		errstr[JHD_MAX_ERROR_STR - 1] = '\0';
  	}
	while(log){
		log->handler(log,errstr,len,0,NULL,NULL,0);
		log = log->next;
	}
}
void log_assert_buf(const unsigned char *buffer,size_t buf_len,const char *fmt,...){
  	va_list args;
  	size_t len,i;
  	char errstr[JHD_MAX_ERROR_STR];
  	jhd_log_t *log;
  	log = &jhd_top_log;
  	len = JHD_MAX_ERROR_STR;
   	va_start(args, fmt);
  	len = vsnprintf(((char*)errstr), (size_t)(JHD_MAX_ERROR_STR), fmt, args);
  	va_end(args);
  	if (len >= JHD_MAX_ERROR_STR) {
  		len = JHD_MAX_ERROR_STR - 1;
  		errstr[JHD_MAX_ERROR_STR - 1] = '\0';
  	}
	while(log){
		log->handler(log,errstr,len,0,NULL,NULL,0);
		log = log->next;
	}
  	len = vsnprintf(((char*)errstr), (size_t)(JHD_MAX_ERROR_STR), "===>[%lu]{\n",buf_len);
	log = &jhd_top_log;
	while(log){
		log->handler(log,errstr,len,0,NULL,NULL,0);
		log = log->next;
	}

	len = 0;
	for(i=0; len < buf_len;){
		if(len > (JHD_MAX_ERROR_STR - 10)){
			len = vsnprintf(&errstr[len], JHD_MAX_ERROR_STR-len,"0x%02X,",buffer[i]);
		}

		if(len > (JHD_MAX_ERROR_STR - 10)){
			errstr[len] = 0;
			log = &jhd_top_log;
			while(log){
				log->handler(log,errstr,len,0,NULL,NULL,0);
				log = log->next;
			}
		}
		++i;
		if(len %16 ==0){
			errstr[len] ='\n';
			++len;
		}
	}
	errstr[len++] ='}';
	errstr[len++] ='\n';
	log = &jhd_top_log;
	while(log){
		log->handler(log,errstr,len,0,NULL,NULL,0);
		log = log->next;
	}
}
#endif



void jhd_log_default_handler(jhd_log_t *log, u_char* buf, size_t len,uint16_t level,u_char* file_name, u_char *func_name, int line) {
	if(file_name){
		printf("%s %s %s[%d]==>%s\n%s\n",jhd_cache_log_time,jhd_log_level_enum[level], file_name, line, func_name,buf);
	}else{
		printf(buf);
	}
	fflush(stdout);
	//FIXME:impl  write file
}
void jhd_std_log_handler(jhd_log_t *log, u_char* buf, size_t len,uint16_t level, u_char* file_name, u_char *func_name, int line) {
	if(file_name){
		printf("%s %s %s[%d]==>%s\n%s\n",jhd_cache_log_time,jhd_log_level_enum[level], file_name, line, func_name,buf);
	}else{
		printf(buf);
	}
	fflush(stdout);
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
    jhd_top_log.level = JHD_LOG_STDERR;
	jhd_top_log.handler = jhd_log_default_handler;
}


