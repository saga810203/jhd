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
#include <execinfo.h>


static char   jhd_top_log_file_name[1024];

static jhd_log_t jhd_top_log;

static char *jhd_log_level_enum[] = {"ASSERT" "STDERR", " EMERG", " ALERT", "  CRIT", "   ERR", "  WARN", "NOTICE", "  INFO", " DEBUG", };

void _log_out(const char* file_name, const char *func_name, const int line, const uint16_t level,const char* fmt, ...) {
	va_list args;
	char errstr[JHD_MAX_ERROR_STR];
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
	char errstr[ASSERT_MSG_LEN];
	char** strings;
	size_t len;
	jhd_log_t *log;
	log = &jhd_top_log;

//	p = errstr;

	 len  = snprintf(errstr,ASSERT_MSG_LEN,"^^^^^^^^^^^^^^^^^!!BUGGER!!^^^^^^^^^^^^^^^^^\n");


	npstr = backtrace(buffer, JHD_TEMP_ONCE_DEINFE_IN_FUNCTION);
	strings = backtrace_symbols(buffer, npstr);
	if (strings == NULL) {
		len = snprintf(&errstr[len],ASSERT_MSG_LEN - len,"backtrace return 0\n");
	} else {
		len = snprintf(&errstr[len],ASSERT_MSG_LEN - len,"===================backtrace===============================\n");
		for (i = 0; i < npstr; i++) {
			for(j=0; j < i;++j){
				if(len <= (ASSERT_MSG_LEN-2)){
					len = snprintf(&errstr[len],ASSERT_MSG_LEN - len,"\t");
				}else{
					goto do_print;
				}
			}
			if(len <= (ASSERT_MSG_LEN-2)){
				len = snprintf(&errstr[len],ASSERT_MSG_LEN - len,"==> %s\n",(char*)(strings[i]));
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
  	len = snprintf(((char*)errstr), (size_t)(JHD_MAX_ERROR_STR), "===>[%lu]{\n",buf_len);
	log = &jhd_top_log;
	while(log){
		log->handler(log,errstr,len,0,NULL,NULL,0);
		log = log->next;
	}

	len = 0;
	for(i=0; len < buf_len;){
		if(len > (JHD_MAX_ERROR_STR - 10)){
			len = snprintf(&errstr[len], JHD_MAX_ERROR_STR-len,"0x%02X,",buffer[i]);
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






void jhd_log_default_handler(jhd_log_t *log, char* buf, size_t len,const uint16_t level,const char* file_name,const char *func_name,const int line) {
	if(file_name){
		printf("%s %s %s[%d]==>%s\n%s\n",jhd_cache_log_time,jhd_log_level_enum[level], file_name, line, func_name,buf);
	}else{
		printf(buf);
	}
	fflush(stdout);
	//FIXME:impl  write file
}
void jhd_std_log_handler(jhd_log_t *log, char* buf, size_t len,const uint16_t level,const char* file_name, const char *func_name,const int line) {
	if(file_name){
		printf("%s %s %s[%d]==>%s\n%s\n",jhd_cache_log_time,jhd_log_level_enum[level], file_name, line, func_name,buf);
	}else{
		printf("%s\n",buf);
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
	strcpy(jhd_top_log_file_name,"/var/jhttpd/jhttpd.log");
}


void jhd_log_change_file(char* fn,size_t len){
	if(len<1024){
		strncpy(jhd_top_log_file_name,fn,len);
	}
}
void jhd_log_swtich_file(){
	char   pid_text[20];
	if(jhd_process == JHD_PROCESS_WORKER){
		sprintf(pid_text,".%d",jhd_pid);
		strcat(jhd_top_log_file_name,pid_text);
	}
    jhd_top_log.level = JHD_LOG_STDERR;
	jhd_top_log.handler = jhd_log_default_handler;
}

























#ifdef JHD_LOG_LEVEL_INFO
  char jhd_log_static_buf[JHD_LOG_STATIC_BUFFER_MAX_SIZE];
  static const char* _JHD_HEX_STR[]={"0x00","0x01","0x02","0x03","0x04","0x05","0x06","0x07","0x08","0x09","0x0A","0x0B","0x0C","0x0D","0x0E","0x0F",
  				"0x10","0x11","0x12","0x13","0x14","0x15","0x16","0x17","0x18","0x19","0x1A","0x1B","0x1C","0x1D","0x1E","0x1F",
  				"0x20","0x21","0x22","0x23","0x24","0x25","0x26","0x27","0x28","0x29","0x2A","0x2B","0x2C","0x2D","0x2E","0x2F",
  				"0x30","0x31","0x32","0x33","0x34","0x35","0x36","0x37","0x38","0x39","0x3A","0x3B","0x3C","0x3D","0x3E","0x3F",
  				"0x40","0x41","0x42","0x43","0x44","0x45","0x46","0x47","0x48","0x49","0x4A","0x4B","0x4C","0x4D","0x4E","0x4F",
  				"0x50","0x51","0x52","0x53","0x54","0x55","0x56","0x57","0x58","0x59","0x5A","0x5B","0x5C","0x5D","0x5E","0x5F",
  				"0x60","0x61","0x62","0x63","0x64","0x65","0x66","0x67","0x68","0x69","0x6A","0x6B","0x6C","0x6D","0x6E","0x6F",
  				"0x70","0x71","0x72","0x73","0x74","0x75","0x76","0x77","0x78","0x79","0x7A","0x7B","0x7C","0x7D","0x7E","0x7F",
  				"0x80","0x81","0x82","0x83","0x84","0x85","0x86","0x87","0x88","0x89","0x8A","0x8B","0x8C","0x8D","0x8E","0x8F",
  				"0x90","0x91","0x92","0x93","0x94","0x95","0x96","0x97","0x98","0x99","0x9A","0x9B","0x9C","0x9D","0x9E","0x9F",
  				"0xA0","0xA1","0xA2","0xA3","0xA4","0xA5","0xA6","0xA7","0xA8","0xA9","0xAA","0xAB","0xAC","0xAD","0xAE","0xAF",
  				"0xB0","0xB1","0xB2","0xB3","0xB4","0xB5","0xB6","0xB7","0xB8","0xB9","0xBA","0xBB","0xBC","0xBD","0xBE","0xBF",
  				"0xC0","0xC1","0xC2","0xC3","0xC4","0xC5","0xC6","0xC7","0xC8","0xC9","0xCA","0xCB","0xCC","0xCD","0xCE","0xCF",
  				"0xD0","0xD1","0xD2","0xD3","0xD4","0xD5","0xD6","0xD7","0xD8","0xD9","0xDA","0xDB","0xDC","0xDD","0xDE","0xDF",
  				"0xE0","0xE1","0xE2","0xE3","0xE4","0xE5","0xE6","0xE7","0xE8","0xE9","0xEA","0xEB","0xEC","0xED","0xEE","0xEF",
  				"0xF0","0xF1","0xF2","0xF3","0xF4","0xF5","0xF6","0xF7","0xF8","0xF9","0xFA","0xFB","0xFC","0xFD","0xFE","0xFF",
  };

  void jhd_log_gen_buf(char* title,void *buf,size_t len)
  {
  	size_t i ,slen;
  	unsigned char *p=buf;
  	const char *s;
  	slen = 0;
  	slen += snprintf(((char*)(&jhd_log_static_buf[slen])),(size_t)(JHD_LOG_STATIC_BUFFER_MAX_SIZE-slen),"%s:[%ld]{",title,len);
  	for(i=0;i < len ;++i){
  		s = _JHD_HEX_STR[p[i]];
  		slen += snprintf(((char*)(&jhd_log_static_buf[slen])),(size_t)(JHD_LOG_STATIC_BUFFER_MAX_SIZE-slen),"%s,",s);
  		if(((i+1) % 16)==0){
  			slen += snprintf(((char*)(&jhd_log_static_buf[slen])),(size_t)(JHD_LOG_STATIC_BUFFER_MAX_SIZE-slen),"\n");
  		}
  	}
  	slen += snprintf(((char*)(&jhd_log_static_buf[slen])),(size_t)(JHD_LOG_STATIC_BUFFER_MAX_SIZE-slen),"}\n");
  }
#endif
