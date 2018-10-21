/*
 * jhd_log.h
 *
 *  Created on: May 11, 2018
 *      Author: root
 */

#ifndef JHD_LOG_H_
#define JHD_LOG_H_

#define JHD_LOG_LEVEL_DEBUG
#define JHD_LOG_ASSERT_ENABLE

#define JHD_LOG_TEST_ENABLE



#ifdef JHD_LOG_LEVEL_EMERG
#define JHD_LOG_LEVEL_STDERR
#endif

#ifdef JHD_LOG_LEVEL_ALERT
#define JHD_LOG_LEVEL_EMERG
#endif


#ifdef JHD_LOG_LEVEL_CRIT
#define JHD_LOG_LEVEL_ALERT
#define JHD_LOG_LEVEL_EMERG
#define JHD_LOG_LEVEL_STDERR
#endif


#ifdef JHD_LOG_LEVEL_ERR
#define JHD_LOG_LEVEL_CRIT
#define JHD_LOG_LEVEL_ALERT
#define JHD_LOG_LEVEL_EMERG
#define JHD_LOG_LEVEL_STDERR
#endif


#ifdef JHD_LOG_LEVEL_WARN
#define JHD_LOG_LEVEL_ERR
#define JHD_LOG_LEVEL_CRIT
#define JHD_LOG_LEVEL_ALERT
#define JHD_LOG_LEVEL_EMERG
#define JHD_LOG_LEVEL_STDERR
#endif

#ifdef JHD_LOG_LEVEL_NOTICE
#define JHD_LOG_LEVEL_WARN
#define JHD_LOG_LEVEL_ERR
#define JHD_LOG_LEVEL_CRIT
#define JHD_LOG_LEVEL_ALERT
#define JHD_LOG_LEVEL_EMERG
#define JHD_LOG_LEVEL_STDERR
#endif

#ifdef JHD_LOG_LEVEL_INFO
#define JHD_LOG_LEVEL_NOTICE
#define JHD_LOG_LEVEL_WARN
#define JHD_LOG_LEVEL_ERR
#define JHD_LOG_LEVEL_CRIT
#define JHD_LOG_LEVEL_ALERT
#define JHD_LOG_LEVEL_EMERG
#define JHD_LOG_LEVEL_STDERR
#endif


#ifdef JHD_LOG_LEVEL_DEBUG
#define JHD_LOG_LEVEL_INFO
#define JHD_LOG_LEVEL_NOTICE
#define JHD_LOG_LEVEL_WARN
#define JHD_LOG_LEVEL_ERR
#define JHD_LOG_LEVEL_CRIT
#define JHD_LOG_LEVEL_ALERT
#define JHD_LOG_LEVEL_EMERG
#define JHD_LOG_LEVEL_STDERR
#endif




void log_buf(void* buf,size_t len);




#define JHD_LOG_STDERR           	((uint16_t) 0)
#define JHD_LOG_EMERG             	((uint16_t) 1)
#define JHD_LOG_ALERT             	((uint16_t) 2)
#define JHD_LOG_CRIT              	((uint16_t) 3)
#define JHD_LOG_ERR               	((uint16_t) 4)
#define JHD_LOG_WARN              	((uint16_t) 5)
#define JHD_LOG_NOTICE            	((uint16_t) 6)
#define JHD_LOG_INFO              	((uint16_t) 7)
#define JHD_LOG_DEBUG             	((uint16_t) 8)



#define JHD_MAX_ERROR_STR 10240







void _log_out(const char* file_name,const char *func_name,const int line,const uint16_t level,const char* fmt,...);





void _log_assert(const char* file_name,const char *func_name,const int line);



#define  log_write(level,fmt,...)	_log_out((const char*)__FILE__,(const char*)__FUNCTION__ ,(const int) __LINE__,(const uint16_t)level,(const char*)fmt,##__VA_ARGS__)

#ifdef JHD_LOG_LEVEL_DEBUG
#define  log_debug(fmt,...)	_log_out((const char*)__FILE__,(const char*)__FUNCTION__ ,(const int)__LINE__,(const uint16_t)JHD_LOG_DEBUG,(const char*)fmt,##__VA_ARGS__)
#else
#define  log_debug(fmt,...)
#endif
#ifdef JHD_LOG_LEVEL_INFO
#define  log_info(fmt,...)	_log_out((const char*)__FILE__,(const char*)__FUNCTION__ ,(const int)__LINE__,(const uint16_t)JHD_LOG_INFO,(const char*)fmt,##__VA_ARGS__)
#else
#define  log_info(fmt,...)
#endif
#ifdef JHD_LOG_LEVEL_NOTICE
#define  log_notice(fmt,...)	_log_out((const char*)__FILE__,(const char*)__FUNCTION__ ,(const int)__LINE__,(const uint16_t)JHD_LOG_NOTICE,(const char*)fmt,##__VA_ARGS__)
#else
#define  log_notice(fmt,...)
#endif
#ifdef JHD_LOG_LEVEL_WARN
#define  log_warn(fmt,...)	_log_out((const char*)__FILE__,(const char*)__FUNCTION__ ,(const int)__LINE__,(const uint16_t)JHD_LOG_WARN,(const char*)fmt,##__VA_ARGS__)
#else
#define  log_warn(fmt,...)
#endif
#ifdef JHD_LOG_LEVEL_ERR
#define  log_err(fmt,...)	_log_out((const char*)__FILE__,(const char*)__FUNCTION__ ,(const int)__LINE__,(const uint16_t)JHD_LOG_ERR,(const char*)fmt,##__VA_ARGS__)
#else
#define  log_err(fmt,...)
#endif
#ifdef JHD_LOG_LEVEL_CRIT
#define  log_crit(fmt,...)	_log_out((const char*)__FILE__,(const char*)__FUNCTION__ ,(const int)__LINE__,(const uint16_t)JHD_LOG_CRIT,(const char*)fmt,##__VA_ARGS__)
#else
#define  log_crit(fmt,...)
#endif
#ifdef JHD_LOG_LEVEL_ALERT
#define  log_alert(fmt,...)	_log_out((const char*)__FILE__,(const char*)__FUNCTION__ ,(const int)__LINE__,(const uint16_t)JHD_LOG_ALERT,(const char*)fmt,##__VA_ARGS__)
#else
#define  log_alert(fmt,...)
#endif
#ifdef JHD_LOG_LEVEL_EMERG
#define  log_emerg(fmt,...)	_log_out((const char*)__FILE__,(const char*)__FUNCTION__ ,(const int)__LINE__,(const uint16_t)JHD_LOG_EMERG,(const char*)fmt,##__VA_ARGS__)
#else
#define  log_emerg(fmt,...)
#endif
#ifdef JHD_LOG_LEVEL_STDERR
#define  log_stderr(fmt,...)	_log_out((const char*)__FILE__,(const char*)__FUNCTION__ ,(const int)__LINE__,(const uint16_t)JHD_LOG_STDERR,(const char*)fmt,##__VA_ARGS__)
#else
#define  log_stderr(fmt,...)
#endif
#ifdef JHD_LOG_ASSERT_ENABLE
#define  log_assert(ASSERT_VAL) if(!(ASSERT_VAL)) _log_assert((const char*)__FILE__,(const char*)__FUNCTION__ ,(const int)__LINE__)
void log_assert_msg(const  char *fmt,...);
void log_assert_buf(const unsigned char *buffer,size_t len,const char *fmt,...);
#else
#define  log_assert(assert_value)
#endif




#ifdef JHD_LOG_LEVEL_INFO
#define JHD_LOG_STATIC_BUFFER_MAX_SIZE (1024*1024)
extern  char jhd_log_static_buf[JHD_LOG_STATIC_BUFFER_MAX_SIZE];
void jhd_log_gen_buf(char* title,void *buf,size_t len);
#define log_mpi_info(TITLE,XXX)            \
	memset(jhd_log_static_buf,0,JHD_LOG_STATIC_BUFFER_MAX_SIZE);\
	jhd_tls_mpi_write_string(XXX,10,jhd_log_static_buf,JHD_LOG_STATIC_BUFFER_MAX_SIZE);\
    log_info("%s\n%s\n",TITLE,jhd_log_static_buf)

#define log_buf_info(TITLE,BUF,LEN) jhd_log_gen_buf(TITLE,BUF,LEN);log_info(jhd_log_static_buf)
#else
#define  log_mpi_info(TITLE,XXX)
#define log_buf_info(TITLE,BUF,LEN)
#endif

#ifdef JHD_LOG_LEVEL_DEBUG
#define log_mpi_debug(TITLE,XXX)            \
	memset(jhd_log_static_buf,0,JHD_LOG_STATIC_BUFFER_MAX_SIZE);\
	jhd_tls_mpi_write_string(XXX,10,jhd_log_static_buf,JHD_LOG_STATIC_BUFFER_MAX_SIZE);\
    log_debug("%s\n%s\n",TITLE,jhd_log_static_buf)

#define log_buf_debug(TITLE,BUF,LEN) jhd_log_gen_buf(TITLE,BUF,LEN);log_debug(jhd_log_static_buf)
#else
#define  log_mpi_debug(TITLE,XXX)
#define log_buf_debug(TITLE,BUF,LEN)
#endif




#ifdef JHD_LOG_TEST_ENABLE

#define log_test_out(T,F,...) printf((const char*)T);printf((const char*)T,##__VA_ARGS__)
void log_test_buf(void *title,unsigned char *buf, size_t len);

#else

#define log_test_out(T,F,...)

#define log_test_buf(T,B,L)

#endif


typedef struct jhd_log_s  jhd_log_t;
// JHD_OK do next log   JHD_ERROR  don‘t next log
typedef void (*log_handler_pt)(jhd_log_t *log,u_char* buf,size_t len,u_char* file_name,u_char *func_name,int line);

struct jhd_log_s{
		uint16_t  			level;
		log_handler_pt 		handler;
		void				*data;
		jhd_log_t			*next;
		jhd_obj_free_pt		close;

};




void jhd_log_default_handler(jhd_log_t  *log,u_char* buf,size_t len,u_char* file_name,u_char *func_name,int line);

void jhd_log_close();

void jhd_log_replace(uint16_t level,log_handler_pt handler,void *data,jhd_obj_free_pt close);

void jhd_log_add(jhd_log_t *log);


void jhd_log_init();


void jhd_log_change_file(u_char* fn,size_t len);

void jhd_log_swtich_file();


extern jhd_log_t  *main_log;

#endif /* JHD_LOG_H_ */
