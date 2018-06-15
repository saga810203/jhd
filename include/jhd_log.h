/*
 * jhd_log.h
 *
 *  Created on: May 11, 2018
 *      Author: root
 */

#ifndef JHD_LOG_H_
#define JHD_LOG_H_





#define JHD_LOG_STDERR           	((uint16_t) 0)
#define JHD_LOG_EMERG             	((uint16_t) 1)
#define JHD_LOG_ALERT             	((uint16_t) 2)
#define JHD_LOG_CRIT              	((uint16_t) 3)
#define JHD_LOG_ERR               	((uint16_t) 4)
#define JHD_LOG_WARN              	((uint16_t) 5)
#define JHD_LOG_NOTICE            	((uint16_t) 6)
#define JHD_LOG_INFO              	((uint16_t) 7)
#define JHD_LOG_DEBUG             	((uint16_t) 8)



#define JHD_MAX_ERROR_STR 2048





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


void _log_out(u_char* file_name,u_char *func_name,int line,uint16_t level,const u_char* fmt,...);

void jhd_log_close();

void jhd_log_replace(uint16_t level,log_handler_pt handler,void *data,jhd_obj_free_pt close);

void jhd_log_add(jhd_log_t *log);


void jhd_log_init();


void jhd_log_change_file(u_char* fn,size_t len);

void jhd_log_swtich_file();







#define  log_write(level,fmt,...)	_log_out(__FILE__,__FUNCTION__,__LINE__,level,fmt,__VA_ARGS__)
#define  log_debug(fmt,...)	_log_out(__FILE__,__FUNCTION__,__LINE__,JHD_LOG_DEBUG,fmt,__VA_ARGS__)
#define  log_info(fmt,...)	_log_out(__FILE__,__FUNCTION__,__LINE__,JHD_LOG_INFO,fmt,__VA_ARGS__)
#define  log_notice(fmt,...)	_log_out(__FILE__,__FUNCTION__,__LINE__,JHD_LOG_NOTICE,fmt,__VA_ARGS__)
#define  log_warn(fmt,...)	_log_out(__FILE__,__FUNCTION__,__LINE__,JHD_LOG_WARN,fmt,__VA_ARGS__)
#define  log_err(fmt,...)	_log_out(__FILE__,__FUNCTION__,__LINE__,JHD_LOG_ERR,fmt,__VA_ARGS__)
#define  log_crit(fmt,...)	_log_out(__FILE__,__FUNCTION__,__LINE__,JHD_LOG_CRIT,fmt,__VA_ARGS__)
#define  log_alert(fmt,...)	_log_out(__FILE__,__FUNCTION__,__LINE__,JHD_LOG_ALERT,fmt,__VA_ARGS__)
#define  log_emerg(fmt,...)	_log_out(__FILE__,__FUNCTION__,__LINE__,JHD_LOG_EMERG,fmt,__VA_ARGS__)
#define  log_stderr(fmt,...)	_log_out(__FILE__,__FUNCTION__,__LINE__,JHD_LOG_STDERR,fmt,__VA_ARGS__)







extern jhd_log_t  *main_log;





#endif /* JHD_LOG_H_ */
