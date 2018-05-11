/*
 * jhd_log.h
 *
 *  Created on: May 11, 2018
 *      Author: root
 */

#ifndef JHD_LOG_H_
#define JHD_LOG_H_



#define JHD_LOG_MASK_SOURCE_INFO  	((u_int16_t)(1<<15))
#define JHD_LOG_MASK_IN_MASTER 		((u_int16_t)(1<<14))
#define JHD_LOG_MASK_IN_WORKER 		((u_int16_t)(1<<13))
#define JHD_LOG_MASK_UTIL 			((u_int16_t)(1<<12))
#define JHD_LOG_MASK_DOWN 			((u_int16_t)(1<<11))
#define JHD_LOG_MASK_UP 			((u_int16_t)(1<<10))


#define JHD_LOG_STDERR           	((u_int16_t) 0)
#define JHD_LOG_EMERG             	((u_int16_t) 1)
#define JHD_LOG_ALERT             	((u_int16_t) 2)
#define JHD_LOG_CRIT              	((u_int16_t) 3)
#define JHD_LOG_ERR               	((u_int16_t) 4)
#define JHD_LOG_WARN              	((u_int16_t) 5)
#define JHD_LOG_NOTICE            	((u_int16_t) 6)
#define JHD_LOG_INFO              	((u_int16_t) 7)
#define JHD_LOG_DEBUG             	((u_int16_t) 8)



#define JHD_MAX_ERROR_STR 2048





typedef struct jhd_log_s  jhd_log_t;

typedef void (*log_handler_pt)(jhd_log_t *log,u_char* buf,size_t len);

struct jhd_log_s{
		u_int16_t  			mask;
		u_int16_t  			level;
		log_handler_pt 		handler;
		void				*data;
		jhd_log_t			*next;
};



void _log_out(u_char* file_name,u_char *func_name,int line,jhd_log_t *log,u_int16_t log_mask,u_int16_t level,const u_char* fmt,...);


#define  log_write(log,log_mask,level,fmt,...)	_log_out(__FILE__,__FUNCTION__,__LINE__,log,log_mask,level,fmt,__VA_ARGS__)
#define  log_debug(log,log_mask,fmt,...)	_log_out(__FILE__,__FUNCTION__,__LINE__,log,log_mask,JHD_LOG_DEBUG,fmt,__VA_ARGS__)
#define  log_info(log,log_mask,fmt,...)	_log_out(__FILE__,__FUNCTION__,__LINE__,log,log_mask,JHD_LOG_INFO,fmt,__VA_ARGS__)
#define  log_notice(log,log_mask,fmt,...)	_log_out(__FILE__,__FUNCTION__,__LINE__,log,log_mask,JHD_LOG_NOTICE,fmt,__VA_ARGS__)
#define  log_warn(log,log_mask,fmt,...)	_log_out(__FILE__,__FUNCTION__,__LINE__,log,log_mask,JHD_LOG_WARN,fmt,__VA_ARGS__)
#define  log_err(log,log_mask,fmt,...)	_log_out(__FILE__,__FUNCTION__,__LINE__,log,log_mask,JHD_LOG_ERR,fmt,__VA_ARGS__)
#define  log_crit(log,log_mask,fmt,...)	_log_out(__FILE__,__FUNCTION__,__LINE__,log,log_mask,JHD_LOG_CRIT,fmt,__VA_ARGS__)
#define  log_alert(log,log_mask,fmt,...)	_log_out(__FILE__,__FUNCTION__,__LINE__,log,log_mask,JHD_LOG_ALERT,fmt,__VA_ARGS__)
#define  log_emerg(log,log_mask,fmt,...)	_log_out(__FILE__,__FUNCTION__,__LINE__,log,log_mask,JHD_LOG_EMERG,fmt,__VA_ARGS__)
#define  log_stderr(log,log_mask,fmt,...)	_log_out(__FILE__,__FUNCTION__,__LINE__,log,log_mask,level,STDERR,__VA_ARGS__)







extern jhd_log_t  *main_log;





#endif /* JHD_LOG_H_ */
