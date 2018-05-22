/*
 * jhd_conf.h
 *
 *  Created on: May 22, 2018
 *      Author: root
 */

#ifndef JHD_CONF_H_
#define JHD_CONF_H_


#define  JHD_CONFIG_MAX_LINE_SIZE 8192

//
//struct  jhd_conf_command_s{
//	u_char block;
//
//
//}





typedef int (*jhd_config_handler)(u_char* file_name,u_char* line,size_t line_len,u_char* data,size_t data_len);



int jhd_conf_read(u_char* file_name,jhd_config_handler handler,u_char* prev_file_name);


#endif /* JHD_CONF_H_ */
