/*
 * jhd_conf.h
 *
 *  Created on: May 22, 2018
 *      Author: root
 */

#ifndef JHD_CONF_H_
#define JHD_CONF_H_


#define  JHD_CONFIG_MAX_LINE_SIZE 8192

#define  JHD_CONF_DEFAULT_CONFIG_FILE "/etc/jhttpd/jhttpd.conf"
#define  JHD_CONF_CONFIG_FILE_ENV_NAME "JHTTPD_CONFIG_FILE"



typedef struct jhd_config_item_s jhd_config_item_t;




typedef int (*jhd_config_handler_pt)(u_char* file_name,u_char* line,size_t line_len,u_char* data,size_t data_len,off_t line_no);


typedef jhd_config_item_t* (*jhd_config_start_child_handler_pt)(jhd_config_item_t* parent,u_char *str_start,size_t len);
typedef int (*jhd_config_set_value_handler_pt)(jhd_config_item_t *config,u_char *name_start,size_t name_len,u_char *value_start,size_t value_len);
typedef int (*jhd_config_over_handler_pt)(jhd_config_item_t *config);




struct jhd_config_item_s{
		jhd_config_item_t  *parent_config_item;
		void   *data;
		jhd_config_start_child_handler_pt  child_handler;
		jhd_config_set_value_handler_pt  value_handler;
		jhd_config_over_handler_pt       over_handler;
};



typedef int (*jhd_config_handler_pt)(u_char* file_name,u_char* line,size_t line_len,u_char* data,size_t data_len,off_t line_no);


int jhd_conf_parse(jhd_config_handler_pt handler);

int jhd_conf_parse_default();





#endif /* JHD_CONF_H_ */
