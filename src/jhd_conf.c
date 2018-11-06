/*
 * jhd_conf.c
 *
 *  Created on: May 22, 2018
 *      Author: root
 */
#include <jhd_config.h>

#include <jhd_conf.h>
#include <jhd_connection.h>

#define  JHD_CONF_CONFIG_FILE_ENV_NAME "JHTTPD_CONFIG_FILE"

static u_char  _config_file[]="/etc/jhttpd/jhttpd.conf";

u_char * jhd_config_file=_config_file;

//static jhd_config_item_t* jhd_conf_core_start_child(jhd_config_item_t* parent,u_char *str_start,size_t len);
//static int jhd_conf_core_set_value(jhd_config_item_t *config,u_char *name_start,size_t name_len,u_char *value_start,size_t value_len);
//static int jhd_conf_core_over(jhd_config_item_t *config);
//
//
//
////static jhd_config_item_t  jhd_main_config={
////		NULL,
////		NULL,
////		jhd_conf_core_start_child,
////		jhd_conf_core_set_value,
////		jhd_conf_core_over
////
////};
////
////static const u_char *jhd_config_http_listen = "http_listen";
////static const u_char *jhd_config_https_listen "https_listen";
//
//static jhd_config_item_t* jhd_conf_core_start_child(jhd_config_item_t* parent,u_char *str_start,size_t len){
////	if(jhd_static_string_equals(str_start,len,jhd_config_http_listen,strlen((const char*)jhd_config_http_listen))){
////
////
////
////	}
////	if(jhd_static_string_equals(str_start,len,jhd_config_https_listen,strlen((const char*)jhd_config_https_listen))){
////
////	}
////
////
//	return NULL;
//}
//
//#undef JHD_TMP_HTTP_LISTEN
//#undef JHD_TMP_HTTPS_LISTEN
//
//
//static int jhd_conf_core_set_value(jhd_config_item_t *config,u_char *name_start,size_t name_len,u_char *value_start,size_t value_len);
//static int jhd_conf_core_over(jhd_config_item_t *config);
//
//
//static jhd_inline void jhd_conf_parse_line(u_char* p, size_t len, size_t *out_len, size_t* line_len) {
//	size_t i;
//	*out_len = 0;
//	*line_len = 0;
//	char c;
//	for (i = 0; i < len; ++i) {
//		c = p[i];
//		if (c == '\n') {
//			*line_len = i + 1;
//			if (i > 1) {
//				p = p + i;
//				--p;
//				if (i) {
//					if (*p == '\r') {
//						--p;
//						--i;
//					}
//					while (i) {
//						c = *p;
//						if ((c != ' ') && (c != '\t')) {
//							*out_len = i;
//							return;
//						}
//						--p;
//						--i;
//					}
//				}
//			}
//		}
//	}
//	return;
//}
//
//static jhd_inline void jhd_conf_skip_white(u_char* p, size_t *len) {
//	size_t i = 0;
//	for (; i < *len; ++i) {
//		if ((p[i] == ' ') || (p[i] == '\t')) {
//			continue;
//		}
//		*len = (*len) - i;
//		memmove(p + i, p, *len);
//		return;
//	}
//	*len = 0;
//}
//
//static int jhd_conf_read(const char* file_name, jhd_config_handler_pt handler) {
////	u_char buffer[JHD_CONFIG_MAX_LINE_SIZE];
////
////	size_t line_no, line_len, data_len, buffer_len;
////	off_t off;
////	ssize_t n;
////	int fd;
////	off = 0;
////	buffer_len = 0;
////	line_no = 1;
////	fd = open(file_name, O_RDONLY, 0);
////	if (fd != JHD_ERROR) {
////		for (;;) {
////			jhd_conf_skip_white(&buffer[0], &buffer_len);
////			if (buffer_len) {
////				jhd_conf_parse_line(&buffer[0], buffer_len, &data_len, &line_len);
////				if (0 == line_len) {
////					if (buffer_len == JHD_CONFIG_MAX_LINE_SIZE) {
////						close(fd);
////						log_stderr("")
////						return JHD_ERROR;
////					}
////				} else {
////					if ((data_len > 0) && (buffer[0] != '#')) {
////						if (handler(file_name, &buffer[0], line_len, &buffer[0], data_len, line_no) != JHD_OK) {
////							close(fd);
////							jhd_err = JHD_ERR_LOGIC_CONF_HANDLER_ABORT;
////							return JHD_ERROR;
////						}
////					}
////					buffer_len -= line_len;
////					++line_no;
////					if (buffer_len) {
////						continue;
////					}
////				}
////			}
////			n = pread(fd, &buffer[buffer_len],
////			JHD_CONFIG_MAX_LINE_SIZE - buffer_len, off);
////			if (n) {
////				if (JHD_ERROR != n) {
////					buffer_len += n;
////					off += n;
////				}
////			} else {
////				buffer[buffer_len] = '\n';
////				++buffer_len;
////				close(fd);
////				jhd_conf_parse_line(&buffer[0], buffer_len, &data_len, &line_len);
////				if (data_len) {
////					if (handler(file_name, &buffer[0], line_len, &buffer[0], data_len, line_no) != JHD_OK) {
////						jhd_err = JHD_ERR_LOGIC_CONF_HANDLER_ABORT;
////						return JHD_ERROR;
////					}
////				}
////				return JHD_OK;
////			}
////		}
////	}
////	jhd_err = JHD_ERR_FILE_OPEN;
//	return JHD_ERROR;
//}
//
//
int jhd_conf_parse(jhd_config_handler_pt handler){
//	u_char* file_name;
//	file_name = getenv(JHD_CONF_CONFIG_FILE_ENV_NAME);
//	if(!file_name){
//		jhd_config_file = file_name;
//	}
//	return jhd_conf_read(jhd_config_file,handler);

	return JHD_ERROR;
}



int jhd_conf_default_config_handler(u_char* file_name,u_char* line,size_t line_len,u_char* data,size_t data_len,off_t line_no){

	return JHD_OK;
}


static char *localhost_ipv4_addr_text ="0.0.0.0";
void gen_test_config(){
	jhd_listening_t *lis;
	lis = malloc(sizeof(jhd_listening_t));
	memset(lis,0,sizeof(jhd_listening_t));



	lis->accept_timeout = 1000*60;
	jhd_listening_set_addr_text(lis,(u_char*)localhost_ipv4_addr_text,strlen(localhost_ipv4_addr_text),443);

	lis->backlog = 511;
	lis->rcvbuf = 8192;
	lis->sndbuf = 8192;



}

int jhd_conf_parse_default(){














	return JHD_OK;
}




















