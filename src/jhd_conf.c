/*
 * jhd_conf.c
 *
 *  Created on: May 22, 2018
 *      Author: root
 */

#include <jhd_config.h>
#include <jhd_conf.h>

static jhd_inline void jhd_conf_find_data(u_char* start, size_t len, u_char** out, size_t *out_len) {
	int i;

	u_char *b, *e;
	*out_len = 0;
	*out = NULL;
	b = NULL;

	if (len) {
		char c;
		for(i=0; i < len;++i) {
			c = start[i];
			if((c =='\t') ||(c == ' ') ) {
				continue;
			}
			if(c == '#') {
				return;
			}
			*out = b = &start[i];

			break;
		}
		if (b) {
			e = &start[len - 1];
			for (; e >= b; --e) {
				c = *e;
				if ((c == '\t') || (c == ' ') || (c == '\r')) {
					continue;
				}

				*out_len = e - b + 1;
				break;
			}

		}
	}
	return;

}

int jhd_conf_read(u_char* file_name, jhd_config_handler handler) {
	u_char buffer[JHD_CONFIG_MAX_LINE_SIZE];

	size_t line_no, line_len, data_len,buffer_len;
	off_t off;
	ssize_t n;

	u_char* data;

	int fd;

	off = 0;
	buffer_len = 0;
	line_no = 1;
	fd = open(file_name, O_RDONLY, 0);
	if (fd != JHD_ERROR) {

		for (;;) {
			if (buffer_len) {

			}
			n = pread(fd, &buffer[buffer_len], JHD_CONFIG_MAX_LINE_SIZE - buffer_len,off);
			if (n) {

			} else {
				jhd_conf_find_data(&buffer[0],buffer_len,&data,&data_len);
				if(data_len){
					handler(file_name,&buffer[0],buffer_len,data,data_len);
						return JHD_OK;
				}
			}
		}

	}
	return JHD_ERROR;
}
