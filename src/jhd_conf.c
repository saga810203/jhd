/*
 * jhd_conf.c
 *
 *  Created on: May 22, 2018
 *      Author: root
 */

#include <jhd_config.h>
#include <jhd_conf.h>

static jhd_inline void jhd_conf_parse_line(u_char* p, size_t len,
		size_t *out_len, size_t* line_len) {
	int i;
	*out_len = 0;
	*line_len = 0;
	char c;
	for (i = 0; i < len; ++i) {
		c = p[i];
		if (c == '\n') {
			*line_len = i + 1;
			if (i > 1) {
				p = p + i;
				--p;
				if (i) {
					if (*p == '\r') {
						--p;
						--i;
					}
					while (i) {
						c = *p;
						if ((c != ' ') && (c != '\t')) {
							*out_len = i;
							return;
						}
						--p;
						--i;
					}
				}
			}
		}
	}
	return;
}

static jhd_inline void jhd_conf_skip_white(u_char* p, size_t *len) {
	int i = 0;
	for (; i < *len; ++i) {
		if ((p[i] == ' ') || (p[i] == '\t')) {
			continue;
		}
		*len = (*len) - i;
		memmove(p + i, p, *len);
		return;
	}
	*len = 0;
}

int jhd_conf_read(u_char* file_name, jhd_config_handler handler) {
	u_char buffer[JHD_CONFIG_MAX_LINE_SIZE];

	size_t line_no, line_len, data_len, buffer_len;
	off_t off;
	ssize_t n;
	int fd;
	off = 0;
	buffer_len = 0;
	line_no = 1;
	fd = open(file_name, O_RDONLY, 0);
	if (fd != JHD_ERROR) {
		for (;;) {
			jhd_conf_skip_white(&buffer[0], &buffer_len);
			if (buffer_len) {
				jhd_conf_parse_line(&buffer[0], buffer_len, &data_len,
						&line_len);
				if (0 == line_len) {
					if (buffer_len == JHD_CONFIG_MAX_LINE_SIZE) {
						close(fd);
						jhd_err = JHD_ERR_LOGIC_CONF_MAX_LINE_SIZE;
						return JHD_ERROR;
					}
				} else {
					if ((data_len > 0) && (buffer[0] != '#')) {
						if (handler(file_name, &buffer[0], line_len, &buffer[0],
								data_len, line_no) != JHD_OK) {
							close(fd);
							jhd_err = JHD_ERR_LOGIC_CONF_HANDLER_ABORT;
							return JHD_ERROR;
						}
					}
					buffer_len -= line_len;
					++line_no;
					if (buffer_len) {
						continue;
					}
				}
			}
			n = pread(fd, &buffer[buffer_len],
					JHD_CONFIG_MAX_LINE_SIZE - buffer_len, off);
			if (n) {
				if (JHD_ERROR != n) {
					buffer_len += n;
					off += n;
				}
			} else {
				buffer[buffer_len] = '\n';
				++buffer_len;
				close(fd);
				jhd_conf_parse_line(&buffer[0], buffer_len, &data_len,
						&line_len);
				if (data_len) {
					if (handler(file_name, &buffer[0], line_len, &buffer[0],
							data_len, line_no) != JHD_OK) {
						jhd_err = JHD_ERR_LOGIC_CONF_HANDLER_ABORT;
						return JHD_ERROR;
					}
				}
				return JHD_OK;
			}
		}
	}
	jhd_err = JHD_ERR_FILE_OPEN;
	return JHD_ERROR;
}
