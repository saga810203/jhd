/*
 * jhd_conf.c
 *
 *  Created on: May 22, 2018
 *      Author: root
 */

#include <jhd_config.h>
#include <jhd_conf.h>

static jhd_inline void jhd_conf_parse_line(u_char* start, size_t len, u_char** out, size_t *out_len,size_t* line_len) {
	int i;

	u_char *b, *e;
	*out_len = 0;
	*out = NULL;
	b = NULL;
	*line_len = 0;
	char c;

	for(i=0 ; i < len; ++i){
		c = start[i];
		if((c =='\t') ||(c == ' ') ) {
			continue;
		}else {
			len-=i;
			b = start+i;
			*out = b;
			goto found_head;
		}
	}
	return ;

found_head:

    for(i = 0 ;i < len ; ++i){
    	c = b[i];
    	if(c == '\n'){
    		e = b+i;
    		*line_len = (e - start) + 1;
    		goto found_tail;

    	}
    }
    return ;

 found_tail:
    --e;
    if(*e == '\r'){
    	--e;
    }

    while(e <= b){
    	c = *e;
    	if((c == '\t') || (c ==' ')){
    		--e;
    	}else{
    		*out_len = e - b +1;
    	}
    }
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
				jhd_conf_parse_line(&buffer[0],buffer_len,&data,&data_len,&line_len);
				if(0 == line_len){
					if(buffer_len ==JHD_CONFIG_MAX_LINE_SIZE ){
						close(fd);
						return JHD_BUSY;
					}
				}else{
					if(handler(file_name,&buffer[0],line_len,data,data_len,line_no) == JHD_OK){
						buffer_len -=line_len;
						if(buffer_len ){
							memmove(&buffer[0],&buffer[line_len],buffer_len);
							continue;
						}
						++line_no;
					}else {
						close(fd);
						return JHD_OK;
					}
				}

			}
			n = pread(fd, &buffer[buffer_len], JHD_CONFIG_MAX_LINE_SIZE - buffer_len,off);
			if (n) {
				if(JHD_ERROR != n){
					buffer_len+=n;
					off+=n;
				}
			} else {
				buffer[buffer_len] = '\n';
				++buffer_len;
				jhd_conf_parse_line(&buffer[0],buffer_len,&data,&data_len,&line_len);
				handler(file_name,&buffer[0],line_len,data,data_len,line_no);
				close(fd);
				return JHD_OK;
			}
		}

	}
	return JHD_ERROR;
}
