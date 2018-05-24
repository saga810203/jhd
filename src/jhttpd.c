/*
 * jhttpd.c
 *
 *  Created on: May 22, 2018
 *      Author: root
 */

#include <jhd_core.h>




static jhd_log_t jhd_std_log = {
	(uint16_t)(JHD_LOG_MASK_IN_MASTER | JHD_LOG_MASK_UTIL),
#ifdef JHD_DEBUG
	JHD_LOG_DEBUG,
#else
	JHD_LOG_WARN,
#endif
	jhd_std_log_handler,
	NULL,NULL
};

static char* config_file;

int main(int argc, char * const *argv) {
	jhd_update_time();





}
