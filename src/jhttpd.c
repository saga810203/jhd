/*
 * jhttpd.c
 *
 *  Created on: May 22, 2018
 *      Author: root
 */

#include <jhd_core.h>
#include <jhd_log.h>
#include <jhd_conf.h>
#include <jhd_connection.h>
#include <jhd_ssl.h>
#include <jhd_shm.h>

static jhd_log_t jhd_std_log = { (uint16_t) (JHD_LOG_MASK_IN_MASTER | JHD_LOG_MASK_UTIL),
#ifdef JHD_DEBUG
        JHD_LOG_DEBUG,
#else
        JHD_LOG_WARN,
#endif
        jhd_std_log_handler,
        NULL, NULL };



















int main(int argc, char * const *argv) {
	jhd_update_time();
	jhd_core_init();
	if (JHD_OK != jhd_conf_parse_default()) {
		jhd_err = 1;
		goto finish;
	}




	if(jhd_run_master_startup_listener()!=JHD_OK){
		jhd_err = 1;
		//TODO:LOG
		goto finish;
	}

	jhd_err = 0;
	//TODO handle argv









	finish: jhd_run_master_shutdown_listener();
	jhd_free_shm();

	return jhd_err;

}
