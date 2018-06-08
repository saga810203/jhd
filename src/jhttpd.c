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

	jhd_process = JHD_PROCESS_HELPER;


	jhd_update_time();
	jhd_core_init();
	if (JHD_OK != jhd_conf_parse_default()) {
		jhd_err = 1;
		goto finish;
	}

	if(argc == 2 && strcmp(argv[0],"-s")){
		return  jhd_signal_process(argv[1]);
	}


	if(jhd_run_master_startup_listener()!=JHD_OK){
		jhd_err = 1;
		//TODO:LOG
		goto finish;
	}

	jhd_err = 0;
	if(!jhd_signal_init()){
		return 1;
	}

	if(jhd_daemonized){
		if(!jhd_daemon()){
			return 1;
		}
	}
	jhd_process = jhd_single ? JHD_PROCESS_SINGLE : JHD_PROCESS_MASTER;
	if(!jhd_create_pidfile()){
		return 1;
	}



	jhd_quit = 0;
    if (jhd_process == JHD_PROCESS_SINGLE) {
        jhd_single_process();

    } else {
        jhd_master_process();
    }

	finish: jhd_run_master_shutdown_listener();
	jhd_free_shm();
	jhd_delete_pidfile();

	return jhd_err;

}
