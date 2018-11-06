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
#include <jhd_shm.h>
#include <jhd_process.h>

int jhd_err=0;

int main(int argc, char * const *argv) {
	jhd_process = JHD_PROCESS_HELPER;
	jhd_daemonized = 0;
	jhd_log_init();
	jhd_update_time();
	jhd_core_init();
	if (argc == 3 && strcmp(argv[1], "-s") == 0) {
		return jhd_signal_process(argv[2]);
	}

	if(argc == 2 && strcmp(argv[1],"-daemon") == 0){
		jhd_daemonized = 1;
	}
	jhd_process = JHD_PROCESS_MASTER;
//	if (JHD_OK != jhd_conf_parse_default()) {
//		log_stderr("jhttpd server parse config file[%s] error!!!!!!",jhd_config_file);
//		jhd_err = 1;
//		goto finish;
//	}

	gen_test_config();

	if (jhd_run_master_startup_listener() != JHD_OK) {
		jhd_err = 1;
		log_stderr("jhd start error");
		goto finish;
	}
	jhd_err = 0;
	if (!jhd_init_signals()) {
		jhd_err =1;
		log_stderr("jhd_init_signals() error");
		return 1;
	}

	if (jhd_daemonized) {
		if (!jhd_daemon()) {
			jhd_err =1;
		    goto finish;
		}
		jhd_log_swtich_file();
	}
	if (!jhd_create_pidfile()) {
		return 1;
	}
	if (jhd_single) {
		jhd_single_process();
	} else {
		jhd_master_process();
	}

	finish:
	if(jhd_process == JHD_PROCESS_MASTER){
		jhd_run_master_shutdown_listener();
	}
	jhd_log_close();
	return jhd_err;
}
