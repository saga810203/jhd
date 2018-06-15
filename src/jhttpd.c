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


int main(int argc, char * const *argv) {

	jhd_process = JHD_PROCESS_HELPER;

	jhd_log_init();
	jhd_update_time();
	if (!jhd_ssl_init()) {
		return JHD_ERROR;
	}
	jhd_http_init();
	jhd_core_init();
	if (JHD_OK != jhd_conf_parse_default()) {
		jhd_err = 1;
		goto finish;
	}

	if (argc == 2 && strcmp(argv[0], "-s")) {
		return jhd_signal_process(argv[1]);
	}



	if (jhd_run_master_startup_listener() != JHD_OK) {
		jhd_err = 1;
		//TODO:LOG
		goto finish;
	}

	jhd_err = 0;
	if (!jhd_signal_init()) {
		return 1;
	}

	if (jhd_daemonized) {
		if (!jhd_daemon()) {
			return 1;
		}
		jhd_log_swtich_file();
	}
	jhd_process = jhd_single ? JHD_PROCESS_SINGLE : JHD_PROCESS_MASTER;
	if (!jhd_create_pidfile()) {
		return 1;
	}

	jhd_quit = 0;
	if (jhd_process == JHD_PROCESS_SINGLE) {
		jhd_single_process();

	} else {
		jhd_master_process();
	}

	finish: jhd_run_master_shutdown_listener();
	jhd_http_free();
	jhd_ssl_free();
	jhd_free_shm();
	jhd_delete_pidfile();
	jhd_log_close();

	return jhd_err;

}
