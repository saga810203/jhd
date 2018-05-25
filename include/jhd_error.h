/*
 * jhd_error.h
 *
 *  Created on: 2018年5月24日
 *      Author: root
 */

#ifndef JHD_ERROR_H_
#define JHD_ERROR_H_


#define JHD_ERR_OS  1
#define JHD_ERR_FILE  (JHD_ERR_OS + 100)
#define JHD_ERR_FILE_OPEN   (JHD_ERR_FILE +1)


#define JHD_ERR_SOCKET (JHD_ERR_OS + 200)






#define JHD_ERR_LOGIC  100000
#define JHD_ERR_LOGIC_CONF   JHD_ERR_LOGIC
#define JHD_ERR_LOGIC_CONF_MAX_LINE_SIZE (JHD_ERR_LOGIC_CONF +1)
#define JHD_ERR_LOGIC_CONF_HANDLER_ABORT (JHD_ERR_LOGIC_CONF +2)




#endif /* JHD_ERROR_H_ */
