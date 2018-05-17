/*
 * jhd_string.h
 *
 *  Created on: May 14, 2018
 *      Author: root
 */

#ifndef JHD_STRING_H_
#define JHD_STRING_H_



#define STR_SIZE


#define jhd_string_free(str) if(!((1<<15) & MEM_SIZE(str)))){jhd_free(str);}





#endif /* JHD_STRING_H_ */
