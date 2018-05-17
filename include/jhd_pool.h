/*
 * jhd_pool.h
 *
 *  Created on: May 14, 2018
 *      Author: root
 */

#ifndef JHD_POOL_H_
#define JHD_POOL_H_


#define MEM_SIZE_PTR(p) (((u_char*)(p))-2)

#define  MEM_SIZE(p)   (*((u_int16_t*)MEM_SIZE_PTR(p)))



	void* jhd_malloc(size_t  size);
	void* jhd_calloc(size_t  size);
	void  jhd_free(void* ptr);


#endif /* JHD_POOL_H_ */
