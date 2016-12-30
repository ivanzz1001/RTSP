/*************************************************************************
	> File Name: comm.h
	> Author: bxq
	> Mail: 544177215@qq.com 
	> Created Time: Sunday, December 20, 2015 AM07:37:50 CST
 ************************************************************************/

#ifndef __COMM_H__
#define __COMM_H__

#include <stdio.h>

#define dbg(fmt, arg...) do {printf("[DEBUG %s:%d:%s] " fmt, __FILE__, __LINE__, __func__, ##arg);} while(0)
#define info(fmt, arg...) do {printf("[INFO  %s:%d:%s] " fmt, __FILE__, __LINE__, __func__, ##arg);} while(0)
#define warn(fmt, arg...) do {printf("[WARN  %s:%d:%s] " fmt, __FILE__, __LINE__, __func__, ##arg);} while(0)
#define err(fmt, arg...) do {printf("[ERROR %s:%d:%s] " fmt, __FILE__, __LINE__, __func__, ##arg);} while(0)

#endif

