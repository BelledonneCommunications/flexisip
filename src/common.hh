/*
	Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010  Belledonne Communications SARL.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/


#ifndef PROXY_COMMON_H
#define PROXY_COMMON_H

#include <cstdlib>
#include <cstdarg>
#include <ortp/ortp.h>

extern bool sUseSyslog;

#define LOGD ortp_message
#define LOGI ortp_message
#define LOGW ortp_warning
#define LOGE ortp_error
#define LOGA ortp_fatal

#define IS_LOGD ortp_log_level_enabled(ORTP_DEBUG)
/* 
 *We want LOGN to output all the time: this is for startup notice.
 */
#define LOGN(args...) do{ \
	ortp_message(args); \
	if (sUseSyslog){ \
		syslog(LOG_NOTICE,args); \
	}else{ \
		fprintf(stdout,args); \
		fprintf(stdout,"\n"); \
	}\
}while(0);
/** LOGF must be used to report any startup or configuration fatal error that needs to be seen by the operator.
 * This is why it goes to syslog (if syslog is used) and standart output.
**/
#define LOGF(args...) do{ \
	ortp_error(args); \
	if (sUseSyslog){ \
		fprintf(stderr,args); \
		fprintf(stderr,"\n"); \
	}\
	exit(-1); \
}while(0);

class Mutex{
	public:
		Mutex();
		void lock();
		void unlock();
		~Mutex();
	private:
		pthread_mutex_t mMutex;
};

template <typename _type>
class delete_functor{
	public:
		void operator()(_type *obj){
			delete obj;
		}
};



#endif
