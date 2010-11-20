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


#define LOGD ortp_message
#define LOGI ortp_message
#define LOGW ortp_warning
#define LOGE ortp_error
#define LOGF ortp_fatal
#define LOGN ortp_message

class Mutex{
	public:
		Mutex(){
			pthread_mutex_init(&mMutex,NULL);
		}
		void lock(){
			pthread_mutex_lock(&mMutex);
		}
		void unlock(){
			pthread_mutex_unlock(&mMutex);
		}
		~Mutex(){
			pthread_mutex_destroy(&mMutex);
		}
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
