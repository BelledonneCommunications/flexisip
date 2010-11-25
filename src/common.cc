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

#include <stdarg.h>
#include <stdio.h>

#include "common.hh"

Mutex::Mutex(){
	int err;
	if ((err=pthread_mutex_init(&mMutex,NULL))!=0){
		LOGE("pthread_mutex_init(): %s",strerror(errno));
	}
}

Mutex::~Mutex(){
	int err;
	if ((err=pthread_mutex_destroy(&mMutex))!=0){
		LOGE("pthread_mutex_destroy(): %s",strerror(errno));
	}
}

void Mutex::lock(){
	int err;
	if ((err=pthread_mutex_lock(&mMutex))!=0){
		LOGE("pthread_mutex_lock(): %s",strerror(errno));
	}
}

void Mutex::unlock(){
	int err;
	if ((err=pthread_mutex_unlock(&mMutex))!=0){
		LOGE("pthread_mutex_unlock(): %s",strerror(errno));
	}
}

