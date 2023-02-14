/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include <cstring>
#include <time.h>

#include "flexisip-config.h"

#include "flexisip/common.hh"

using namespace flexisip;

time_t getCurrentTime() {
#ifdef MONOTONIC_CLOCK_REGISTRATIONS
	struct timespec t;
	if (clock_gettime(CLOCK_MONOTONIC, &t)) {
		LOGE("cannot read monotonic clock");
		return time(NULL);
	}

	return t.tv_sec;
#else
	return time(NULL);
#endif
}

time_t getTimeOffset([[maybe_unused]] time_t current_time) {
	static time_t empty = {0};
#ifdef MONOTONIC_CLOCK_REGISTRATIONS
	time_t offset = time(NULL) - current_time;
#else
	return empty;
#endif
}

namespace flexisip {

Mutex::Mutex(bool reentrant) : mReentrant(reentrant), mCount(0) {
	int err;
	if ((err = pthread_mutex_init(&mMutex, NULL)) != 0) {
		LOGE("pthread_mutex_init(): %s", strerror(errno));
	}
	if (mReentrant) {
		if ((err = pthread_mutex_init(&mInternalMutex, NULL)) != 0) {
			LOGE("pthread_mutex_init(): %s", strerror(errno));
		}
	}
}

Mutex::~Mutex() {
	int err;
	if ((err = pthread_mutex_destroy(&mMutex)) != 0) {
		LOGE("pthread_mutex_destroy(): %s", strerror(errno));
	}
	if (mReentrant) {
		if ((err = pthread_mutex_destroy(&mInternalMutex)) != 0) {
			LOGE("pthread_mutex_destroy(): %s", strerror(errno));
		}
	}
}

void Mutex::lock() {
	int err;
	if (mReentrant) {
		if ((err = pthread_mutex_lock(&mInternalMutex)) != 0) {
			LOGE("pthread_mutex_lock(): %s", strerror(errno));
		}
		if (mThread != pthread_self()) {

			if ((err = pthread_mutex_unlock(&mInternalMutex)) != 0) {
				LOGE("pthread_mutex_unlock(): %s", strerror(errno));
			}

			if ((err = pthread_mutex_lock(&mMutex)) != 0) {
				LOGE("pthread_mutex_lock(): %s", strerror(errno));
			}

			if ((err = pthread_mutex_lock(&mInternalMutex)) != 0) {
				LOGE("pthread_mutex_lock(): %s", strerror(errno));
			}
			mThread = pthread_self();
		}
		mCount++;
		if ((err = pthread_mutex_unlock(&mInternalMutex)) != 0) {
			LOGE("pthread_mutex_unlock(): %s", strerror(errno));
		}
	} else {
		if ((err = pthread_mutex_lock(&mMutex)) != 0) {
			LOGE("pthread_mutex_lock(): %s", strerror(errno));
		}
	}
}

void Mutex::unlock() {
	int err;
	if (mReentrant) {
		if ((err = pthread_mutex_lock(&mInternalMutex)) != 0) {
			LOGE("pthread_mutex_lock(): %s", strerror(errno));
		}
		if (mThread == pthread_self()) {
			if (--mCount == 0) {
				mThread = 0;
				if ((err = pthread_mutex_unlock(&mMutex)) != 0) {
					LOGE("pthread_mutex_unlock(): %s", strerror(errno));
				}
			}
		}
		if ((err = pthread_mutex_unlock(&mInternalMutex)) != 0) {
			LOGE("pthread_mutex_unlock(): %s", strerror(errno));
		}
	} else {
		if ((err = pthread_mutex_unlock(&mMutex)) != 0) {
			LOGE("pthread_mutex_unlock(): %s", strerror(errno));
		}
	}
}

struct addrinfo* BinaryIp::resolve(const std::string& hostname, [[maybe_unused]] bool numericOnly = false) {
	// Warning: IPv6 can use brakets.
	std::string hostnameCopy;
	struct addrinfo* res = NULL;
	if (hostname[0] == '[') hostnameCopy = hostname.substr(1, hostname.size() - 2);
	else hostnameCopy = hostname;
	if ((res = bctbx_name_to_addrinfo(AF_INET6, SOCK_DGRAM, hostnameCopy.c_str(), 0)) == NULL) {
		LOGE("getaddrinfo failed with %s", hostnameCopy.c_str());
	}
	return res;
}

BinaryIp::BinaryIp(const struct addrinfo* ai) {
	mAddr = ((struct sockaddr_in6*)ai->ai_addr)->sin6_addr;
}

BinaryIp::BinaryIp(const char* ip) {
	struct addrinfo* ai = resolve(ip, true);
	if (ai) {
		mAddr = ((struct sockaddr_in6*)ai->ai_addr)->sin6_addr;
		freeaddrinfo(ai);
	} else {
		memset(&mAddr, 0, sizeof(mAddr));
	}
}
std::string BinaryIp::asString() const {
	char ip[64];
	struct sockaddr_in6 addr = {0};
	addr.sin6_family = AF_INET6;
	memcpy(&addr.sin6_addr, (const void*)&mAddr, sizeof(mAddr));
	// might be better to use bctbx_getnameinfo instead
	bctbx_sockaddr_to_printable_ip_address((struct sockaddr*)&addr, sizeof(addr), ip, sizeof(ip));
	return ip;
}
std::ostream& operator<<(std::ostream& os, const BinaryIp& ip) {
	return os << ip.asString();
}

} // namespace flexisip
