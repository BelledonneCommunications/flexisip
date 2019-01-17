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
#include <time.h>
#include <flexisip/common.hh>
#include "flexisip-config.h"
#include <cstring>

using namespace flexisip;

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

time_t getTimeOffset(time_t current_time) {
	static time_t empty = {0};
#ifdef MONOTONIC_CLOCK_REGISTRATIONS
	time_t offset = time(NULL) - current_time;
#else
	return empty;
#endif
}

BinaryIp::BinaryIp(const char *hostname, bool onlyIpString) {
	// Warning: IPv6 can use brakets.
	char *node = hostname[0] != '['
		? (char *)hostname
		: strndup(hostname + 1, strlen(hostname) - 2);

	struct addrinfo hints, *res;

	memset(&mAddr, 0, sizeof mAddr);
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET6; // Only IPv6.
	hints.ai_flags = AI_V4MAPPED; // Transform IPv4 in IPv6.

	// Suppresses host address lookups.
	if (onlyIpString)
		hints.ai_flags |= AI_NUMERICHOST;

	if (getaddrinfo(node, NULL, &hints, &res) != 0)
		LOGE("getaddrinfo failed with %s", hostname);
	else {
		mAddr = ((struct sockaddr_in6 *)res->ai_addr)->sin6_addr;
		freeaddrinfo(res);
	}

	// free IPv6 address with brakets.
	if (node != hostname)
		free(node);
}

std::vector<std::string> flexisip::split (const std::string &str, const std::string &delimiter) {
	std::vector<std::string> out;
	size_t pos = 0, oldPos = 0;
	for (; (pos = str.find(delimiter, pos)) != std::string::npos; oldPos = pos + 1, pos = oldPos)
		out.push_back(str.substr(oldPos, pos - oldPos));
	out.push_back(str.substr(oldPos));
	return out;
}
