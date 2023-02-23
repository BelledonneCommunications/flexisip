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

#pragma once

#include <sys/timeb.h>

#include <cstdarg>
#include <cstdlib>
#include <map>
#include <string>
#include <vector>

#include "flexisip/logmanager.hh"

#ifndef MAX
#define MAX(a, b) (a) > (b) ? (a) : (b)
#endif

time_t getCurrentTime();
time_t getTimeOffset(time_t current_time);

namespace flexisip {

class Mutex {
public:
	Mutex(bool reentrant = false);
	void lock();
	void unlock();
	~Mutex();

private:
	const bool mReentrant;
	pthread_t mThread;
	int mCount;
	pthread_mutex_t mMutex;
	pthread_mutex_t mInternalMutex;
};

template <typename _type>
class delete_functor {
public:
	void operator()(_type* obj) {
		delete obj;
	}
};

template <typename _first, typename _last>
class map_delete_functor {
public:
	void operator()(std::pair<_first, _last> obj) {
		delete obj.second;
	}
};

#define RESTART_EXIT_CODE 5

// Helper to get ip from host in a portable binary format.
// It has comparison functions, which makes it suitable to use in std::set or std::map, for fast search.
class BinaryIp {
public:
	/* Adds a hostname in the form of BinaryIp into a generic STL container.
	 If numericOnly is set to true, then no DNS lookup will be made. As a result fully qualified domain names will be
	 ignored.*/
	template <typename _containerT>
	static _containerT& emplace(_containerT& container, const std::string& hostname, bool numericOnly = false) {
		struct addrinfo* ai = resolve(hostname, numericOnly);
		struct addrinfo* ai_it;
		for (ai_it = ai; ai_it != nullptr; ai_it = ai_it->ai_next) {
			container.emplace(ai_it);
		}
		freeaddrinfo(ai);
		return container;
	}
	/* Builds a BinaryIp from a struct addrinfo containing an AF_INET6 address only !.
	 * Do not use directly, use static emplace() method to build BinarIps.*/
	BinaryIp(const struct addrinfo* ai);
	BinaryIp(const char* ip);

	bool operator==(const BinaryIp& ip2) const {
		return memcmp(&mAddr, &ip2.mAddr, sizeof mAddr) == 0;
	}
	bool operator<(const BinaryIp& ip2) const {
		return memcmp(&mAddr, &ip2.mAddr, sizeof mAddr) < 0;
	}
	bool operator<=(const BinaryIp& ip2) const {
		return memcmp(&mAddr, &ip2.mAddr, sizeof mAddr) <= 0;
	}
	bool operator>(const BinaryIp& ip2) const {
		return memcmp(&mAddr, &ip2.mAddr, sizeof mAddr) > 0;
	}
	bool operator>=(const BinaryIp& ip2) const {
		return memcmp(&mAddr, &ip2.mAddr, sizeof mAddr) >= 0;
	}
	// turn hummanely readable IP. This function is not optimized for speed.
	std::string asString() const;

private:
	static struct addrinfo* resolve(const std::string& hostname, bool numericOnly);
	struct in6_addr mAddr;
};

std::ostream& operator<<(std::ostream& os, const flexisip::BinaryIp& ip);
} // namespace flexisip