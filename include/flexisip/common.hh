
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

#pragma once

#include "logmanager.hh"

#include <cstdlib>
#include <cstdarg>
#include <map>
#include <string>
#include <vector>
#include <sys/timeb.h>

#ifndef MAX
#define MAX(a, b) (a) > (b) ? (a) : (b)
#endif

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

template <typename _type> class delete_functor {
  public:
	void operator()(_type *obj) {
		delete obj;
	}
};

template <typename _first, typename _last> class map_delete_functor {
  public:
	void operator()(std::pair<_first, _last> obj) {
		delete obj.second;
	}
};

#define RESTART_EXIT_CODE 5

time_t getCurrentTime();
time_t getTimeOffset(time_t current_time);

// Helper to get ip from host in a portable binary format.
class BinaryIp {
public:
	// If onlyIpString = true, no address lookups are executed.
	BinaryIp(const char *hostname, bool onlyIpString = false);

	bool operator==(const BinaryIp &ip2) const {
		return !memcmp(&mAddr, &ip2.mAddr, sizeof mAddr);
	}

private:
	struct in6_addr mAddr;
};


std::vector<std::string> split (const std::string &str, const std::string &delimiter);

inline std::vector<std::string> split (const std::string &str, char delimiter) {
	return split(str, std::string(1, delimiter));
}
