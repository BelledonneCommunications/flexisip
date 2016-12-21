/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2010-2016  Belledonne Communications SARL, All rights reserved.

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

#ifndef stats_hh
#define stats_hh

#include <sys/un.h>
#include <pthread.h>
#include <string>
#include "configmanager.hh"

class Stats {
  public:
	Stats();
	~Stats();
	int start();
	void stop();

  private:
	void run();
	void parseAndAnswer(unsigned int socket, const std::string &query);
	GenericEntry* find(GenericStruct *root, std::vector<std::string> &path);
	static void *threadfunc(void *arg);
	
	bool mRunning;
	pthread_t mThread;
	unsigned int local_socket, remote_socket, remote_length;
	struct sockaddr_un local, remote;
	int local_length;
};

#endif
