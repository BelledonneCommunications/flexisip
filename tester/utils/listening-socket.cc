/*
 Flexisip, a flexible SIP proxy server with media capabilities.
 Copyright (C) 2010-2021  Belledonne Communications SARL, All rights reserved.

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
#include "listening-socket.hh"

#include <cstdlib>

#include <arpa/inet.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace std;
using namespace flexisip;

void ListeningSocket::listenUntil(promise<void>& barrier) {
	int sock;
	struct sockaddr_in addr;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(3000);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("Unable to create socket");
		exit(EXIT_FAILURE);
	}

	if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		perror("Unable to bind");
		exit(EXIT_FAILURE);
	}

	if (listen(sock, 1) < 0) {
		perror("Unable to listen");
		exit(EXIT_FAILURE);
	}

	std::future<void> barrier_future = barrier.get_future();
	barrier_future.wait();

	close(sock);
}
