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
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <csignal>
#include <stdexcept>
#include <thread>

#include <sys/wait.h>
#include <unistd.h>

#include "bctoolbox/tester.h"
#include "flexisip/logmanager.hh"

#include "utils/server/proxy-server.hh"

#include "proxy-server-process.hh"

using namespace std;

namespace flexisip {
namespace tester {

ProxyServerProcess::ProxyServerProcess() {
	BC_ASSERT_EQUAL(pipe(mPipeFds), 0, int, "%i");
}

ProxyServerProcess::~ProxyServerProcess() {
	terminate();
	close(mPipeFds[0]);
	close(mPipeFds[1]);
}

void ProxyServerProcess::spawn(const std::map<std::string, std::string>& config) {
	using namespace std::chrono;

	mPID = fork();
	if (mPID == 0) {
		bctbx_set_log_handler([](const char* domain, BctbxLogLevel lev, const char* fmt, va_list args) {
			auto newDomain = string{"remote-proxy:"} + domain;
			bctbx_logv_out(newDomain.c_str(), lev, fmt, args);
		});
		Server proxy{config};
		proxy.start();
		notify();
		SLOGD << "RUN MAIN LOOP";
		proxy.getRoot()->run();
	} else {
		this->wait();
	}
}
void ProxyServerProcess::terminate() {
	if (mPID > 0) {
		kill(mPID, SIGKILL);
		mPID = 0;
	}
}

void ProxyServerProcess::pause() {
	if (mPID > 0) {
		kill(mPID, SIGSTOP);
	}
	waitid(P_PID, mPID, nullptr, WSTOPPED);
}

void ProxyServerProcess::unpause() {
	if (mPID > 0) {
		kill(mPID, SIGCONT);
	}
	waitid(P_PID, mPID, nullptr, WCONTINUED);
}

void ProxyServerProcess::notify() {
	if (mPID > 0) throw logic_error{"notify(): not a child"};
	const auto msg = string{"OK"};
	const auto bytesWritten = write(mPipeFds[1], msg.c_str(), msg.size());
	BC_ASSERT_EQUAL(bytesWritten, msg.size(), ssize_t, "%zi");
}
void ProxyServerProcess::wait() {
	using namespace std::chrono;

	if (mPID == 0) throw logic_error{"wait(): not a parent"};

	fcntl(mPipeFds[0], F_SETFL, O_NONBLOCK);

	int nread = -1;

	char buffer[2];
	const auto startTime = steady_clock::now();
	while (steady_clock::now() - startTime <= 2s) {
		nread = read(mPipeFds[0], buffer, sizeof(buffer));
		if (nread < 0 && errno == EAGAIN) nread = 0;
		if (nread > 0) break;
		this_thread::sleep_for(10ms);
	}

	if (nread <= 0) {
		throw runtime_error{"Flexisip failed to start"};
	}
}

} // namespace tester
} // namespace flexisip
