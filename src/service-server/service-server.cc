/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/
#include "service-server.hh"

#include <chrono>

#include "flexisip/logmanager.hh"

namespace flexisip {

using namespace std;
using namespace chrono;

void ServiceServer::init() {
	if (mRoot) {
		mTimer = make_unique<sofiasip::Timer>(mRoot, 10ms);
		mTimer->setForEver([this]() {
			if (mStarted) {
				const auto start = high_resolution_clock::now();
				_run();
				const auto stop = high_resolution_clock::now();
				const auto duration = duration_cast<milliseconds>(stop - start);
				if (duration > 50ms) {
					SLOGD << "ServiceServer::_run() - took more than 50ms [" << duration.count() << " ms].";
				} else if (duration > 100ms) {
					SLOGW << "ServiceServer::_run() - took more than 100ms [" << duration.count() << " ms].";
				}
			}
		});
	}
	this->_init();
};

std::unique_ptr<AsyncCleanup> ServiceServer::stop() {
	mStarted = false;
	if (mRoot) {
		mTimer.reset();
	}
	return this->_stop();
};

} // namespace flexisip
