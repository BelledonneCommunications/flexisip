/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2017  Belledonne Communications SARL.

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

#include <sofia-sip/su_wait.h>

namespace flexisip {

class ServiceServer {
public:
	ServiceServer(su_root_t* root);
	virtual ~ServiceServer() = default;

	void init();

	//Stop service server
	void stop();

	virtual void _init() = 0;
	virtual void _run() = 0;
	virtual void _stop() = 0;
protected:
	bool mStarted;
	su_root_t* mRoot;
	su_timer_t *mTimer;

	static void timerFunc(su_root_magic_t *magic, su_timer_t *t, ServiceServer* thiz) {
		if (thiz->mStarted) {
			thiz->_run();
		}
	};
};

} //namespace flexisip