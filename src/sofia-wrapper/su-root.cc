/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022  Belledonne Communications SARL, All rights reserved.

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

#include "flexisip/logmanager.hh"

#include "flexisip/sofia-wrapper/su-root.hh"

using namespace std;

namespace sofiasip {

// This function is not signal-safe. (allocates dynamic memory)
void SuRoot::addToMainLoop(const function<void()>& functionToAdd) {
	su_msg_r msg = SU_MSG_R_INIT;
	if (-1 == su_msg_create(msg, su_root_task(mCPtr), su_root_task(mCPtr), mainLoopFunctionCallback,
	                        sizeof(function<void()>*))) {
		LOGF("Couldn't create auth async message");
	}

	if (-1 == su_msg_deinitializer(msg, mainLoopFunctionCallbackDeinitializer)) {
		LOGF("Couldn't set deinitializer function for message.");
	}

	auto clientCb = reinterpret_cast<function<void()>**>(su_msg_data(msg));
	*clientCb = new function<void()>(functionToAdd);

	if (-1 == su_msg_send(msg)) {
		LOGF("Couldn't send auth async message to main thread.");
	}
}

void SuRoot::mainLoopFunctionCallback([[maybe_unused]] su_root_magic_t* rm, su_msg_t** msg, [[maybe_unused]] void* u) noexcept {
	(**reinterpret_cast<function<void()>**>(su_msg_data(msg)))();
}

void SuRoot::mainLoopFunctionCallbackDeinitializer(su_msg_arg_t* data) noexcept {
	delete *reinterpret_cast<function<void()>**>(data);
}

void SuRoot::addOneShotTimer(const function<void()>& timerFunction, NativeDuration ms) {
	mOneShotTimerList.emplace_back(this->getCPtr(), ms);
	const auto iter = prev(mOneShotTimerList.end());
	iter->set([this, timerFunction, iter]() {
		timerFunction();
		mOneShotTimerList.erase(iter);
	});
}

} // namespace sofiasip
