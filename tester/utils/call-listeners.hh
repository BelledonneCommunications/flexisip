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

#pragma once

#include "core-assert.hh"

namespace flexisip::tester {

class CallTransferListener : public linphone::CallListener {
public:
	void onTransferStateChanged(const std::shared_ptr<linphone::Call>&, linphone::Call::State state) override;

	[[nodiscard]] AssertionResult assertNotifyReceived(CoreAssert<>& asserter, linphone::Call::State expectedState) {
		mLastState = static_cast<linphone::Call::State>(-1);
		return asserter.iterateUpTo(
		    0x20, [this, &expectedState]() { return LOOP_ASSERTION(mLastState == expectedState); }, std::chrono::seconds{2});
	}

	linphone::Call::State mLastState{};
};

} // namespace flexisip::tester