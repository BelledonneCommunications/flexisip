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

#include "async-stop-core.hh"

namespace flexisip::b2bua {

AsyncStopCore::AsyncStopCore(const std::shared_ptr<linphone::Core>& core) : mCore(core) {
	if (mCore->getGlobalState() != linphone::GlobalState::Off) mCore->stopAsync();
}

bool AsyncStopCore::finished() {
	if (mCore->getGlobalState() == linphone::GlobalState::Off) return true;

	mCore->iterate();
	return mCore->getGlobalState() == linphone::GlobalState::Off;
}

} // namespace flexisip::b2bua
