/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2025 Belledonne Communications SARL, All rights reserved.

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

#include <memory>

#include "linphone++/linphone.hh"
#include "service-server/async-cleanup.hh"

namespace flexisip::b2bua {

/// Instructs the linphone::Core to shutdown and iterates it until it reaches linphone::GlobalState::Off
class AsyncStopCore : public AsyncCleanup {
public:
	AsyncStopCore(const std::shared_ptr<linphone::Core>&);

	bool finished() override;

private:
	std::shared_ptr<linphone::Core> mCore;
};

} // namespace flexisip::b2bua