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

#include <memory>

#include "flexisip/sofia-wrapper/su-root.hh"
#include "flexisip/utils/timer.hh"

namespace flexisip {

class ServiceServer {
public:
	template <typename SuRootPtr>
	ServiceServer(SuRootPtr&& root) : mRoot{std::forward<SuRootPtr>(root)} {}
	virtual ~ServiceServer() = default;

	void init();

	//Stop service server
	void stop();

	virtual void _init() = 0;
	virtual void _run() = 0;
	virtual void _stop() = 0;
protected:
	bool mStarted{true};
	std::shared_ptr<sofiasip::SuRoot> mRoot{};
	std::unique_ptr<sofiasip::Timer> mTimer{};
};

} //namespace flexisip
