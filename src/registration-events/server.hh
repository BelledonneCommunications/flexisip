/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2010-2020  Belledonne Communications SARL, All rights reserved.

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

#include <linphone++/linphone.hh>

#include "service-server.hh"

namespace flexisip {

namespace RegistrationEvent {
	
class Server : public ServiceServer
, public std::enable_shared_from_this<Server>
, public linphone::CoreListener {
	public:
		static const std::string CONTENT_TYPE;

		template <typename SuRootPtr> Server(SuRootPtr&& root) : ServiceServer{std::forward<SuRootPtr>(root)} {}

		void onSubscribeReceived(
			const std::shared_ptr<linphone::Core> & lc,
			const std::shared_ptr<linphone::Event> & lev,
			const std::string & subscribeEvent,
			const std::shared_ptr<const linphone::Content> & body
		) noexcept override;

		protected:
		void _init () override;
		void _run () override;
		void _stop () override;

	private:
	class Init {
	public:
		Init();
	};
	static Init sStaticInit;
	std::shared_ptr<linphone::Core> mCore;
};

}

}
