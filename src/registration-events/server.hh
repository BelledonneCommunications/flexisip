/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023 Belledonne Communications SARL, All rights reserved.

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
#include <unordered_map>

#include <linphone++/linphone.hh>

#include "registration-events/registrar/listener.hh"
#include "service-server.hh"

namespace flexisip {

namespace RegistrationEvent {

class Server : public ServiceServer {
public:
	class Subscriptions : public std::enable_shared_from_this<Subscriptions>, public linphone::CoreListener {
	private:
		void onSubscribeReceived(const std::shared_ptr<linphone::Core>&,
		                         const std::shared_ptr<linphone::Event>&,
		                         const std::string&,
		                         const std::shared_ptr<const linphone::Content>&) override;

		std::shared_ptr<Registrar::Listener> makeListener(const std::shared_ptr<linphone::Event>&);

		std::unordered_map<const linphone::Event*, Registrar::Listener> mListeners{};
	};

	static const std::string CONTENT_TYPE;

	template <typename SuRootPtr>
	Server(SuRootPtr&& root) : ServiceServer{std::forward<SuRootPtr>(root)} {
	}

protected:
	void _init() override;
	void _run() override;
	void _stop() override;

private:
	class Init {
	public:
		Init();
	};
	static Init sStaticInit;
	std::shared_ptr<linphone::Core> mCore;
};

} // namespace RegistrationEvent

} // namespace flexisip
