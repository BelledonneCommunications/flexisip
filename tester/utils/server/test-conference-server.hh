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

#include "agent.hh"
#include "conference/conference-server.hh"
#include "flexisip/configmanager.hh"
#include "registrar/registrar-db.hh"
#include "utils/server/proxy-server.hh"

namespace flexisip::tester {

class TestConferenceServer {
public:
	explicit TestConferenceServer(const Server& proxy);
	TestConferenceServer(const Agent&,
	                     const std::shared_ptr<ConfigManager>& cfg,
	                     const std::shared_ptr<RegistrarDb>& registrarDb);
	~TestConferenceServer();

	void clearLocalDomainList();

	auto getChatrooms() {
		return mConfServer->getCore()->getChatRooms();
	}

	void bindChatRoom(const std::string& bindingUrl,
	                  const std::string& contact,
	                  const std::shared_ptr<ContactUpdateListener>& listener) {
		mConfServer->bindChatRoom(bindingUrl, contact, listener);
	};

private:
	/** Overrides the behaviour of the ConferenceServer to make it use a port chosen at random. This works because it
	 *  will share the same config as the proxy, so it can hot-patch it with the port bound.
	 */
	class PatchedConferenceServer : public ConferenceServer {
	public:
		template <typename StrT, typename SuRootPtr>
		PatchedConferenceServer(StrT&& path,
		                        SuRootPtr&& root,
		                        const std::shared_ptr<ConfigManager>& cfg,
		                        const std::shared_ptr<RegistrarDb>& registrarDb)
		    : ConferenceServer(std::forward<StrT>(path), std::forward<SuRootPtr>(root), cfg, registrarDb),
		      mConfigManager(cfg) {
		}

		// We need to change the port before the conference server binds its addresses to the Registrar. But not too
		// soon, as if the core's global state changes, it will rebind to a new port, invalidating the previously
		// patched config. As of the current implementation of ConferenceServer::_init(), hooking into `bindAddresses`
		// is the perfect place to do that.
		void bindAddresses() override;

	private:
		std::shared_ptr<ConfigManager> mConfigManager;
	};

	std::shared_ptr<sofiasip::SuRoot> mRoot;
	std::shared_ptr<PatchedConferenceServer> mConfServer;
};

} // namespace flexisip::tester
