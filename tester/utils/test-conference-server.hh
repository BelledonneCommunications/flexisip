/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <memory>

#include "agent.hh"
#include "conference/conference-server.hh"

namespace flexisip {
namespace tester {

class TestConferenceServer {
public:
	TestConferenceServer(const Agent&);
	~TestConferenceServer();

	void clearLocalDomainList();

private:
	/** Overrides the behaviour of the ConferenceServer to make it use a port chosen at random. This works because it
	 *  will share the same config as the proxy, so it can hot-patch it with the port bound.
	 */
	class PatchedConferenceServer : public ConferenceServer {
	public:
		template <typename StrT, typename SuRootPtr>
		PatchedConferenceServer(StrT&& path, SuRootPtr&& root)
		    : ConferenceServer{std::forward<StrT>(path), std::forward<SuRootPtr>(root)} {
		}

		// We need to change the port before the conference server binds its addresses to the Registrar. But not too
		// soon, as if the core's global state changes, it will rebind to a new port, invalidating the previously
		// patched config. As of the current implementation of ConferenceServer::_init(), hooking into `bindAddresses`
		// is the perfect place to do that.
		void bindAddresses() override;
	};

	const std::shared_ptr<PatchedConferenceServer> mConfServer;
};

} // namespace tester
} // namespace flexisip
