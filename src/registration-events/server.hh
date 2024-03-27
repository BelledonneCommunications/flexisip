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

#include <memory>
#include <string>
#include <unordered_map>

#include <linphone++/linphone.hh>

#include "flexisip/registrar/registar-listeners.hh"
#include "registrar/registrar-db.hh"
#include "service-server/service-server.hh"

namespace flexisip {

namespace RegistrationEvent {

class Server : public ServiceServer {
public:
	class Subscriptions : public linphone::CoreListener,
	                      public ContactRegisteredListener,
	                      public ContactUpdateListener {
	public:
		Subscriptions(const std::shared_ptr<RegistrarDb>& registrarDb) : mRegistrarDb{registrarDb} {
		}

	private:
		void onSubscribeReceived(const std::shared_ptr<linphone::Core>&,
		                         const std::shared_ptr<linphone::Event>&,
		                         const std::string&,
		                         const std::shared_ptr<const linphone::Content>&) override;
		void onSubscriptionStateChanged(const std::shared_ptr<linphone::Core>& core,
		                                const std::shared_ptr<linphone::Event>& linphoneEvent,
		                                linphone::SubscriptionState state) override;

		void onRecordFound(const std::shared_ptr<Record>& r) override;
		void onError(const SipStatus&) override {
		}
		void onInvalid(const SipStatus&) override {
		}
		void onContactUpdated(const std::shared_ptr<ExtendedContact>&) override {
		}

		void onContactRegistered(const std::shared_ptr<Record>&, const std::string& uidOfFreshlyRegistered) override;

		void processRecord(const std::shared_ptr<Record>&, const std::string& uidOfFreshlyRegistered);

		std::unordered_map<std::string, std::shared_ptr<linphone::Event>> mEvents{};
		std::shared_ptr<RegistrarDb> mRegistrarDb;
	};

	static const std::string CONTENT_TYPE;

	template <typename SuRootPtr>
	Server(SuRootPtr&& root, const std::shared_ptr<ConfigManager>& cfg, const std::shared_ptr<RegistrarDb>& registrarDb)
	    : ServiceServer(std::forward<SuRootPtr>(root)), mConfigManager(cfg), mRegistrarDb(registrarDb) {
	}

protected:
	void _init() override;
	void _run() override;
	std::unique_ptr<AsyncCleanup> _stop() override;

private:
	std::shared_ptr<ConfigManager> mConfigManager;
	std::shared_ptr<RegistrarDb> mRegistrarDb;
	std::shared_ptr<linphone::Core> mCore;
};

} // namespace RegistrationEvent

} // namespace flexisip
