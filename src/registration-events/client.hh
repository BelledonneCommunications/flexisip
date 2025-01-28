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

#include <iostream>

#include <linphone++/linphone.hh>

namespace flexisip {

namespace RegistrationEvent {

class ClientListener {
public:
	/* This is where the parsing result of the incoming NOTIFY are notified.
	 * The ParticipantDeviceIdentity object is convenient to represent the device information returned by the reg event
	 * package.
	 */
	virtual void
	onNotifyReceived(const std::list<std::shared_ptr<linphone::ParticipantDeviceIdentity>>& participantDevices) = 0;
	virtual void onRefreshed(const std::shared_ptr<linphone::ParticipantDeviceIdentity>& participantDevice) = 0;
};

class Client;

/*
 * Helper class to create client 'reg' subscriptions.
 * It must be alive as long as there are Client instanciated, otherwise the clients won't receive any notify anymore.
 * And it must be hold by a shared_ptr.
 * Its main purpose is to centralize the linphone::Event callbacks; that are attached to the Core, and dispatch them to
 * the Clients.
 */
class ClientFactory : public std::enable_shared_from_this<ClientFactory>, public linphone::CoreListener {
	friend class Client;

public:
	ClientFactory(const std::shared_ptr<linphone::Core>& core);
	std::shared_ptr<Client> create(const std::shared_ptr<const linphone::Address>& to);

private:
	static constexpr std::string_view mLogPrefix{"ClientFactory"};

	virtual void onNotifyReceived(const std::shared_ptr<linphone::Core>& lc,
	                              const std::shared_ptr<linphone::Event>& lev,
	                              const std::string& notifiedEvent,
	                              const std::shared_ptr<const linphone::Content>& body) override;
	virtual void onSubscriptionStateChanged(const std::shared_ptr<linphone::Core>& core,
	                                        const std::shared_ptr<linphone::Event>& linphoneEvent,
	                                        linphone::SubscriptionState state) override;
	int mUseCount = 0;
	void registerClient(Client& client);
	void unregisterClient(Client& client);
	std::shared_ptr<linphone::Core> getCore() const {
		return mCore;
	}
	std::shared_ptr<linphone::Core> mCore;
};

/**
 * Base class for a "reg" event client.
 * It has to be inherited to get notified of the results of the subscription (the incoming NOTIFY request content).
 */
class Client {
	friend class ClientFactory;

public:
	~Client();
	void subscribe();
	void unsubscribe();
	void setListener(ClientListener* listener);

protected:
	Client(const std::shared_ptr<ClientFactory>& factory, const std::shared_ptr<const linphone::Address>& to);

private:
	static constexpr const char* eventKey = "Regevent::Client";
	static constexpr std::string_view mLogPrefix{"Client"};

	void onNotifyReceived(const std::shared_ptr<const linphone::Content>& body);
	void onSubscriptionStateChanged(linphone::SubscriptionState state);

	std::shared_ptr<linphone::Event> mSubscribeEvent;
	ClientListener* mListener = nullptr;
	std::shared_ptr<ClientFactory> mFactory;
	std::shared_ptr<linphone::Address> mTo;
};

} // end of namespace RegistrationEvent

} // namespace flexisip