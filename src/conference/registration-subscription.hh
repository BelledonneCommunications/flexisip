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

#include "flexisip/registrar/registar-listeners.hh"
#include "flexisip/utils/sip-uri.hh"
#include "linphone++/linphone.hh"
#include "registrar/registrar-db.hh"
#include "registration-events/client.hh"

namespace flexisip {

struct virtual_enable_shared_from_this_base : std::enable_shared_from_this<virtual_enable_shared_from_this_base> {
	virtual ~virtual_enable_shared_from_this_base() = default;
};

template <typename T>
struct virtual_enable_shared_from_this : virtual virtual_enable_shared_from_this_base {
	std::shared_ptr<T> shared_from_this() {
		return std::dynamic_pointer_cast<T>(virtual_enable_shared_from_this_base::shared_from_this());
	}
};

class ConferenceServer;

/*Base for a class that manages registration information subscription for the server group chatroom*/
class RegistrationSubscription : public virtual_enable_shared_from_this<RegistrationSubscription> {
public:
	RegistrationSubscription(const ConferenceServer& server,
	                         const std::shared_ptr<linphone::ChatRoom>& cr,
	                         const std::shared_ptr<const linphone::Address>& participant);
	virtual void start() = 0;
	virtual void stop() = 0;
	~RegistrationSubscription() override;
	std::shared_ptr<linphone::ChatRoom> getChatRoom() const;

protected:
	bool isContactCompatible(const std::string& specs);
	/*call this to notify the current list of participant devices for the requested participant*/
	void notify(const std::list<std::shared_ptr<linphone::ParticipantDeviceIdentity>>& participantDevices);
	/*call this to notify that a device has just registered*/
	void notifyRegistration(const std::shared_ptr<const linphone::Address>& participantDevices);
	const ConferenceServer& mServer;
	const std::shared_ptr<linphone::ChatRoom> mChatRoom;
	const std::shared_ptr<linphone::Address> mParticipant;

private:
	int getMaskFromSpecs(const std::string& specs);

	std::string mLogPrefix{};
};

class RegistrationSubscriptionFetchListener
    : public virtual_enable_shared_from_this<RegistrationSubscriptionFetchListener>,
      public ContactUpdateListener {
public:
	~RegistrationSubscriptionFetchListener() override = default;
};

class RegistrationSubscriptionListener : public virtual_enable_shared_from_this<RegistrationSubscriptionListener>,
                                         public ContactRegisteredListener {
public:
	~RegistrationSubscriptionListener() override = default;
};

/**
 * Implementation of a registration subscription based on flexisip's RegistrarDb.
 */
class OwnRegistrationSubscription : public RegistrationSubscription,
                                    protected RegistrationSubscriptionFetchListener,
                                    protected RegistrationSubscriptionListener {
public:
	OwnRegistrationSubscription(const ConferenceServer& server,
	                            const std::shared_ptr<linphone::ChatRoom>& cr,
	                            const std::shared_ptr<const linphone::Address>& participant,
	                            RegistrarDb& registrarDb);
	void start() override;
	void stop() override;

private:
	std::shared_ptr<linphone::Address> getPubGruu(const std::shared_ptr<Record>& r,
	                                              const std::shared_ptr<ExtendedContact>& ec);
	void processRecord(const std::shared_ptr<Record>& r);
	/*ContactUpdateListener virtual functions to override*/
	void onRecordFound(const std::shared_ptr<Record>& r) override;
	void onError(const SipStatus&) override {};
	void onInvalid(const SipStatus&) override {};
	void onContactUpdated([[maybe_unused]] const std::shared_ptr<ExtendedContact>& ec) override {};
	/*ContactRegisteredListener overrides*/
	void onContactRegistered(const std::shared_ptr<Record>& r, const std::string& uid) override;

	SipUri mParticipantAor;
	bool mActive = false;
	std::string mLogPrefix;

	RegistrarDb& mRegistrarDb; // keep only a ref as registrarDb is owned by ConferenceServer
};

/**
 * Implementation that uses the 'reg' event package to get registration information from external domains with
 * SUBSCRIBE/NOTIFY
 */
class ExternalRegistrationSubscription : public RegistrationSubscription,
                                         protected RegistrationEvent::ClientListener,
                                         protected RegistrationEvent::Client {
public:
	ExternalRegistrationSubscription(const ConferenceServer& server,
	                                 const std::shared_ptr<linphone::ChatRoom>& cr,
	                                 const std::shared_ptr<const linphone::Address>& participant);
	void start() override;
	void stop() override;

private:
	void onNotifyReceived(
	    const std::list<std::shared_ptr<linphone::ParticipantDeviceIdentity>>& participantDevices) override;
	void onRefreshed(const std::shared_ptr<linphone::ParticipantDeviceIdentity>& participantDevice) override;
};

} // namespace flexisip