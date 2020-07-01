/*
 Flexisip, a flexible SIP proxy server with media capabilities.
 Copyright (C) 2018 Belledonne Communications SARL.

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

#include <linphone++/linphone.hh>
#include <flexisip/registrardb.hh>

using namespace std;
using namespace linphone;

namespace flexisip {

struct virtual_enable_shared_from_this_base:
	enable_shared_from_this<virtual_enable_shared_from_this_base> {
	virtual ~virtual_enable_shared_from_this_base() {}
};

template<typename T>
struct virtual_enable_shared_from_this:
virtual virtual_enable_shared_from_this_base {
	shared_ptr<T> shared_from_this() {
		return dynamic_pointer_cast<T>(
			virtual_enable_shared_from_this_base::shared_from_this());
	}
};

class ConferenceServer;

/*Base for a class that manages registration information subscription for the server group chatroom*/
class RegistrationSubscription : public virtual_enable_shared_from_this<RegistrationSubscription>{
	public:
		RegistrationSubscription(
			const ConferenceServer & server,
			const shared_ptr<ChatRoom> &cr,
			const shared_ptr<const Address> &participant
		);
		virtual void start() = 0;
		virtual void stop() = 0;
		virtual ~RegistrationSubscription();
		shared_ptr<ChatRoom> getChatRoom()const;
	protected:
		/*call this to notify the current list of participant devices for the requested participant*/
		void notify(const list< shared_ptr<ParticipantDeviceIdentity> > & participantDevices);
		/*call this to notify that a device has just registered*/
		void notifyRegistration(const shared_ptr<Address>  & participantDevices);
		const ConferenceServer & mServer;
		const shared_ptr<ChatRoom> mChatRoom;
		const shared_ptr<Address> mParticipant;
};

class RegistrationSubscriptionFetchListener : public virtual_enable_shared_from_this<RegistrationSubscriptionFetchListener>, public ContactUpdateListener{
	public:
		virtual ~RegistrationSubscriptionFetchListener() = default;
};

class RegistrationSubscriptionListener : public virtual_enable_shared_from_this<RegistrationSubscriptionListener>, public ContactRegisteredListener{
	public:
		virtual ~RegistrationSubscriptionListener() = default;
};

/**
 * Implementation of a registration subscription based on flexisip's RegistrarDb.
 */
class OwnRegistrationSubscription
	: public RegistrationSubscription, protected RegistrationSubscriptionFetchListener, protected RegistrationSubscriptionListener
{
	public:
		OwnRegistrationSubscription(
			const ConferenceServer & server,
			const shared_ptr<ChatRoom> &cr,
			const shared_ptr<const Address> &participant
		);
		virtual void start() override;
		virtual void stop() override;

	private:
		shared_ptr<Address> getPubGruu(const shared_ptr<Record> &r, const shared_ptr<ExtendedContact> &ec);
		void processRecord(const shared_ptr<Record> &r);
		/*ContactUpdateListener virtual functions to override*/
		virtual void onRecordFound (const shared_ptr<Record> &r) override;
		virtual void onError () override {};
		virtual void onInvalid () override {};
		virtual void onContactUpdated (const shared_ptr<ExtendedContact> &ec) override {}
		/*ContactRegisteredListener overrides*/
		virtual void onContactRegistered(const shared_ptr<Record> &r, const string &uid) override;

		SofiaAutoHome mHome;
		const url_t *mParticipantAor;
		bool mActive;
};

} // namespace flexisip
