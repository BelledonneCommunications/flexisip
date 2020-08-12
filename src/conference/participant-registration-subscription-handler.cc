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

#include "participant-registration-subscription-handler.hh"
#include "registration-events/client.hh"
#include "utils/string-utils.hh"

using namespace flexisip;
using namespace std;
using namespace linphone;

ParticipantRegistrationSubscriptionHandler::ParticipantRegistrationSubscriptionHandler(const ConferenceServer & server) : mServer(server){
}

string ParticipantRegistrationSubscriptionHandler::getKey (const shared_ptr<const Address> &address) {
	ostringstream ostr;
	ostr << address->getUsername() << "@" << address->getDomain();
	return ostr.str();
}

void ParticipantRegistrationSubscriptionHandler::subscribe (
	const shared_ptr<ChatRoom> &chatRoom,
	const shared_ptr<const Address> &address
) {
	bool toSubscribe = true;
	string key = getKey(address);
	auto range = mSubscriptions.equal_range(key);

	for (auto it = range.first; it != range.second; it++) {
		if (it->second->getChatRoom() == chatRoom) {
			toSubscribe = false;
			break;
		}
	}

	if (toSubscribe) {
		auto config = GenericManager::get()->getRoot()->get<GenericStruct>("conference-server");
		vector<string> domains = StringUtils::split(config->get<ConfigString>("local-domains")->read(), " ");

		bool localOnly = domains.empty();

		domains.push_back(chatRoom->getConferenceAddress()->getDomain());

		if (localOnly || std::find(domains.begin(), domains.end(), address->getDomain()) != domains.end()) {
			LOGD("Subscribed address is local [%s]", address->asString().c_str());
			shared_ptr<OwnRegistrationSubscription> subscription(new OwnRegistrationSubscription(mServer, chatRoom, address));
			mSubscriptions.insert(make_pair(key, subscription));
			subscription->start();
		} else {
			LOGD("Subscribed address is external [%s], subscribe to it", address->asString().c_str());
			auto client = make_shared<RegistrationEvent::Client>(
				mServer,
				chatRoom,
				address
			);
			client->subscribe();
		}
	}
}

void ParticipantRegistrationSubscriptionHandler::unsubscribe (
	const shared_ptr<ChatRoom> &chatRoom,
	const shared_ptr<const Address> &address
) {
	string key = getKey(address);
	auto range = mSubscriptions.equal_range(key);
	for (auto it = range.first; it != range.second;) {
		if (it->second->getChatRoom() == chatRoom) {
			it->second->stop();
			it = mSubscriptions.erase(it);
		} else {
			it++;
		}
	}
}
