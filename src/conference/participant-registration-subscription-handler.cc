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


using namespace flexisip;
using namespace std;


string ParticipantRegistrationSubscriptionHandler::getKey (const shared_ptr<const linphone::Address> &address) {
	return address->getUsername() + "@" + address->getDomain();
}

void ParticipantRegistrationSubscriptionHandler::subscribe (
	const shared_ptr<linphone::ChatRoom> &chatRoom,
	const shared_ptr<const linphone::Address> &address
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
		SLOGI << "Subscribe to RegistrarDB for key '" << key << "' and ChatRoom '"
			<< chatRoom->getLocalAddress()->asString() << "'";
		auto subscription = make_shared<ParticipantRegistrationSubscription>(address, chatRoom);
		mSubscriptions.insert(make_pair(key, subscription));
		RegistrarDb::get()->subscribe(key, subscription);
	}
}

void ParticipantRegistrationSubscriptionHandler::unsubscribe (
	const shared_ptr<linphone::ChatRoom> &chatRoom,
	const shared_ptr<const linphone::Address> &address
) {
	string key = getKey(address);
	auto range = mSubscriptions.equal_range(key);
	for (auto it = range.first; it != range.second;) {
		if (it->second->getChatRoom() == chatRoom) {
			SLOGI << "Unsubscribe from RegistrarDB for key '" << key << "' and ChatRoom '"
				<< chatRoom->getLocalAddress()->asString() << "'";
			RegistrarDb::get()->unsubscribe(key, it->second);
			it = mSubscriptions.erase(it);
		} else {
			it++;
		}
	}
}
