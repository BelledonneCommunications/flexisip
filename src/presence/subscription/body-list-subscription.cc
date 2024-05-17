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

#include <flexisip/logmanager.hh>

#include "bellesip-signaling-exception.hh"
#include "body-list-subscription.hh"
#include "xml/resource-lists.hh"

using namespace std;

namespace flexisip {

BodyListSubscription::BodyListSubscription(unsigned int expires,
                                           belle_sip_server_transaction_t* ist,
                                           belle_sip_provider_t* aProv,
                                           size_t maxPresenceInfoNotifiedAtATime,
                                           const std::weak_ptr<StatPair>& countBodyListSubscription,
                                           function<void(shared_ptr<ListSubscription>)> listAvailable)
    : ListSubscription(expires, ist, aProv, maxPresenceInfoNotifiedAtATime, countBodyListSubscription, listAvailable) {
	belle_sip_request_t* request = belle_sip_transaction_get_request(BELLE_SIP_TRANSACTION(ist));
	if (!belle_sip_message_get_body(BELLE_SIP_MESSAGE(request))) {
		throw BELLESIP_SIGNALING_EXCEPTION_1(400, belle_sip_header_create("Warning", "Empty body")) << "Empty body";
	}

	unique_ptr<Xsd::ResourceLists::ResourceLists> resource_list_body;
	try {
		istringstream data(belle_sip_message_get_body(BELLE_SIP_MESSAGE(request)));
		resource_list_body = Xsd::ResourceLists::parseResourceLists(data, Xsd::XmlSchema::Flags::dont_validate);
	} catch (const Xsd::XmlSchema::Exception& e) {
		ostringstream os;
		os << "Cannot parse body caused by [" << e << "]";
		// todo check error code
		throw BELLESIP_SIGNALING_EXCEPTION_1(400, belle_sip_header_create("Warning", os.str().c_str())) << os.str();
	}

	for (const auto& list : resource_list_body->getList()) {
		for (const auto& entry : list.getEntry()) {
			belle_sip_uri_t* uri = belle_sip_fast_uri_parse(entry.getUri().c_str());
			if (!uri || !belle_sip_uri_get_host(uri) || !belle_sip_uri_get_user(uri)) {
				SLOGE << "Cannot parse list entry [" << entry.getUri() << "]";
				continue;
			}
			if (entry.getUri().find(";user=phone") != string::npos) {
				belle_sip_uri_set_user_param(uri, "phone");
			}
			mListeners.push_back(make_shared<PresentityResourceListener>(*this, uri));
			belle_sip_object_unref(uri);
		}
	}
	finishCreation(ist);
}

} // namespace flexisip
