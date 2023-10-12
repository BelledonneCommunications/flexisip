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

#include <chrono>
#include <thread>

#include "belle-sip/belle-sip.h"

#include "bellesip-signaling-exception.hh"
#include "external-list-subscription.hh"
#include "flexisip/logmanager.hh"
#include "soci-helper.hh"

using namespace std;
using namespace chrono;

namespace flexisip {

ExternalListSubscription::ExternalListSubscription(unsigned int expires,
                                                   belle_sip_server_transaction_t* ist,
                                                   belle_sip_provider_t* aProv,
                                                   size_t maxPresenceInfoNotifiedAtATime,
                                                   function<void(shared_ptr<ListSubscription>)> listAvailable,
                                                   const string& sqlRequest,
                                                   soci::connection_pool* connPool,
                                                   ThreadPool* threadPool)
    : ListSubscription(expires, ist, aProv, maxPresenceInfoNotifiedAtATime, listAvailable), mConnPool(connPool) {
	// create a thread to grab a pool connection and use it to retrieve the auth information
	auto func = bind(&ExternalListSubscription::getUsersList, this, sqlRequest, ist);

	bool success = threadPool->run(func);
	if (!success) // Enqueue() can fail when the queue is full, so we have to act on that
		SLOGE << "[SOCI] Auth queue is full, cannot fullfil user request for list subscription";
}

void ExternalListSubscription::getUsersList(const string& sqlRequest, belle_sip_server_transaction_t* ist) {
	try {
		SociHelper sociHelper(*mConnPool);

		belle_sip_request_t* request = belle_sip_transaction_get_request(BELLE_SIP_TRANSACTION(ist));
		belle_sip_header_to_t* toHeader =
		    belle_sip_message_get_header_by_type(BELLE_SIP_MESSAGE(request), belle_sip_header_to_t);
		belle_sip_header_from_t* fromHeader =
		    belle_sip_message_get_header_by_type(BELLE_SIP_MESSAGE(request), belle_sip_header_from_t);
		char* c_toUri = belle_sip_uri_to_string(belle_sip_header_address_get_uri(BELLE_SIP_HEADER_ADDRESS(toHeader)));
		char* c_fromUri =
		    belle_sip_uri_to_string(belle_sip_header_address_get_uri(BELLE_SIP_HEADER_ADDRESS(fromHeader)));

		string fromUri(c_fromUri);
		string toUri(c_toUri);
		belle_sip_free(c_fromUri);
		belle_sip_free(c_toUri);

		sociHelper.execute([&](soci::session& sql) {
			soci::rowset<soci::row> ret =
			    (sql.prepare << sqlRequest, soci::use(fromUri, "from"), soci::use(toUri, "to"));
			string addrStr;
			for (const auto& row : ret) {
				addrStr = row.get<string>(0);
				unique_ptr<belle_sip_header_address_t, void (*)(void*)> addr(
				    belle_sip_header_address_parse(addrStr.c_str()), belle_sip_object_unref);
				if (addr == nullptr) {
					ostringstream os;
					os << "Cannot parse list entry [" << addrStr << "]";
					continue;
				}
				const belle_sip_uri_t* uri = belle_sip_header_address_get_uri(addr.get());
				if (!uri || !belle_sip_uri_get_host(uri) || !belle_sip_uri_get_user(uri)) {
					ostringstream os;
					os << "Cannot parse list entry [" << addrStr << "]";
					continue;
				}
				const char* name = belle_sip_header_address_get_displayname(addr.get());
				mListeners.push_back(make_shared<PresentityResourceListener>(*this, uri, name ? name : ""));
			}
		});
	} catch (SociHelper::DatabaseException& e) {
	}
	finishCreation(ist);
}

} // namespace flexisip
