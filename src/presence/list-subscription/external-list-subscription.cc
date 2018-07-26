/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2010-2015  Belledonne Communications SARL, All rights reserved.

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

#include <chrono>
#include <thread>

#include "belle-sip/message.h"
#include "soci/mysql/soci-mysql.h"

#include "bellesip-signaling-exception.hh"
#include "external-list-subscription.hh"
#include "log/logmanager.hh"

using namespace soci;
using namespace std;
using namespace chrono;

namespace flexisip {

ExternalListSubscription::ExternalListSubscription(
		unsigned int expires,
		belle_sip_server_transaction_t *ist,
		belle_sip_provider_t *aProv,
		size_t maxPresenceInfoNotifiedAtATime,
		const string &sqlRequest,
		connection_pool *connPool,
		ThreadPool *threadPool,
		function<void(ListSubscription *)> listAvailable
) : ListSubscription(expires, ist, aProv, maxPresenceInfoNotifiedAtATime, listAvailable), mConnPool(connPool) {
	// create a thread to grab a pool connection and use it to retrieve the auth information
	auto func = bind(&ExternalListSubscription::getUsersList, this, sqlRequest, ist);

	bool success = threadPool->Enqueue(func);
	if (!success) // Enqueue() can fail when the queue is full, so we have to act on that
		SLOGE << "[SOCI] Auth queue is full, cannot fullfil user request for list subscription";
}

#define DURATION_MS(start, stop) (unsigned long) duration_cast<milliseconds>((stop) - (start)).count()

void ExternalListSubscription::reconnectSession(session &session) {
	try {
		SLOGE << "[SOCI] Trying close/reconnect session";
		session.close();
		session.reconnect();
		SLOGD << "[SOCI] Session " << session.get_backend_name() << " successfully reconnected";
	} catch (mysql_soci_error const & e) {
		SLOGE << "[SOCI] reconnectSession MySQL error: " << e.err_num_ << " " << e.what() << endl;
	} catch (exception const &e) {
		SLOGE << "[SOCI] reconnectSession error: " << e.what() << endl;
	}
}

void ExternalListSubscription::getUsersList(const string &sqlRequest, belle_sip_server_transaction_t *ist) {
	steady_clock::time_point start;
	steady_clock::time_point stop;
	session *sql = nullptr;

	try {
		start = steady_clock::now();
		// will grab a connection from the pool. This is thread safe
		sql = new session(*mConnPool); //this may raise a soci_error exception, so keep it in the try block.

		stop = steady_clock::now();

		SLOGD << "[SOCI] Pool acquired in " << DURATION_MS(start, stop) << "ms";
		start = stop;

		belle_sip_request_t *request = belle_sip_transaction_get_request(BELLE_SIP_TRANSACTION(ist));
		char *uri_as_string = belle_sip_uri_to_string(belle_sip_request_get_uri(request));
		char *origin_uri_as_string = belle_sip_uri_to_string(belle_sip_request_extract_origin(request));

		if (uri_as_string && origin_uri_as_string)
			SLOGI << "from: " << origin_uri_as_string << ", to: " << uri_as_string << endl;

		rowset<row> ret = (sql->prepare << sqlRequest);
		string uriStr;
		for (rowset<row>::const_iterator it = ret.begin(); it != ret.end(); ++it) {
			const row &row = *it;
			uriStr = "sip:" + row.get<string>(1) + "@" + row.get<string>(2);
			belle_sip_uri_t *uri = belle_sip_fast_uri_parse(uriStr.c_str());
			if (!uri || !belle_sip_uri_get_host(uri) || !belle_sip_uri_get_user(uri)) {
				ostringstream os;
				os << "Cannot parse list entry [" << uriStr << "]";
				throw BELLESIP_SIGNALING_EXCEPTION_1(400, belle_sip_header_create("Warning", os.str().c_str())) << os.str();
			}
			if (uriStr.find(";user=phone") != string::npos) {
				belle_sip_uri_set_user_param(uri,"phone");
			}
			mListeners.push_back(make_shared<PresentityResourceListener>(*this, uri));
			belle_sip_object_unref(uri);
		}

		stop = steady_clock::now();
	} catch (mysql_soci_error const &e) {
		stop = steady_clock::now();

		SLOGE << "[SOCI] getUsersList MySQL error after " << DURATION_MS(start, stop) << "ms : " << e.err_num_ << " " << e.what();
		if (sql)
			reconnectSession(*sql);
	} catch (exception const &e) {
		stop = steady_clock::now();

		SLOGE << "[SOCI] getUsersList error after " << DURATION_MS(start, stop) << "ms : " << e.what();
		if (sql)
			reconnectSession(*sql);
	}
	if (sql)
		delete sql;

	finishCreation(ist);
}

} // namespace flexisip
