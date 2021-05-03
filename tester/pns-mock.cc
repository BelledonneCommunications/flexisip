/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2021  Belledonne Communications SARL, All rights reserved.

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

#include "pns-mock.hh"

#include <chrono>
#include <regex>
#include <thread>

#include <flexisip/logmanager.hh>

#include "flexisip-config.h"

using namespace std;
using namespace nghttp2::asio_http2;
using namespace nghttp2::asio_http2::server;
using namespace boost::asio::ssl;

namespace flexisip {
namespace pushnotification {

bool PnsMock::exposeMock(int code, const string& body, const string& reqBodyPattern, promise<bool>&& barrier,
                          bool timeout) {
	bool assert = false;
	try {
		boost::system::error_code ec{};

		context tls(context::tls);
		tls.use_private_key_file(TESTER_DATA_DIR + string("/cert/self.signed.key.test.pem"), context::pem);
		tls.use_certificate_chain_file(TESTER_DATA_DIR + string("/cert/self.signed.cert.test.pem"));
		configure_tls_context_easy(ec, tls);

		mServer.handle("/fcm/send", handleRequest(code, body, reqBodyPattern, assert, timeout));
		mServer.handle("/3/device/", handleRequest(code, body, reqBodyPattern, assert, timeout));

		if (mServer.listen_and_serve(ec, tls, "localhost", "3000", true)) {
			SLOGE << "error: " << ec.message() << std::endl;
			barrier.set_value(false);
			return assert;
		}
		barrier.set_value(true);
		mServer.join();
		return assert;
	} catch (boost::system::system_error& e) {
		SLOGD << e.what();
		return assert;
	}
}

std::function<void(const request&, const response&)>
PnsMock::handleRequest(int code, const string& body, const string& reqBodyPattern, bool& assert, bool timeout) {
	return [code, body, reqBodyPattern, &assert, timeout](const request& req, const response& res) {
		req.on_data([reqBodyPattern, &assert](const uint8_t* data, std::size_t len) {
			if (len > 0) {
				string body{reinterpret_cast<const char*>(data), len};
				regex bodyRegex(reqBodyPattern, regex::ECMAScript);
				assert = regex_search(body, bodyRegex);
			}
		});
		res.write_head(code);
		if (timeout) {
			this_thread::sleep_for(chrono::milliseconds(32000));
		}
		res.end(body);
	};
}

void PnsMock::forceCloseServer() {
	for (const auto& io_service : mServer.io_services()) {
		io_service->stop();
	}

	mServer.stop();
}

} // namespace pushnotification
} // namespace flexisip
