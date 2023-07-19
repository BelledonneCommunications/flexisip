/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include "pns-mock.hh"

#include <chrono>
#include <regex>
#include <thread>

#include <flexisip/logmanager.hh>

#include "tester.hh"

using namespace std;
using namespace flexisip::tester;
using namespace nghttp2::asio_http2;
using namespace nghttp2::asio_http2::server;
using namespace boost::asio::ssl;

namespace flexisip {
namespace pushnotification {

PnsMock::PnsMock() : mCtx(ssl::context::tls) {
	mCtx.use_private_key_file(bcTesterRes("cert/self.signed.key.test.pem"), context::pem);
	mCtx.use_certificate_chain_file(bcTesterRes("cert/self.signed.cert.test.pem"));
}

bool PnsMock::exposeMock(
    int code, const string& body, const string& reqBodyPattern, std::promise<bool>&& barrier, bool timeout) {
	bool assert = false;
	try {
		onPushRequest(handleRequest(code, body, reqBodyPattern, assert, timeout));

		bool success = serveAsync("3000");
		barrier.set_value(success);
		if (success) {
			mServer.join();
		}
		return assert;
	} catch (boost::system::system_error& e) {
		SLOGD << e.what();
		return assert;
	}
}

request_cb
PnsMock::handleRequest(int code, const string& body, const string& reqBodyPattern, bool& assert, bool timeout) {
	return [code, body, reqBodyPattern, &assert, timeout](const request& req, const response& res) {
		req.on_data([reqBodyPattern, &assert](const uint8_t* data, std::size_t len) {
			if (len > 0) {
				string body{reinterpret_cast<const char*>(data), len};
				regex bodyRegex(reqBodyPattern, regex::ECMAScript);
				assert = regex_search(body, bodyRegex);
				if (!assert) SLOGE << "Body is different, actual body : \n" << body;
			}
		});
		res.write_head(code);
		if (timeout) {
			this_thread::sleep_for(3s);
		}
		res.end(body);
	};
}

void PnsMock::onPushRequest(request_cb cb) {
	mServer.handle("/fcm/send", cb);
	mServer.handle("/3/device/", cb);
	mServer.handle("/generic", cb);
}

bool PnsMock::serveAsync(const std::string& port) {
	boost::system::error_code ec{};

	configure_tls_context_easy(ec, mCtx);

	if (mServer.listen_and_serve(ec, mCtx, "localhost", port, true)) {
		SLOGE << "error: " << ec.message() << std::endl;
		return false;
	}
	return true;
}

void PnsMock::forceCloseServer() {
	for (const auto& io_service : mServer.io_services()) {
		io_service->stop();
	}

	mServer.stop();
}

} // namespace pushnotification
} // namespace flexisip
