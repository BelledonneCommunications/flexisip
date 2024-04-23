/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

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

#include <functional>
#include <memory>
#include <queue>
#include <string>
#include <string_view>

#include <sofia-sip/nth.h>

#include "flexisip/sofia-wrapper/su-root.hh"

namespace flexisip {

/**
 * An HTTTP/1 client.
 * Can be used to establish a connection to a remote server and send GET requests one by one.
 */
class Http1Client {
public:
	explicit Http1Client(const std::shared_ptr<sofiasip::SuRoot>& root);

	// Send a GET request to the remote server at the given url address and call the given callback with the response.
	// If a request is already in progress, this request is added to the request queue.
	// The callback is always called, with empty response on error.
	void requestGET(std::string_view url, std::function<void(std::string_view)>&& usrCallback);

private:
	void sendNextRequest();
	void onRequestResponse(std::string_view data);
	struct nthEngineDeleter {
		void operator()(nth_engine_t* e) {
			nth_engine_destroy(e);
		}
	};
	struct nthClientDeleter {
		void operator()(nth_client_t* clt) {
			nth_client_destroy(clt);
		}
	};
	struct PendingRequest {
		PendingRequest(std::string_view _url, std::function<void(std::string_view)>&& _cb)
		    : url{_url}, usrCallback{std::move(_cb)} {
		}
		std::string url;
		std::function<void(std::string_view)> usrCallback;
	};

	std::shared_ptr<sofiasip::SuRoot> mRoot;
	std::unique_ptr<nth_engine_t, nthEngineDeleter> mNthEngine;
	std::queue<PendingRequest> mPendingRequests;
	std::unique_ptr<nth_client_t, nthClientDeleter> mNthClient;
};

} // namespace flexisip