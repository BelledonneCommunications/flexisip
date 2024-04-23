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

#define NTH_CLIENT_MAGIC_T void

#include "http1-client.hh"

#include "flexisip/logmanager.hh"
#include "flexisip/utils/sip-uri.hh"
namespace flexisip {

Http1Client::Http1Client(const std::shared_ptr<sofiasip::SuRoot>& root) : mRoot{root} {
	mNthEngine.reset(nth_engine_create(mRoot->getCPtr(), NTHTAG_ERROR_MSG(0), TAG_END()));
}

void Http1Client::requestGET(std::string_view url, std::function<void(std::string_view)>&& usrCallback) {
	// limit to one request at a time
	const auto readyToSend = mPendingRequests.empty();
	mPendingRequests.emplace(url, std::move(usrCallback));
	if (readyToSend) sendNextRequest();
}

void Http1Client::sendNextRequest() {
	constexpr auto callback = [](nth_client_magic_t* ctx, nth_client_t* client, http_t const* rep) {
		auto thiz = static_cast<Http1Client*>(ctx);
		const auto status = nth_client_status(client);
		if (status != 200) {
			const auto phrase = rep && rep->http_status ? rep->http_status->st_phrase : "";
			const auto url = sofiasip::Url(nth_client_url(client));
			LOGE("Server replies %d %s to %s GET request.", status, phrase, url.str().c_str());
			thiz->onRequestResponse("");
			return 1;
		}

		thiz->onRequestResponse(rep->http_payload->pl_data);
		return 0;
	};

	const auto& pendingReq = mPendingRequests.front();
	mNthClient.reset(nth_client_tcreate(mNthEngine.get(), callback, this, HTTP_METHOD_GET,
	                                    URL_STRING_MAKE(pendingReq.url.data()), TAG_END()));
	if (!mNthClient) {
		LOGW("Failed to send GET request to %s", pendingReq.url.data());
		onRequestResponse("");
	}
}

void Http1Client::onRequestResponse(std::string_view data) {
	const auto& req = mPendingRequests.front();
	req.usrCallback(data);
	mPendingRequests.pop();
	if (!mPendingRequests.empty()) sendNextRequest();
}

} // namespace flexisip