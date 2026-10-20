/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2026 Belledonne Communications SARL, All rights reserved.

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

#include <vector>

#include "b2bua/sip-bridge/sip-bridge.hh"
#include "linphone++/linphone.hh"
#include "utils/client-call.hh"
#include "utils/client-core.hh"
#include "utils/core-assert.hh"

namespace flexisip::tester {

using V1AccountDesc = flexisip::b2bua::bridge::config::v1::AccountDesc;

// The external SIP proxy that the B2BUA will bridge calls to. (For test purposes, it's actually the same proxy)
// MUST match config/flexisip_b2bua.conf:[b2bua-server]:outbound-proxy
constexpr auto outboundProxy = "sip:127.0.0.1:5860;transport=tcp";

class ExternalClient;

class InternalClient {
	friend class ExternalClient;
	CoreClient client;

	std::shared_ptr<linphone::Address> toInternal(std::shared_ptr<linphone::Address>&& external) const;

public:
	template <typename... _Args>
	InternalClient(_Args&&... __args) : client(std::forward<_Args>(__args)...) {}

	std::shared_ptr<linphone::Call> invite(const ExternalClient& external) const;

	std::shared_ptr<linphone::Call> call(const ExternalClient& external);

	void endCurrentCall(const ExternalClient& other);

	auto getCore() {
		return client.getCore();
	}
};

class ExternalClient {
	friend class InternalClient;
	CoreClient client;

	std::shared_ptr<linphone::Address> getAddress() const {
		return client.getAccount()->getContactAddress()->clone();
	}

public:
	ExternalClient(CoreClient&& client) : client(std::move(client)) {}
	template <typename... _Args>
	ExternalClient(_Args&&... __args) : client(std::forward<_Args>(__args)...) {}

	[[nodiscard]] auto hasReceivedCallFrom(const InternalClient& internal, const BcAssert<>& asserter) const {
		return client.hasReceivedCallFrom(internal.client, asserter);
	}

	auto getCallLog() const {
		return client.getCallLog();
	}

	auto endCurrentCall(const InternalClient& other) {
		return client.endCurrentCall(other.client);
	}

	auto getCore() {
		return client.getCore();
	}
	auto getCurrentCall() {
		return client.getCurrentCall();
	}
};

inline std::shared_ptr<linphone::Address> InternalClient::toInternal(std::shared_ptr<linphone::Address>&& external) const {
	external->setDomain(client.getAccount()->getParams()->getIdentityAddress()->getDomain());
	return std::move(external);
}

inline std::shared_ptr<linphone::Call> InternalClient::invite(const ExternalClient& external) const {
	return client.getCore()->inviteAddress(toInternal(external.getAddress()));
}

inline std::shared_ptr<linphone::Call> InternalClient::call(const ExternalClient& external) {
	return client.call(external.client, toInternal(external.getAddress()));
}

inline void InternalClient::endCurrentCall(const ExternalClient& other) {
	client.endCurrentCall(other.client);
}

struct DtmfListener : public linphone::CallListener {
	std::vector<int> received{};

	void onDtmfReceived([[maybe_unused]] const std::shared_ptr<linphone::Call>& _call, int dtmf) {
		received.push_back(dtmf);
	}
};


} // namespace flexisip::tester
