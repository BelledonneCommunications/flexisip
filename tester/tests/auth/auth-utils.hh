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

#include <memory>
#include <string>
#include <string_view>

#include "flexisip/logmanager.hh"
#include "sofia-wrapper/nta-agent.hh"
#include "sofia-wrapper/nta-outgoing-transaction.hh"
#include "utils/test-patterns/test.hh"

namespace flexisip::tester::authentication {

struct Response {
	int status;
	std::string msg;
};

const Response response_200_ok = {200, ""};
const Response response_401_unauthorized = {401, "WWW-Authenticate"};
const Response response_403_forbidden = {403, "Domain forbidden"};
const Response response_407_proxy_auth_required = {407, "Proxy-Authenticate"};

static void checkResponse(const std::shared_ptr<sofiasip::NtaOutgoingTransaction>& transaction,
                          const Response& expected) {
	BC_ASSERT_CPP_EQUAL(transaction->getStatus(), expected.status);

	const auto response = transaction->getResponse();
	BC_HARD_ASSERT(response != nullptr);

	const auto rawResponse = response->msgAsString();
	SLOGD << "Server response:\n" << rawResponse;
	if (expected.msg.empty()) return;

	BC_ASSERT(rawResponse.find(expected.msg) != std::string::npos);
}

static std::string
registerRequest(const std::string& sipUri, const std::string& CSeq, const std::string& addField = "") {
	// clang-format off
	return std::string(
		std::string("REGISTER ") + sipUri+ " SIP/2.0\r\n"
		"Max-Forwards: 5\r\n"
		"To: <" + sipUri + ">\r\n"
		"From: <" + sipUri + ">;tag=465687829\r\n"
		"Call-ID: 1053183492\r\n"
		"CSeq: " + CSeq + " REGISTER\r\n"
		"Contact: <" + sipUri + ";>;+sip.instance=fcm1Reg\r\n"
		"Expires: 3600\r\n"
		+ addField +
		"Content-Length: 0\r\n");
	// clang-format on
}

static std::shared_ptr<sofiasip::NtaOutgoingTransaction> sendRequest(sofiasip::NtaAgent& UAC,
                                                                     const std::shared_ptr<sofiasip::SuRoot>& root,
                                                                     std::string_view request,
                                                                     std::string_view dstPort) {
	using namespace std::chrono_literals;
	auto transaction = UAC.createOutgoingTransaction(request, std::string("sip:localhost:") + dstPort.data());

	auto beforePlus2 = std::chrono::system_clock::now() + 2s;
	while (!transaction->isCompleted() && beforePlus2 >= std::chrono::system_clock::now()) {
		root->step(20ms);
	}
	BC_ASSERT(transaction->isCompleted());
	return transaction;
}
} // namespace flexisip::tester::authentication