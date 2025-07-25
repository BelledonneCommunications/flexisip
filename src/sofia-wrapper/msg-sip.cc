/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2025 Belledonne Communications SARL, All rights reserved.

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

#include <vector>

#include "flexisip/logmanager.hh"
#include "utils/string-utils.hh"

#include "flexisip/sofia-wrapper/msg-sip.hh"

using namespace std;
using namespace string_literals;

namespace sofiasip {

/*Invoking the copy constructor of MsgSip implies the deep copy of the underlying msg_t */
MsgSip::MsgSip(const MsgSip& msgSip) : mMsg(msg_dup(msgSip.mMsg)) {
	serialize();
	mLogPrefix = flexisip::LogManager::makeLogPrefixForInstance(this, "MsgSip");
	LOGD << "Copied from MsgSip " << &msgSip;
}

MsgSip::MsgSip(int flags, std::string_view msg) : mMsg(msg_make(sip_default_mclass(), flags, msg.data(), msg.size())) {
	if (!mMsg || msg_has_error(mMsg)) {
		auto error = std::runtime_error("Error during message parsing from string_view:\n'"s + msg.data() + "'");
		msg_destroy(mMsg.take());
		throw error;
	}
}

std::string MsgSip::toString(msg_t& msg) {
	struct rawMsg_deleter {
		void operator()(char* raw) {
			su_free(nullptr, raw);
		}
	};

	size_t msg_size{};
	unique_ptr<char, rawMsg_deleter> raw{msg_as_string(nullptr, &msg, nullptr, 0, &msg_size)};
	return string{raw.get(), msg_size};
}

msg_header_t* MsgSip::findHeader(const std::string& name, bool searchUnknowns) {
	const sip_t* sip = getSip();
	auto begin = reinterpret_cast<msg_header_t* const*>(&sip->sip_via);
	auto end = reinterpret_cast<msg_header_t* const*>(&sip->sip_unknown);
	for (auto it = begin; it < end; it++) {
		msg_header_t* header = *it;
		if (header && strcasecmp(header->sh_common->h_class->hc_name, name.c_str()) == 0) {
			return header;
		}
	}

	if (searchUnknowns && sip->sip_unknown) {
		/* Search through unknown/custom headers, too */
		msg_unknown_t* unknown = sip->sip_unknown;
		do {
			if (strcasecmp(unknown->un_name, name.c_str()) == 0) {
				return reinterpret_cast<msg_header_t*>(unknown);
			}
		} while ((unknown = unknown->un_next));
	}
	return nullptr;
}

std::string MsgSip::msgAsString() const {
	// Here we hack out the constness.
	// msg_as_string is non const as it will modify the internal buffers of msg_t during serialization.
	return toString(const_cast<msg_t&>(*mMsg));
}

std::string MsgSip::contextAsString() const {
	ostringstream os;
	auto* sip = getSip();
	vector<char> buffer(4096);

	sip_from_e(buffer.data(), buffer.size(), (msg_header_t*)sip->sip_from, 0);
	os << "From: " << buffer.data() << endl;

	sip_to_e(buffer.data(), buffer.size(), (msg_header_t*)sip->sip_to, 0);
	os << "To: " << buffer.data() << endl;

	sip_call_id_e(buffer.data(), buffer.size(), (msg_header_t*)sip->sip_call_id, 0);
	os << "Call-ID: " << buffer.data() << endl;

	sip_cseq_e(buffer.data(), buffer.size(), (msg_header_t*)sip->sip_cseq, 0);
	os << "CSeq: " << buffer.data();

	return os.str();
}

bool MsgSip::isGroupChatInvite() const noexcept {
	const auto* sip = getSip();
	if (sip->sip_request->rq_method != sip_method_invite) return false;
	if (sip->sip_content_type && sip->sip_content_type->c_type &&
	    strcasecmp(sip->sip_content_type->c_subtype, "resource-lists+xml") != 0) {
		return false;
	}
	if (sip->sip_content_type && sip->sip_content_type->c_params &&
	    !msg_params_find(sip->sip_content_type->c_params, "text")) {
		return false;
	}
	return true;
}

bool MsgSip::isChatService() noexcept {
	const auto* messageTypeHeader = this->findHeader("X-fs-message-type", true);
	if (!messageTypeHeader) return false;

	const auto messageTypeHeaderCString =
	    sip_header_as_string(getHome(), reinterpret_cast<const sip_header_t*>(messageTypeHeader));
	if (!messageTypeHeaderCString) return false;

	if (string{messageTypeHeaderCString} == "X-fs-message-type: chat-service") return true;

	return false;
}
bool MsgSip::isInDialog() const noexcept {
	const auto* sip = getSip();
	return sip != nullptr && sip->sip_to != nullptr && sip->sip_to->a_tag != nullptr;
}

shared_ptr<flexisip::SipBooleanExpression> MsgSip::sShowBodyFor{nullptr};

void MsgSip::setShowBodyFor(const string& filterString) {
	if (filterString.empty()) {
		throw invalid_argument("show_body-for-filter can't be empty. Use true to see all body, false to see none.");
	}
	sShowBodyFor = flexisip::SipBooleanExpressionBuilder::get().parse(filterString);
}

MsgSipPriority MsgSip::getPriority() const {
	using namespace flexisip::string_utils;

	const auto sip = getSip();
	const auto priorityString = sip->sip_priority && sip->sip_priority->g_string ? sip->sip_priority->g_string : ""s;

	if (iequals(priorityString, "") || iequals(priorityString, "normal")) {
		return MsgSipPriority::Normal;
	} else if (iequals(priorityString, "non-urgent")) {
		return MsgSipPriority::NonUrgent;
	} else if (iequals(priorityString, "urgent")) {
		return MsgSipPriority::Urgent;
	} else if (iequals(priorityString, "emergency")) {
		return MsgSipPriority::Emergency;
	}

	return MsgSipPriority::Normal;
}

std::string MsgSip::getCallID() const {
	const auto sipCallId = getSip()->sip_call_id;
	return sipCallId != nullptr ? sipCallId->i_id : ""s;
}

MsgSipPriority MsgSip::getPreviousPriority(MsgSipPriority current) {
	switch (current) {
		case MsgSipPriority::Emergency:
			return MsgSipPriority::Urgent;
		case MsgSipPriority::Urgent:
			return MsgSipPriority::Normal;
		case MsgSipPriority::Normal:
			return MsgSipPriority::NonUrgent;
		case MsgSipPriority::NonUrgent:
			throw logic_error("MsgSipPriority::NonUrgent is the lowest priority");
		default:
			throw invalid_argument("MsgSip::getPreviousPriority - sofiasip::MsgSipPriority value is not valid ["s +
			                       to_string(static_cast<int>(current)) + "]");
	}
}

std::ostream& operator<<(std::ostream& strm, const sofiasip::MsgSip& obj) noexcept {
	auto messageString = obj.msgAsString();

	if (!MsgSip::getShowBodyForFilter()->eval(*obj.getSip())) {
		// If message method is not in the "show body" whitelist, remove body.
		const auto endOfHeaders = messageString.find("\r\n\r\n");
		const auto removedBodySize = endOfHeaders != std::string::npos ? messageString.size() - (endOfHeaders + 4) : 0;
		if (removedBodySize != 0) {
			messageString.resize(endOfHeaders);
			strm << messageString << "\r\n\r\n[" << removedBodySize << " bytes of body hidden]\r\n\r\n";
			return strm;
		}
	}

	strm << messageString;

	return strm;
}

} // namespace sofiasip