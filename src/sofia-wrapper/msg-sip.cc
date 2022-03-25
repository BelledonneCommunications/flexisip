/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL.

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

#include <vector>

#include "flexisip/logmanager.hh"

#include "msg-sip.hh"

using namespace std;

namespace sofiasip {

/*Invoking the copy constructor of MsgSip implies the deep copy of the underlying msg_t */
MsgSip::MsgSip(const MsgSip& msgSip) {
	msgSip.serialize();
	msg_t* freshCopy = msg_dup(msgSip.mMsg);
	assignMsg(freshCopy);
	msg_destroy(freshCopy);
	LOGD("New MsgSip %p copied from MsgSip %p", this, &msgSip);
}

MsgSip::MsgSip(int flags, const std::string& msg) {
	mMsg = msg_make(sip_default_mclass(), flags, msg.c_str(), msg.size());
	if (!mMsg || msg_has_error(mMsg)) {
		throw runtime_error("Error during message parsing from string : \n" + msg);
	}
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

const char* MsgSip::print() const {
	// make sure the message is serialized before showing it; it can be very confusing.
	size_t msg_size;
	msg_serialize(mMsg, (msg_pub_t*)getSip());
	return msg_as_string(getHome(), mMsg, NULL, 0, &msg_size);
}

std::string MsgSip::printString() const {
	// make sure the message is serialized before showing it; it can be very confusing.
	size_t msg_size;
	msg_serialize(mMsg, (msg_pub_t*)getSip());
	const auto cStr = msg_as_string(getHome(), mMsg, nullptr, 0, &msg_size);
	return string{cStr, msg_size};
}

std::string MsgSip::printContext() const {
	ostringstream os;
	sip_t* sip = getSip();
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

}; // namespace sofiasip
