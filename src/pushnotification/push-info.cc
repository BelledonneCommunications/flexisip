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

#include "push-info.hh"

#include <stdexcept>

#include "flexisip/logmanager.hh"
#include "flexisip/sofia-wrapper/msg-sip.hh"

#include "request.hh"
#include "utils/string-utils.hh"
#include "utils/uri-utils.hh"

using namespace std;
using namespace flexisip;
using namespace pushnotification;

PushInfo::PushInfo(const sofiasip::MsgSip& msg) {
	const auto* sip = msg.getSip();

	setDestinations(sip->sip_request->rq_url);

	this->mCallId = sip->sip_call_id->i_id;
	if (msg.isGroupChatInvite()) {
		this->mChatRoomAddr = sip->sip_from->a_url->url_user;
	}

	if (sip->sip_from->a_display) {
		// Remove the double-quotes and the spaces surrounding the display name
		auto displayName = sip->sip_from->a_display;
		auto it1 = displayName, it2 = const_cast<const char*>(index(displayName, '\0'));
		StringUtils::stripAll(it1, it2, [](const char& c) { return std::isspace(c) != 0; });
		StringUtils::strip(it1, it2, '"');
		this->mFromName.assign(it1, it2);
	}
	sofiasip::Home home{};
	this->mFromUri = url_as_string(home.home(), sip->sip_from->a_url);

	this->mToUri = url_as_string(home.home(), sip->sip_to->a_url);
	this->mFromTag = sip->sip_from->a_tag;
	if (sip->sip_request->rq_method == sip_method_message && sip->sip_payload && sip->sip_payload->pl_len > 0) {
		auto* payload = sip->sip_payload;
		this->mText.assign(payload->pl_data, payload->pl_len);
	}

	auto firstDest = this->mDestinations.cbegin();
	if (firstDest != this->mDestinations.cend() && firstDest->second->isApns()) {
		parseAppleSpecifics(msg);
	}
}

PushInfo::PushInfo(const ExtendedContact& contact) {
	setDestinations(contact.mSipContact->m_url);
	mCallId = contact.mCallId;
	mFromUri = mToUri = contact.urlAsString();
}

void PushInfo::setDestinations(const url_t* url) {
	if (url_has_param(url, "pn-provider")) { // RFC8599
		mDestinations = RFC8599PushParams::parsePushParams(url->url_params);
	} else if (url_has_param(url, "pn-tok")) { // Flexisip and Linphone legacy parameters
		mDestinations = RFC8599PushParams::parseLegacyPushParams(url->url_params);
	} else {
		throw MissingPushParameters{};
	}
}

void PushInfo::addDestination(const std::shared_ptr<const RFC8599PushParams>& dest) noexcept {
	for (auto pnType : dest->getSupportedPNTypes()) {
		this->mDestinations[pnType] = dest;
	}
}

const std::string& PushInfo::getPNProvider() const {
	auto it = this->mDestinations.cbegin();
	if (it == this->mDestinations.cend()) throw InvalidPushParameters{"no destination set"};
	return it->second->getProvider();
}

void PushInfo::parseAppleSpecifics(const sofiasip::MsgSip& msg) {
	const auto* sip = msg.getSip();
	const auto* params = sip->sip_request->rq_url->url_params;
	auto msg_str = UriUtils::getParamValue(params, "pn-msg-str");
	if (msg_str.empty()) {
		SLOGD << "no optional pn-msg-str, using default: IM_MSG";
		msg_str = "IM_MSG";
	}

	auto call_str = UriUtils::getParamValue(params, "pn-call-str");
	if (call_str.empty()) {
		SLOGD << "no optional pn-call-str, using default: IC_MSG";
		call_str = "IC_MSG";
	}

	auto group_chat_str = UriUtils::getParamValue(params, "pn-groupchat-str");
	if (group_chat_str.empty()) {
		SLOGD << "no optional pn-groupchat-str, using default: GC_MSG";
		group_chat_str = "GC_MSG";
	}

	auto call_snd = UriUtils::getParamValue(params, "pn-call-snd");
	if (call_snd.empty()) {
		SLOGD << "no optional pn-call-snd, using empty";
		call_snd = "empty";
	}

	auto msg_snd = UriUtils::getParamValue(params, "pn-msg-snd");
	if (msg_snd.empty()) {
		SLOGD << "no optional pn-msg-snd, using empty";
		msg_snd = "empty";
	}

	auto mwi_str = UriUtils::getParamValue(params, "pn-mwi-str");
	if (mwi_str.empty()) {
		SLOGD << "no optional pn-mwi-str, using MWI_NOTIFY_STR";
		mwi_str = "MWI_NOTIFY_STR";
	}

	if (sip->sip_request->rq_method == sip_method_invite && !msg.isGroupChatInvite()) this->mAlertMsgId = call_str;
	else if (sip->sip_request->rq_method == sip_method_message) this->mAlertMsgId = msg_str;
	else if (sip->sip_request->rq_method == sip_method_notify) this->mAlertMsgId = mwi_str;
	else if (msg.isGroupChatInvite()) this->mAlertMsgId = group_chat_str;
	else this->mAlertMsgId = "IC_SIL";

	auto missingCallMsg = UriUtils::getParamValue(params, "pn-missing-call-str");
	if (!missingCallMsg.empty()) mMissingCallMsg = missingCallMsg;

	auto acceptedElsewhereMsg = UriUtils::getParamValue(params, "pn-call-accepted-elsewhere-str");
	if (!acceptedElsewhereMsg.empty()) mAcceptedElsewhereMsg = acceptedElsewhereMsg;

	auto declinedElsewhereMsg = UriUtils::getParamValue(params, "pn-call-declined-elsewhere-str");
	if (!declinedElsewhereMsg.empty()) mDeclinedElsewhereMsg = declinedElsewhereMsg;

	this->mAlertSound =
	    (sip->sip_request->rq_method == sip_method_invite && this->mChatRoomAddr.empty()) ? call_snd : msg_snd;
}

const RFC8599PushParams& PushInfo::getDestination(PushType pType) const {
	if (mDestinations.find(pType) == mDestinations.cend()) {
		throw UnsupportedPushType{pType};
	}
	return *mDestinations.at(pType);
}
