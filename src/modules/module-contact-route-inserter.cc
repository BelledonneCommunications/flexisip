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

#include "module-contact-route-inserter.hh"

#include "agent.hh"
#include "contact-masquerader.hh"
#include "flexisip/module.hh"

using namespace std;

namespace flexisip {

ModuleInfo<ContactRouteInserter> ContactRouteInserter::sInfo{
    "ContactRouteInserter",
    "Masquerade 'Contact' header fields of incoming REGISTER requests that are not handled locally (think about "
    "flexisip used as a SBC gateway). Flexisip is then able to route back outgoing INVITE requests to the original "
    "address. It is a sort of similar mechanism as Record-Route, but for REGISTER requests.",
    {"StatisticsCollector"},
    ModuleInfoBase::ModuleOid::ContactRouteInserter,
    [](GenericStruct& moduleConfig) {
	    ConfigItemDescriptor items[] = {
	        {
	            Boolean,
	            "masquerade-contacts-on-registers",
	            "Masquerade 'Contact' header fields in REGISTER requests with the proxy address.",
	            "true",
	        },
	        {
	            Boolean,
	            "masquerade-contacts-for-invites",
	            "Masquerade 'Contact' header fields in INVITE requests (and responses) with the proxy address.",
	            "false",
	        },
	        {
	            Boolean,
	            "insert-domain",
	            "Use the domain read from the 'From' header field when masquerading.",
	            "false",
	        },
	        config_item_end,
	    };
	    moduleConfig.addChildrenValues(items);
    },
    ModuleClass::Experimental,
};

void ContactRouteInserter::onLoad(const GenericStruct* mc) {
	mInsertDomain = mc->get<ConfigBoolean>("insert-domain")->read();
	mMasqueradeInvites = mc->get<ConfigBoolean>("masquerade-contacts-for-invites")->read();
	mMasqueradeRegisters = mc->get<ConfigBoolean>("masquerade-contacts-on-registers")->read();
	mCtRtParamName = "CtRt" + getAgent()->getUniqueId();
}

void ContactRouteInserter::onRequest(RequestSipEvent& ev) {
	const auto& msg = ev.getMsgSip();
	const auto method = msg->getSipMethod();

	if (mMasqueradeRegisters && method == sip_method_register) {
		LOGD << "Postponing contact masquerading (for REGISTER): outgoing transport not yet determined";
		ev.addBeforeSendCallback([paramName = mCtRtParamName, prefix = mLogPrefix, insertDomain = mInsertDomain](
		                             const std::shared_ptr<MsgSip>& msg, const tport_t* primary) {
			LOGD_CTX(prefix, "beforeSend") << "Masquerading contact";
			contact_masquerader::masquerade(*msg, paramName, primary, insertDomain);
		});
	} else if (mMasqueradeInvites && method == sip_method_invite) {
		LOGD << "Postponing contact masquerading (for INVITE): outgoing transport not yet determined";
		ev.addBeforeSendCallback([paramName = mCtRtParamName, prefix = mLogPrefix](const std::shared_ptr<MsgSip>& msg,
		                                                                           const tport_t* primary) {
			LOGD_CTX(prefix, "beforeSend") << "Masquerading contact";
			contact_masquerader::masquerade(*msg, paramName, primary);
		});
	}

	if (method == sip_method_register) return;

	auto* requestUri = msg->getSip()->sip_request->rq_url;
	SipUri uri{};
	try {
		uri = SipUri{requestUri};
	} catch (const std::exception& exception) {
		LOGD << "Request URI is invalid (" << exception.what() << "): aborting";
		return;
	}

	if (!uri.hasParam(mCtRtParamName)) {
		LOGD << "No contact route parameter found in the request URI: nothing to do";
		return;
	}

	LOGD << "Found a contact route parameter in the request URI: restoring";
	contact_masquerader::restore(msg->getHome(), requestUri, uri.getParam(mCtRtParamName), "doroute");
}

void ContactRouteInserter::onResponse(ResponseSipEvent& ev) {
	const auto& msg = ev.getMsgSip();
	const auto cseqMethod = msg->getSip()->sip_cseq->cs_method;

	// No need to postpone the operation here as the outgoing transport is already known.
	if (mMasqueradeInvites && (cseqMethod == sip_method_invite || cseqMethod == sip_method_subscribe))
		contact_masquerader::masquerade(*msg, mCtRtParamName, tport_parent(ev.getIncomingTport().get()));
}

} // namespace flexisip