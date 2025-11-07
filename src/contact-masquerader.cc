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

#include "contact-masquerader.hh"

using namespace std;
using namespace flexisip;
using namespace sofiasip;

void ContactMasquerader::masquerade(su_home_t* home, sip_contact_t* contact, const string& domain) const {
	if (contact == nullptr) {
		LOGD << "Contact is empty: aborting";
		return;
	}
	SipUri uri{};
	try {
		uri = SipUri{contact->m_url};
	} catch (const std::exception& exception) {
		LOGD << "Contact is invalid (" << exception.what() << "): aborting";
		return;
	}
	if (uri.getSchemeType() == SipUri::Scheme::any) {
		LOGD << "Contact is star '*': aborting";
		return;
	}

	string param = (uri.hasParam("transport") ? uri.getParam("transport") : "udp") + ":";
	if (!domain.empty()) {
		// param=transport:domain
		param += domain;
	} else {
		// param=transport:ip_prev_hop:port_prev_hop
		param += uri.getHost() + ":" + uri.getPortWithFallback().data();
	}

	const auto transportUri = SipUri{mAgent->getDefaultUri()};
	uri = uri.replaceScheme(transportUri.getSchemeType());
	uri = uri.replaceHost(transportUri.getHost());
	uri = uri.replacePort(transportUri.getPort());

	if (transportUri.hasParam("transport")) uri = uri.setParameter("transport", transportUri.getParam("transport"));

	uri = uri.setParameter(mCtRtParamName, param);

	*contact->m_url = *url_hdup(home, uri.get());
	LOGD << "Contact rewritten to: " << uri.str();
}

void ContactMasquerader::masquerade(MsgSip& ms, bool insertDomain) const {
	auto* contact = ms.getSip()->sip_contact;
	const string domain{insertDomain ? ms.getSip()->sip_from->a_url->url_host : ""};

	while (contact) {
		if (contact->m_expires && strcmp(contact->m_expires, "0") == 0 &&
		    (contact != ms.getSip()->sip_contact || contact->m_next)) {
			LOGD << "Removing contact header with 'expires=0': " << SipUri{contact->m_url}.str();
			auto* tmp = contact->m_next;
			msg_header_remove(ms.getMsg(), reinterpret_cast<msg_pub_t*>(ms.getSip()),
			                  reinterpret_cast<msg_header_t*>(contact));
			contact = tmp;
		} else {
			masquerade(ms.getHome(), contact, domain);
			contact = contact->m_next;
		}
	}
}

void ContactMasquerader::restore(su_home_t* home, url_t* dest, const string& param, const string& newParam) const {
	SipUri uri{};
	try {
		uri = SipUri{dest};
	} catch (const std::exception& exception) {
		LOGD << "Provided URI is invalid (" << exception.what() << "): aborting";
		return;
	}

	uri.removeParam(mCtRtParamName);
	uri.removeParam("maddr");
	uri.removeParam("transport");

	const auto paramParsingResult = string_utils::split(param, ":");
	if (paramParsingResult.size() != 3) {
		LOGD << "Contact parameter '" << param << "' does not have the right format: aborting";
		return;
	}

	const auto& transport = paramParsingResult[0];
	const auto& host = paramParsingResult[1];
	const auto& port = paramParsingResult[2];

	if (!string_utils::iequals(transport, "udp")) uri = uri.setParameter("transport", transport);

	uri = uri.replaceHost(host);
	uri = uri.replacePort(port);

	if (!newParam.empty()) uri = uri.setParameter(newParam, "");

	*dest = *url_hdup(home, uri.get());
	LOGD << "Request URI changed to: '" << uri.str() << "'";
}