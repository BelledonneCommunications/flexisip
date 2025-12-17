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

#include "module-sanitychecker.hh"

#include "flexisip/flexisip-exception.hh"
#include "flexisip/utils/sip-uri.hh"

using namespace std;
using namespace flexisip;

void ModuleSanityChecker::onRequest(shared_ptr<RequestSipEvent>& ev) {
	sip_t* sip = ev->getMsgSip()->getSip();

	checkHeaders(sip);
	if (sip->sip_request == nullptr || sip->sip_request->rq_url->url_host == nullptr) {
		THROW_LINE(InvalidRequestError, "bad request URI");
	}
	// RFC 6665-3.1.2: https://datatracker.ietf.org/doc/html/rfc6665#section-3.1.2
	if (sip->sip_request->rq_method == sip_method_subscribe && sip->sip_event == nullptr) {
		THROW_LINE(InvalidRequestError, "bad request, no 'Event' header in SUBSCRIBE request");
	}
}

void ModuleSanityChecker::checkHeaders(sip_t* sip) {
	if (sip->sip_via == nullptr) {
		THROW_LINE(InvalidRequestError, "no via");
	}
	if (sip->sip_from == nullptr || sip->sip_from->a_url->url_host == nullptr || sip->sip_from->a_tag == nullptr) {
		THROW_LINE(InvalidRequestError, "invalid from header");
	}
	if (sip->sip_to == nullptr || sip->sip_to->a_url->url_host == nullptr) {
		THROW_LINE(InvalidRequestError, "invalid to header");
	}
	sofiasip::Url urlFrom{sip->sip_from->a_url};
	auto fromParsingError = SipUri::hasParsingError(urlFrom);
	if (fromParsingError) {
		THROW_LINE(InvalidRequestError,
		           "invalid URI in from header [" + urlFrom.str() + "]: " + fromParsingError.value());
	}
	sofiasip::Url urlTo{sip->sip_to->a_url};
	auto toParsingError = SipUri::hasParsingError(urlTo);
	if (toParsingError) {
		THROW_LINE(InvalidRequestError, "invalid URI in to header [" + urlTo.str() + "]: " + toParsingError.value());
	}
	if (sip->sip_contact) {
		if (sip->sip_contact->m_url->url_scheme == nullptr) {
			THROW_LINE(InvalidRequestError, "invalid scheme in contact header");
		}
		if (sip->sip_contact->m_url->url_scheme[0] != '*' && sip->sip_contact->m_url->url_host == nullptr) {
			THROW_LINE(InvalidRequestError, "invalid contact header");
		}
	}
}

ModuleInfo<ModuleSanityChecker> ModuleSanityChecker::sInfo(
    "SanityChecker",
    "The SanitChecker module checks that required fields of a SIP message are present to avoid unecessary checking "
    "while "
    "processing message further.\n"
    "If the message doesn't meet these sanity check criterias, then it is stopped and bad request response is sent.",
    {"DoSProtection"},
    ModuleInfoBase::ModuleOid::SanityChecker,
    [](GenericStruct&) {});
