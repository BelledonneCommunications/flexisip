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

#include <string>
#include <variant>

#include <linphone++/address.hh>
#include <linphone++/call.hh>

#include "flexisip/utils/sip-uri.hh"

#include "b2bua/sip-bridge/accounts/account.hh"
#include "utils/string-interpolation/variable-substitution.hh"
#include "utils/uri-utils.hh"

namespace flexisip::b2bua::bridge {

using utils::string_interpolation::FieldsOf;
using utils::string_interpolation::leaf;
using utils::string_interpolation::resolve;

const auto kLinphoneAddressFields = FieldsOf<std::shared_ptr<const linphone::Address>>{
    {"", leaf([](const auto& address) { return address->asStringUriOnly(); })},
    {"user", leaf([](const std::shared_ptr<const linphone::Address>& address) {
	     return UriUtils::escape(address->getUsername(), UriUtils::sipUserReserved);
     })},
    {"hostport", leaf([](const auto& address) {
	     auto hostport = address->getDomain();
	     const auto port = address->getPort();
	     if (port != 0) {
		     hostport += ":" + std::to_string(port);
	     }
	     return hostport;
     })},
    {"uriParameters", leaf([](const auto& address) {
	     auto params = SipUri{address->asStringUriOnly()}.getParams();
	     if (!params.empty()) {
		     params = ";" + params;
	     }
	     return params;
     })},
};

const auto kLinphoneCallFields = FieldsOf<linphone::Call>{
    {"to", resolve(kLinphoneAddressFields,
                   [](const auto& call) {
	                   // FIXME: when a REFER requests is received, call.getToAddress() == call.getRemoteAddress().
	                   return linphone::Factory::get()->createAddress(call.getRemoteParams()->getCustomHeader("To"));
                   })},
    {"from", resolve(kLinphoneAddressFields, [](const auto& call) { return call.getRemoteAddress(); })},
    {"requestUri", resolve(kLinphoneAddressFields, [](const auto& call) { return call.getRequestAddress(); })},
};

const auto kLinphoneCallTransferFields = []() {
	auto copy = kLinphoneCallFields;
	copy["to"] = resolve(kLinphoneAddressFields, [](const auto& call) { return call.getReferToAddress(); });
	return copy;
}();

const auto kLinphoneEventFields = FieldsOf<linphone::Event>{
    {"to", resolve(kLinphoneAddressFields, [](const auto& event) { return event.getToAddress(); })},
    {"from", resolve(kLinphoneAddressFields, [](const auto& event) { return event.getFromAddress(); })},
    {"requestUri", resolve(kLinphoneAddressFields, [](const auto& event) { return event.getRequestAddress(); })},
};

const auto kSofiaUriFields = FieldsOf<SipUri>{
    {"", leaf([](const auto& uri) { return uri.str(); })},
    {"user", leaf([](const auto& uri) { return uri.getUser(); })},
    {"hostport", leaf([](const auto& uri) {
	     auto hostport = uri.getHost();
	     if (const auto port = uri.getPort(); port != "") {
		     hostport += ":" + port;
	     }
	     return hostport;
     })},
    {"uriParameters", leaf([](const auto& uri) {
	     auto params = uri.getParams();
	     if (!params.empty()) {
		     params = ";" + params;
	     }
	     return params;
     })},
};

const auto kAccountFields = FieldsOf<Account>{
    {"uri",
     resolve(kLinphoneAddressFields,
             [](const auto& account) { return account.getLinphoneAccount()->getParams()->getIdentityAddress(); })},
    {"alias", resolve(kSofiaUriFields, [](const auto& account) { return account.getAlias(); })},
};

} // namespace flexisip::b2bua::bridge