/** Copyright (C) 2010-2024 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <string>
#include <variant>

#include <linphone++/address.hh>
#include <linphone++/call.hh>

#include "flexisip/utils/sip-uri.hh"

#include "b2bua/sip-bridge/accounts/account.hh"
#include "utils/string-interpolation/variable-substitution.hh"

namespace flexisip::b2bua::bridge {

using utils::string_interpolation::FieldsOf;
using utils::string_interpolation::leaf;
using utils::string_interpolation::resolve;

const auto kLinphoneAddressFields = FieldsOf<std::shared_ptr<const linphone::Address>>{
    {"", leaf([](const auto& address) { return address->asStringUriOnly(); })},
    {"user", leaf([](const std::shared_ptr<const linphone::Address>& address) { return address->getUsername(); })},
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
    {"to", resolve(kLinphoneAddressFields, [](const auto& call) { return call.getToAddress(); })},
    {"from", resolve(kLinphoneAddressFields, [](const auto& call) { return call.getRemoteAddress(); })},
    {"requestUri", resolve(kLinphoneAddressFields, [](const auto& call) { return call.getRequestAddress(); })},
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