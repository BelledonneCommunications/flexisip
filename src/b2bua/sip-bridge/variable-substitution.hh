/** Copyright (C) 2010-2024 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <string>
#include <variant>

#include <linphone++/address.hh>
#include <linphone++/call.hh>

#include "flexisip/utils/sip-uri.hh"

#include "b2bua/sip-bridge/accounts/account.hh"
#include "utils/string-interpolation/exceptions.hh"
#include "utils/string-utils.hh"

namespace flexisip::b2bua::bridge::variable_substitution {

template <typename... Args>
using Substituter = std::function<std::string(const Args&...)>;

template <typename... Args>
using Resolver = std::function<Substituter<Args...>(std::string_view)>;

template <typename... Args>
using FieldsOf = std::unordered_map<std::string_view, Resolver<Args...>>;

/**
 * @brief Builds a leaf Resolver that does not accept any sub fields
 *
 * @param substituter the substitution function for this field
 */
template <typename TSubstituter>
constexpr auto leaf(TSubstituter substituter) {
	return [substituter](std::string_view furtherPath) {
		if (furtherPath != "") {
			throw utils::string_interpolation::ContextlessResolutionError(furtherPath);
		}

		return substituter;
	};
}

inline std::pair<std::string_view, std::string_view> popVarName(std::string_view dotPath) {
	const auto split = StringUtils::splitOnce(dotPath, ".");
	if (!split) return {dotPath, ""};

	const auto [head, tail] = *split;
	return {head, tail};
}

/**
 * @brief Builds a (sub-)Resolver from a transformation function and fields map
 *
 * @param fields Available fields in this resolution context
 * @param transformer Callable to extract a new sub-context (field) from the current context
 */
template <typename... Context, typename Transformer = std::nullopt_t>
constexpr auto resolve(FieldsOf<Context...> const& fields, Transformer transformer = std::nullopt) {
	return [transformer, &fields](const auto dotPath) {
		const auto& [varName, furtherPath] = popVarName(dotPath);
		const auto& resolver = fields.find(varName);
		if (resolver == fields.end()) {
			throw utils::string_interpolation::ContextlessResolutionError(varName);
		}

		const auto& substituter = resolver->second(furtherPath);

		return [substituter, transformer](const auto&... args) {
			if constexpr (!std::is_same_v<Transformer, std::nullopt_t>) {
				return substituter(transformer(args...));
			} else {
				return substituter(args...);
				std::ignore = transformer; // Suppress unused warning
			}
		};
	};
}

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

const auto kLinphoneEventFields = FieldsOf<linphone::Event>{
    {"to", resolve(kLinphoneAddressFields, [](const auto& event) { return event.getToAddress(); })},
    {"from", resolve(kLinphoneAddressFields, [](const auto& event) { return event.getFromAddress(); })},
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

} // namespace flexisip::b2bua::bridge::variable_substitution