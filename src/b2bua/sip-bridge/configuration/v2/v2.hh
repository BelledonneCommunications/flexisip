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

/*
    In-memory representation of a Provider configuration file
*/

#pragma once

#include <string>
#include <variant>
#include <vector>

#include "b2bua/sip-bridge/configuration/media-encryption.hh"
#include "b2bua/sip-bridge/configuration/v1.hh"
#include "b2bua/sip-bridge/configuration/v2/account.hh"
#include "flexiapi/schemas/optional-json.hh"
#include "lib/nlohmann-json-3-11-2/json.hpp"

namespace flexisip::b2bua::bridge::config::v2 {
namespace account_selection {

struct Random {};

struct FindInPool {
	std::string by = "{uri}"; // required
	std::string source = "";  // required
};
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(FindInPool, by, source);

} // namespace account_selection
using AccountToUse = std::variant<account_selection::Random, account_selection::FindInPool>;

namespace trigger_cond {

struct MatchRegex {
	std::string pattern = ""; // required
	std::string source = "";  // required
};
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(MatchRegex, pattern, source);

struct Always {};

} // namespace trigger_cond
using TriggerCondition = std::variant<trigger_cond::MatchRegex, trigger_cond::Always>;

} // namespace flexisip::b2bua::bridge::config::v2

NLOHMANN_JSON_NAMESPACE_BEGIN
template <>
struct adl_serializer<flexisip::b2bua::bridge::config::v2::AccountToUse> {
	static void to_json(json&, const flexisip::b2bua::bridge::config::v2::AccountToUse&) {
		throw std::runtime_error{"unimplemented"};
	}

	static void from_json(const json& j, flexisip::b2bua::bridge::config::v2::AccountToUse& accountToUse) {
		using namespace flexisip::b2bua::bridge::config::v2::account_selection;
		const auto strategy = j.at("strategy").get<std::string_view>();
		if (strategy == "Random") {
			accountToUse = Random{};
		} else if (strategy == "FindInPool") {
			accountToUse = j.get<FindInPool>();
		} else {
			throw std::runtime_error{
			    "Unknown 'accountToUse/strategy' found in config. Supported strategies are 'Random' "
			    "and 'FindInPool', not: " +
			    std::string(strategy)};
		}
	}
};

template <>
struct adl_serializer<flexisip::b2bua::bridge::config::v2::TriggerCondition> {
	static void to_json(json&, const flexisip::b2bua::bridge::config::v2::TriggerCondition&) {
		throw std::runtime_error{"unimplemented"};
	}

	static void from_json(const json& j, flexisip::b2bua::bridge::config::v2::TriggerCondition& triggerCond) {
		using namespace flexisip::b2bua::bridge::config::v2::trigger_cond;
		const auto strategy = j.at("strategy").get<std::string_view>();
		if (strategy == "MatchRegex") {
			triggerCond = j.get<MatchRegex>();
		} else if (strategy == "Always") {
			triggerCond = Always{};
		} else {
			throw std::runtime_error{
			    "Unknown 'triggerCondition/strategy' found in config. Supported strategies are 'MatchRegex' "
			    "and 'Always', not: " +
			    std::string(strategy)};
		}
	};
};
NLOHMANN_JSON_NAMESPACE_END

namespace flexisip::b2bua::bridge::config::v2 {

using AccountPoolName = std::string;

enum struct OnAccountNotFound : std::uint8_t {
	NextProvider,
	Decline,
};
NLOHMANN_JSON_SERIALIZE_ENUM(OnAccountNotFound,
                             {
                                 {OnAccountNotFound::NextProvider, "nextProvider"},
                                 {OnAccountNotFound::Decline, "decline"},
                             })

struct OutgoingInvite {
	std::string to = "";                                                     // required
	std::string from = "";                                                   // optional
	std::optional<std::string> outboundProxy = std::nullopt;                 // optional
	std::optional<bool> enableAvpf = std::nullopt;                           // optional
	std::optional<linphone::MediaEncryption> mediaEncryption = std::nullopt; // optional
};
inline void from_json(const nlohmann ::json& nlohmann_json_j, OutgoingInvite& nlohmann_json_t) {
	OutgoingInvite nlohmann_json_default_obj;
	NLOHMANN_JSON_FROM(to)
	NLOHMANN_JSON_FROM_WITH_DEFAULT(from)
	NLOHMANN_JSON_FROM_WITH_DEFAULT(outboundProxy)
	NLOHMANN_JSON_FROM_WITH_DEFAULT(enableAvpf)
	NLOHMANN_JSON_FROM_WITH_DEFAULT(mediaEncryption)
};

struct OutgoingNotify {
	std::string outboundProxy = ""; // required
};
inline void from_json(const nlohmann ::json& nlohmann_json_j, OutgoingNotify& nlohmann_json_t) {
	NLOHMANN_JSON_FROM(outboundProxy)
}

struct Provider {
	std::string name = "";                                                 // required
	AccountPoolName accountPool = "";                                      // required
	TriggerCondition triggerCondition = trigger_cond::Always();            // required
	AccountToUse accountToUse = account_selection::Random();               // required
	OnAccountNotFound onAccountNotFound = OnAccountNotFound::NextProvider; // required
	OutgoingInvite outgoingInvite = {};                                    // required
	OutgoingNotify outgoingNotify = {};                                    // optional
};
inline void from_json(const nlohmann ::json& nlohmann_json_j, Provider& nlohmann_json_t) {
	Provider nlohmann_json_default_obj;
	NLOHMANN_JSON_FROM(name)
	NLOHMANN_JSON_FROM(accountPool)
	NLOHMANN_JSON_FROM(triggerCondition)
	NLOHMANN_JSON_FROM(accountToUse)
	NLOHMANN_JSON_FROM(onAccountNotFound)
	NLOHMANN_JSON_FROM(outgoingInvite)
	NLOHMANN_JSON_FROM_WITH_DEFAULT(outgoingNotify)
}

struct SQLLoader {
	std::string dbBackend = "";   // required
	std::string initQuery = "";   // required
	std::string updateQuery = ""; // required
	std::string connection = "";  // required
	int32_t threadPoolSize = 50;  // optional
};
inline void from_json(const nlohmann ::json& nlohmann_json_j, SQLLoader& nlohmann_json_t) {
	SQLLoader nlohmann_json_default_obj;
	NLOHMANN_JSON_FROM(dbBackend);
	NLOHMANN_JSON_FROM(initQuery);
	NLOHMANN_JSON_FROM(updateQuery);
	NLOHMANN_JSON_FROM(connection);
	NLOHMANN_JSON_FROM_WITH_DEFAULT(threadPoolSize);
};

using StaticLoader = std::vector<Account>;

using AccountPoolLoader = std::variant<StaticLoader, SQLLoader>;
inline void from_json(const nlohmann ::json& nlohmann_json_j, AccountPoolLoader& pool) {
	if (nlohmann_json_j.is_array()) {
		pool = nlohmann_json_j.get<StaticLoader>();
	} else {
		pool = nlohmann_json_j.get<SQLLoader>();
	}
}

struct AccountPool {
	bool registrationRequired = false;         // required
	uint32_t maxCallsPerLine = 0;              // required
	AccountPoolLoader loader = {};             // required
	std::string outboundProxy = "";            // optional
	std::string registrar = "";                // optional
	uint32_t registrationThrottlingRateMs = 0; // optional
	std::string mwiServerUri = "";             // optional
	bool unregisterOnServerShutdown = true;    // optional
};
inline void from_json(const nlohmann ::json& nlohmann_json_j, AccountPool& nlohmann_json_t) {
	AccountPool nlohmann_json_default_obj;
	NLOHMANN_JSON_FROM(registrationRequired)
	NLOHMANN_JSON_FROM(maxCallsPerLine)
	NLOHMANN_JSON_FROM(loader)
	NLOHMANN_JSON_FROM_WITH_DEFAULT(outboundProxy)
	NLOHMANN_JSON_FROM_WITH_DEFAULT(registrar)
	NLOHMANN_JSON_FROM_WITH_DEFAULT(registrationThrottlingRateMs)
	NLOHMANN_JSON_FROM_WITH_DEFAULT(mwiServerUri)
	NLOHMANN_JSON_FROM_WITH_DEFAULT(unregisterOnServerShutdown)
}

using AccountPoolConfigMap = std::unordered_map<AccountPoolName, AccountPool>;
struct Root {
	unsigned int schemaVersion = 2;         // required
	std::vector<Provider> providers = {};   // required
	AccountPoolConfigMap accountPools = {}; // required
};
inline void from_json(const nlohmann ::json& nlohmann_json_j, Root& nlohmann_json_t) {
	NLOHMANN_JSON_FROM(schemaVersion);
	NLOHMANN_JSON_FROM(providers);
	NLOHMANN_JSON_FROM(accountPools);
}

Root fromV1(v1::Root&&);

} // namespace flexisip::b2bua::bridge::config::v2