/** Copyright (C) 2010-2024 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <string>

#include "lib/nlohmann-json-3-11-2/json.hpp"

namespace flexisip::b2bua::bridge::config::v2 {

enum struct SecretType : std::uint8_t {
	MD5,
	SHA256,
	Cleartext,
};
NLOHMANN_JSON_SERIALIZE_ENUM(SecretType,
                             {
                                 {SecretType::MD5, "md5"},
                                 {SecretType::SHA256, "sha256"},
                                 {SecretType::Cleartext, "clrtxt"},
                             })

class Account {
public:
	std::string uri = "";                    // required
	std::string userid = "";                 // optional
	SecretType secretType = SecretType::MD5; // optional
	std::string secret = "";                 // optional
	std::string alias = "";                  // optional
	std::string outboundProxy = "";          // optional

	friend bool operator==(const Account& a, const Account& b) {
		return a.uri == b.uri && a.outboundProxy == b.outboundProxy && a.alias == b.alias &&
		       a.secretType == b.secretType && a.secret == b.secret && a.userid == b.userid;
	};
	friend bool operator!=(const Account& a, const Account& b) {
		return !(a == b);
	};
};

inline void from_json(const nlohmann::json& nlohmann_json_j, Account& nlohmann_json_t) {
	Account nlohmann_json_default_obj;
	NLOHMANN_JSON_FROM(uri)
	NLOHMANN_JSON_FROM_WITH_DEFAULT(userid)
	NLOHMANN_JSON_FROM_WITH_DEFAULT(secretType)
	NLOHMANN_JSON_FROM_WITH_DEFAULT(secret)
	NLOHMANN_JSON_FROM_WITH_DEFAULT(alias)
	NLOHMANN_JSON_FROM_WITH_DEFAULT(outboundProxy)
};

inline void to_json(nlohmann::json& nlohmann_json_j, const Account& nlohmann_json_t) {
	NLOHMANN_JSON_TO(uri);
	NLOHMANN_JSON_TO(userid);
	NLOHMANN_JSON_TO(secretType);
	NLOHMANN_JSON_TO(secret);
	NLOHMANN_JSON_TO(alias);
	NLOHMANN_JSON_TO(outboundProxy)
};

inline std::ostream& operator<<(std::ostream& os, const Account& a) noexcept {
	nlohmann::json j = a;
	os << "config::v2::Account[" << j << "]";
	return os;
}

inline std::ostream& operator<<(std::ostream& os, const std::vector<Account>& vector) noexcept {
	os << "std::vector<Account>[\n";
	for (const auto& elem : vector) {
		os << '\t' << elem << ",\n";
	}
	os << "]";
	return os;
}

} // namespace flexisip::b2bua::bridge::config::v2

#if ENABLE_SOCI

#include "soci/type-conversion-traits.h"
#include "soci/values.h"

namespace soci {

/**
 * Used by soci to transform database result to ForkMessageContextDb and vice-versa.
 */
template <>
class type_conversion<flexisip::b2bua::bridge::config::v2::Account> {
public:
	using base_type = values;

	static void from_base(values const& v, indicator, flexisip::b2bua::bridge::config::v2::Account& account) {
		const auto username = v.get<std::string>("username");
		const auto hostport = v.get<std::string>("hostport");
		account.uri = "sip:" + username + "@" + hostport;
		account.userid = v.get<std::string>("user_id", "");
		account.secretType = nlohmann::json(v.get<std::string>("secret_type", "md5"))
		                         .get<flexisip::b2bua::bridge::config::v2::SecretType>();
		account.secret = v.get<std::string>("secret", "");
		const auto aliasUsername = v.get<std::string>("alias_username", "");
		const auto aliasHostport = v.get<std::string>("alias_hostport", "");
		if (aliasUsername.empty() || aliasHostport.empty()) {
			account.alias = "";
		} else {
			account.alias = "sip:" + aliasUsername + "@" + aliasHostport;
		}
		account.outboundProxy = v.get<std::string>("outbound_proxy", "");
	}
};

} // namespace soci
#endif