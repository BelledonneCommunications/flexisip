/** Copyright (C) 2010-2024 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <regex>
#include <string>

#include "flexisip/utils/sip-uri.hh"
#include "lib/nlohmann-json-3-11-2/json.hpp"
#include "utils/string-utils.hh"

#if ENABLE_SOCI

#include "soci/blob.h"
#include "soci/type-conversion-traits.h"
#include "soci/values.h"

namespace flexisip::b2bua::bridge::config::v2 {
class Account;
}

namespace soci {
template <>
struct type_conversion<flexisip::b2bua::bridge::config::v2::Account>;
}

#endif

namespace flexisip::b2bua::bridge::config::v2 {

enum struct SecretType : std::uint8_t {
	MD5,
	SHA256,
	Cleartext,
};
NLOHMANN_JSON_SERIALIZE_ENUM(
    SecretType,
    {
        {SecretType::MD5, "md5"},
        {SecretType::SHA256, "sha256"},
        // https://www.iana.org/assignments/hash-function-text-names/hash-function-text-names.xhtml
        {SecretType::SHA256, "sha-256"},
        {SecretType::Cleartext, "clrtxt"},
    })

class Account {
public:
	/**
	 * @brief Parameters used to create an Account.
	 */
	struct Parameters {
		std::string uri{""};
		std::optional<std::string> userId{std::nullopt};
		std::optional<SecretType> secretType{std::nullopt};
		std::optional<std::string> secret{std::nullopt};
		std::optional<std::string> realm{std::nullopt};
		std::optional<std::string> alias{std::nullopt};
		std::optional<std::string> outboundProxy{std::nullopt};
		std::optional<std::string> registrar{std::nullopt};
		std::optional<std::string> protocol{std::nullopt};

		bool operator==(const Parameters& other) const {
			return uri == other.uri and userId == other.userId and secretType == other.secretType and
			       secret == other.secret and realm == other.realm and alias == other.alias and
			       outboundProxy == other.outboundProxy and registrar == other.registrar and protocol == other.protocol;
		}

		bool operator!=(const Parameters& other) const {
			return !(*this == other);
		}
	};

	/**
	 * @note Default values for secretType and protocol are set to 'MD5' and 'udp' respectively.
	 */
	Account() : Account(Parameters()){};

	/**
	 * @note Default values for secretType and protocol are set to 'MD5' and 'udp' respectively.
	 * @param parameters set of parameters to initialize the account
	 */
	explicit Account(const Parameters& parameters) : mParams(parameters) {
		if (mParams.secretType == std::nullopt) mParams.secretType = kDefaultSecretType;
		if (mParams.protocol == std::nullopt) mParams.protocol = kDefaultProtocol;
	}

	Account& update(const Parameters& parameters) {
		if (!parameters.uri.empty()) mParams.uri = parameters.uri;
		if (parameters.userId.has_value()) mParams.userId = parameters.userId;
		if (parameters.secretType.has_value()) mParams.secretType = parameters.secretType;
		if (parameters.secret.has_value()) mParams.secret = parameters.secret;
		if (parameters.realm.has_value()) mParams.realm = parameters.realm;
		if (parameters.alias.has_value()) mParams.alias = parameters.alias;
		if (parameters.outboundProxy.has_value()) mParams.outboundProxy = parameters.outboundProxy;
		if (parameters.registrar.has_value()) mParams.registrar = parameters.registrar;
		if (parameters.protocol.has_value()) mParams.protocol = parameters.protocol;
		return *this;
	}

	bool operator==(const Account& other) const {
		return mParams == other.mParams;
	}

	bool operator!=(const Account& other) const {
		return mParams != other.mParams;
	}

	std::string getUri() const {
		return mParams.uri;
	}

	std::string getUserId() const {
		return mParams.userId.value_or(std::string{});
	}

	SecretType getSecretType() const {
		return mParams.secretType.value();
	}

	std::string getSecret() const {
		return mParams.secret.value_or(std::string{});
	}

	std::string getRealm() const {
		return mParams.realm.value_or(std::string{});
	}

	std::string getAlias() const {
		return mParams.alias.value_or(std::string{});
	}

	bool outboundProxyIsSet() const {
		return mParams.outboundProxy.has_value() and !mParams.outboundProxy.value().empty();
	}

	std::string getOutboundProxyUri() const {
		return makeUriFromParameter(mParams.outboundProxy);
	}

	bool registrarIsSet() const {
		return mParams.registrar.has_value() and !mParams.registrar.value().empty();
	}

	std::string getRegistrarUri() const {
		return makeUriFromParameter(mParams.registrar);
	}

	std::string getProtocol() const {
		return mParams.protocol.value();
	}

private:
#if ENABLE_SOCI
	friend struct soci::type_conversion<Account>;
#endif
	friend void from_json(const nlohmann::json& json_object, Account& account);
	friend void to_json(nlohmann::json& json_object, const Account& account);

	static constexpr SecretType kDefaultSecretType{SecretType::MD5};
	static constexpr std::string_view kDefaultSecretTypeAsStr{"md5"};
	static constexpr std::string_view kDefaultProtocol{"udp"};

	/**
	 * If the parameter is a valid SIP URI, return it as is.
	 * Else, build the SIP URI with the provided information (parameter value 'protocol').
	 */
	std::string makeUriFromParameter(const std::optional<std::string>& parameter) const {
		auto parameterValue = parameter.value_or(std::string{});

		static const std::regex sipUriPattern{"(<|)(sip|sips):.+"};
		if (std::regex_match(parameterValue, sipUriPattern)) return parameterValue;

		const auto domain = parameterValue.empty() ? SipUri{mParams.uri}.getHost() : parameterValue;
		return SipUri{"", domain, SipUri::Params{std::string{"transport=" + getProtocol()}.c_str()}}.str();
	}

	Parameters mParams;
};

// Cannot use nlohmann::json macros because of the nested structure (Parameters).
inline void from_json(const nlohmann::json& json_object, Account& account) {
	const Account def{}; // Default values.
	account.mParams = {
	    .uri = json_object.at("uri"),
	    .userId = json_object.value("userid", def.getUserId()),
	    .secretType = json_object.value("secretType", def.getSecretType()),
	    .secret = json_object.value("secret", def.getSecret()),
	    .realm = json_object.value("realm", def.getRealm()),
	    .alias = json_object.value("alias", def.getAlias()),
	    .outboundProxy = json_object.value("outboundProxy", def.mParams.outboundProxy.value_or(std::string{})),
	    .registrar = json_object.value("registrar", def.mParams.registrar.value_or(std::string{})),
	    .protocol = json_object.value("protocol", def.getProtocol()),
	};
};

// Cannot use nlohmann::json macros because of the nested structure (Parameters).
inline void to_json(nlohmann::json& json_object, const Account& account) {
	json_object = nlohmann::json{
	    {"uri", account.getUri()},
	    {"userid", account.getUserId()},
	    {"secretType", account.getSecretType()},
	    {"secret", account.getSecret()},
	    {"realm", account.getRealm()},
	    {"alias", account.getAlias()},
	    {"outboundProxy", account.mParams.outboundProxy.value_or(std::string{})},
	    {"registrar", account.mParams.registrar.value_or(std::string{})},
	    {"protocol", account.getProtocol()},
	};
}

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

namespace soci {

/**
 * Used by soci to transform database result to Account (fill attributes of the provided instance).
 */
template <>
struct type_conversion<flexisip::b2bua::bridge::config::v2::Account> {
	using base_type = values;
	using AccountConfig = flexisip::b2bua::bridge::config::v2::Account;

	static void from_base(values const& v, indicator, AccountConfig& account) {
		auto& params = account.mParams;

		const auto username = get<std::string>(v, "username");
		// Retrieve domain (or hostport for backward compatibility).
		const auto domain = getWithBackwardCompatibility<std::string>(v, "domain", "hostport");
		params.uri = flexisip::SipUri{username, domain}.str();
		params.userId = get<std::string>(v, "user_id", "");

		params.realm = get<std::string>(v, "realm", domain);
		params.secret = get<std::string>(v, "secret", "");
		const auto secretType = flexisip::string_utils::toLower(
		    get<std::string>(v, "secret_type", std::string{AccountConfig::kDefaultSecretTypeAsStr}));
		params.secretType = nlohmann::json(secretType).get<flexisip::b2bua::bridge::config::v2::SecretType>();

		const auto aliasUsername = get<std::string>(v, "alias_username", "");
		// Retrieve alias_domain (or alias_hostport for backward compatibility).
		const auto aliasDomain = getWithBackwardCompatibility<std::string>(v, "alias_domain", "alias_hostport", "");
		if (aliasUsername.empty() or aliasDomain.empty()) params.alias = "";
		else params.alias = flexisip::SipUri{aliasUsername, aliasDomain}.str();

		params.outboundProxy = getOptional<std::string>(v, "outbound_proxy", "");
		params.registrar = getOptional<std::string>(v, "registrar", "");
		params.protocol = flexisip::string_utils::toLower(
		    getOptional<std::string>(v, "protocol", std::string{AccountConfig::kDefaultProtocol}));
	}

	/**
	 * @throw runtime_error if the column 'name' has an invalid data type
	 * @return the value of the column 'name'
	 */
	template <typename TargetType>
	static TargetType
	get(const values& v, const std::string& name, const std::optional<TargetType>& nullValue = std::nullopt) {
		static const auto convertedDataType = []() -> std::pair<data_type, std::string> {
			if (std::is_same_v<TargetType, std::string>) return {dt_string, "string"};
			if (std::is_same_v<TargetType, std::tm>) return {dt_date, "timestamp"};
			if (std::is_same_v<TargetType, double>) return {dt_double, "floating-point"};
			if (std::is_same_v<TargetType, int>) return {dt_integer, "integer"};
			if (std::is_same_v<TargetType, long long>) return {dt_long_long, "big integer"};
			if (std::is_same_v<TargetType, unsigned long long>) return {dt_unsigned_long_long, "unsigned big integer"};
			if (std::is_same_v<TargetType, blob>) return {dt_blob, "blob"};
			return {static_cast<data_type>(-1), "unknown"};
		};

		const auto dataType = v.get_properties(name).get_data_type();
		const auto [targetDataType, targetDataTypeName] = convertedDataType();
		if (targetDataType != dataType)
			throw std::runtime_error("invalid data type '" + targetDataTypeName + "' for column '" + name + "'");

		if (nullValue.has_value()) return v.get<TargetType>(name, *nullValue);
		return v.get<TargetType>(name);
	}

	/**
	 * @return the value of the column 'name' or 'oldName' if the column does not exist
	 */
	template <typename T>
	static T getWithBackwardCompatibility(const values& v,
	                                      const std::string& name,
	                                      const std::string& oldName,
	                                      const std::optional<T>& nullValue = std::nullopt) {
		try {
			std::ignore = v.get_indicator(name);
		} catch (const soci_error&) {
			return get<T>(v, oldName, nullValue);
		}
		return get<T>(v, name, nullValue);
	}

	/**
	 * @return the value of the column 'name' or 'defaultValue' if the column does not exist or is null
	 */
	template <typename T>
	static T getOptional(const values& v, const std::string& name, const T& defaultValue) {
		try {
			std::ignore = v.get_indicator(name);
		} catch (const soci_error&) {
			return defaultValue;
		}
		return get(v, name, std::optional<T>{defaultValue});
	}
};

} // namespace soci
#endif