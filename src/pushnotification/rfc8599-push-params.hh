/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

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

#include <map>
#include <memory>
#include <regex>
#include <set>
#include <string>

#include "push-type.hh"

namespace flexisip {
namespace pushnotification {

/**
 * Class that represents a set of consistent push parameters as defined in RFC8599.
 */
class RFC8599PushParams {
public:
	RFC8599PushParams() = default;
	RFC8599PushParams(const std::string& pnProvider, const std::string& pnParam, const std::string& pnPrid) {
		setFromPushParams(pnProvider, pnParam, pnPrid);
	}

	const std::string& getProvider() const noexcept {
		return mProvider;
	}
	const std::string& getParam() const noexcept {
		return mParam;
	}
	const std::string& getPrid() const noexcept {
		return mPrid;
	}

	/**
	 * Set the RFC8599 parameters without verification.
	 */
	void setFromPushParams(const std::string& pnProvider, const std::string& pnParam, const std::string& pnPrid);
	/**
	 * Set the RFC8599 parameters without verification by using legacy parameters.
	 */
	void setFromLegacyParams(const std::string& pnType, const std::string& pnParam, const std::string& pnTok);

	/**
	 * @brief Return the set of supported push notification types
	 * according the value of the 'provider' and 'param' parameters.
	 */
	std::set<PushType> getSupportedPNTypes() const noexcept;

	/**
	 * @brief Test whether the provider matches the Apple Push Notification Sevice.
	 */
	bool isApns() const noexcept {
		return isApns(mProvider);
	}

	bool isFirebase() const noexcept {
		return mProvider == "fcm";
	}

	/**
	 * @brief Equality operator definition.
	 * @param aOther the other push params object to compare with.
	 * @return true when the (provider, param, prid) triplets are strictly equal.
	 */
	bool operator==(const RFC8599PushParams& aOther) const noexcept {
		return getProvider() == aOther.getProvider() && getParam() == aOther.getParam() &&
		       getPrid() == aOther.getPrid();
	}

	/**
	 * @brief Serialize the object as semi-colomn separated
	 * list of URI paramters as described by RFC8599 i.e.
	 * 'pn-provider=<provider>;pn-param=<param>;pn-prid=<prid>'
	 */
	std::string toUriParams() const;

	/**
	 * Returns a RFC8599 triplet with values randomly generated according
	 * the format of a given provider.
	 * @param aProvider The provider to use. Accepted values: 'apns', 'apns.dev', 'fcm'.
	 * @param aPType For 'apns' and 'apns.dev' providers, the value of 'pn-params' parameter
	 * depends of the kind of push notification. Use PushType::Message or PushType::Background
	 * to generate 'remote' PN parameters and PushType::VoIP for 'voip' PN parameters.
	 * PushType::Unknown is denied.
	 * @throw std::invalid_argument if the given provider is unsupported, or pType is
	 * PushType::Unknown whereas the provider matches 'apns{,.dev}'.
	 */
	static RFC8599PushParams generatePushParams(const std::string& provider, PushType pType = PushType::Unknown);
	/**
	 * Forge a single RFC8599 paramters triplet from an APNS remote and
	 * an APNS voip push paramters triplets.
	 * @param aRemotePushParams The 'remote' push paramters.
	 * @param aVoipPushParams The 'voip' push parameters.
	 * @return A push paramters triplet containing the information
	 * of the two given triplets, formated like this:
	 *   * pn-provider: 'apns' or 'apns.dev';
	 *   * pn-param: '<ProjectID>.<AppID>.remote&voip';
	 *   * pn-prid: '<remoteToken>:remote&<voipToken>:voip'
	 *
	 * @throw std::invalid_argument if the two given triplets cannot be mixed i.e.:
	 *   * the provider of one doesn't match 'apns{,.dev}';
	 *   * the two triplets haven't the same provider;
	 *   * the 'pn-param' parameter of the two triplet haven't the same '<ProjectID>.<AppID>' string;
	 *   * aRemotePushParams has invalid values for 'remote' PN;
	 *   * aVoipPashParams has invalid values for 'voip' PN.
	 */
	static RFC8599PushParams concatPushParams(const RFC8599PushParams& aRemotePushParams,
	                                          const RFC8599PushParams& aVoipPushParams);

	/**
	 * Return type of parse*() methods.
	 */
	using ParsingResult = std::map<PushType, std::shared_ptr<const RFC8599PushParams>>;
	/**
	 * Parse the RFC8599-extended parameters and returns a map which associates
	 * a PushType to the according RFC8599 parameter set.
	 * @throw std::runtime_error if one given parameter has an invalid syntax or the provider isn't supported.
	 */
	static ParsingResult
	parsePushParams(const std::string& pnProvider, const std::string& pnParam, const std::string& pnPrid);

	/**
	 * Same as before except it takes a C-string which
	 * contains the push parameters extracted by SofiaSip. The string
	 * may contains extra parameter but 'pn-provider', 'pn-param' and 'pn-prid'
	 * must be present or std::runtime_error exception will be raised.
	 */
	static ParsingResult parsePushParams(const char* params);
	/**
	 * Same as parsePushParams() but expect the legacy parameters instead of RFC8599.
	 * @throw std::runtime_error if the legacy parameters couldn't be translated in the RFC8599 format.
	 */
	static ParsingResult parseLegacyPushParams(const char* params);

private:
	// Private methods
	/**
	 * Test whether a given 'pn-provider' parameter matches the Apple Push Notification Service.
	 */
	static bool isApns(const std::string& aProvider) noexcept {
		return aProvider == "apns" || aProvider == "apns.dev";
	}

	// Private attributes
	std::string mProvider{}; /**< Value of 'pn-provider' */
	std::string mParam{};    /**< Value of 'pn-param' */
	std::string mPrid{};     /**< Value of 'pn-prid' */

	static const std::regex sApplePnProviderRegex;
	static const std::regex sPnParamRegex;
	static const std::regex sPnParamNoServiceRegex;
	static const std::regex sPnPridOneTokenRegex;
	static const std::regex sPnPridMultipleTokensRegex;
};

} // namespace pushnotification

inline std::ostream& operator<<(std::ostream& aOs, const pushnotification::RFC8599PushParams& aPushParams) noexcept {
	return aOs << "{'" << aPushParams.getProvider() << "', '" << aPushParams.getProvider() << "', '"
	           << aPushParams.getPrid() << "'}";
}

} // namespace flexisip

namespace std {

/**
 * Allow to use RFC8599PushParams class as key of std::unordered_map
 */
template <>
struct hash<flexisip::pushnotification::RFC8599PushParams> {
	auto operator()(const flexisip::pushnotification::RFC8599PushParams& key) const {
		return std::hash<std::string>{}(key.getProvider() + key.getParam() + key.getPrid());
	}
};

} // namespace std
