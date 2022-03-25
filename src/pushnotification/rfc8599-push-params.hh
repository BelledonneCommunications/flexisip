/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

	std::set<PushType> getSupportedPNTypes() const noexcept;

	bool isApns() const noexcept {
		return mProvider == "apns" || mProvider == "apns.dev";
	}

	using ParsingResult = std::map<PushType, std::shared_ptr<const RFC8599PushParams>>;

	/**
	 * Parse the RFC8599-extended parameters and returns a map which associates
	 * a PushType to the according RFC8599 parameter set.
	 * @throw std::runtime_error if one given parameter has an invalid syntax.
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
	 * Same as before but expect the legacy parameter instead of RFC8599.
	 */
	static ParsingResult parseLegacyPushParams(const char* params);

private:
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
} // namespace flexisip
