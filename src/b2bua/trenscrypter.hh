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

#include "b2bua-server.hh"

namespace flexisip {
namespace b2bua {
namespace trenscrypter {

class encryptionConfiguration {
	friend class Trenscrypter;

	linphone::MediaEncryption mode;
	std::regex pattern; /**< regular expression applied on the callee sip address, when matched, the associated
	                       mediaEncryption mode is used on the output call */
	std::string
	    stringPattern; /**< a string version of the pattern for log purpose as the std::regex does not carry it*/

public:
	encryptionConfiguration(linphone::MediaEncryption p_mode, std::string p_pattern)
	    : mode(p_mode), pattern(p_pattern), stringPattern(p_pattern){};
};

class srtpConfiguration {
	friend class Trenscrypter;

	std::list<linphone::SrtpSuite> suites;
	std::regex pattern; /**< regular expression applied on the callee sip address, when matched, the associated SRTP
	                       suites are used */
	std::string
	    stringPattern; /**< a string version of the pattern for log purposes as the std::regex does not carry it */

public:
	srtpConfiguration(std::list<linphone::SrtpSuite> p_suites, std::string p_pattern)
	    : suites(p_suites), pattern(p_pattern), stringPattern(p_pattern){};
};

/**
 * Media encryption transcoder
 */
class Trenscrypter : public b2bua::Application {
	std::shared_ptr<linphone::Core> mCore;
	std::list<encryptionConfiguration> mOutgoingEncryption;
	std::list<srtpConfiguration> mSrtpConf;

public:
	void init(const std::shared_ptr<linphone::Core>& core, const flexisip::ConfigManager& cfg) override;
	std::variant<linphone::Reason, std::shared_ptr<const linphone::Address>>
	onCallCreate(const linphone::Call& incomingCall, linphone::CallParams& outgoingCallParams) override;
};

} // namespace trenscrypter
} // namespace b2bua
} // namespace flexisip
