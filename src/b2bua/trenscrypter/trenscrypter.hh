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

#include "b2bua/b2bua-server.hh"

namespace flexisip::b2bua::trenscrypter {

class encryptionConfiguration {
public:
	encryptionConfiguration(linphone::MediaEncryption p_mode, const std::string& p_pattern)
	    : mode(p_mode), pattern(p_pattern), stringPattern(p_pattern){};

private:
	friend class Trenscrypter;

	linphone::MediaEncryption mode;
	// Regular expression applied on the callee SIP address, when it matches, the associated mediaEncryption mode is
	// used for the outgoing call.
	std::regex pattern;
	// A string version of the pattern for log purpose as the std::regex does not carry it.
	std::string stringPattern;
};

class srtpConfiguration {
public:
	srtpConfiguration(const std::list<linphone::SrtpSuite>& p_suites, const std::string& p_pattern)
	    : suites(p_suites), pattern(p_pattern), stringPattern(p_pattern){};

private:
	friend class Trenscrypter;

	std::list<linphone::SrtpSuite> suites;
	// Regular expression applied on the callee SIP address, when it matches, the associated SRTP suites are used for
	// the outgoing call.
	std::regex pattern;
	// A string version of the pattern for log purposes as the std::regex does not carry it.
	std::string stringPattern;
};

/**
 * B2BUA server application: media encryption transcoder.
 */
class Trenscrypter : public b2bua::Application {
public:
	void init(const std::shared_ptr<B2buaCore>& core, const flexisip::ConfigManager& cfg) override;
	std::variant<linphone::Reason, std::shared_ptr<const linphone::Address>>
	onCallCreate(const linphone::Call& incomingCall, linphone::CallParams& outgoingCallParams) override;

private:
	std::shared_ptr<linphone::Core> mCore;
	std::list<encryptionConfiguration> mOutgoingEncryption;
	std::list<srtpConfiguration> mSrtpConf;
	const std::string mLogPrefix{B2buaServer::kLogPrefix + std::string{"::trenscrypter"}};
};

} // namespace flexisip::b2bua::trenscrypter