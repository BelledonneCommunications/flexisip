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

#include "utils/string-utils.hh"

#include "trenscrypter.hh"

#define FUNC_LOG_PREFIX (mLogPrefix + "::" + __func__ + "()")

namespace flexisip::b2bua::trenscrypter {

namespace {

/**
 * @brief Convert a linphone::MediaEncryption to string.
 *
 * @param[in] encryptionMode the MediaEncryption to be converted
 * @return the corresponding string, one of: {zrtp, sdes, dtls-srtp, none}, or an error message if no match was found.
 **/
std::string MediaEncryption2string(const linphone::MediaEncryption mode) {
	switch (mode) {
		case linphone::MediaEncryption::ZRTP:
			return "zrtp";
		case linphone::MediaEncryption::SRTP:
			return "sdes";
		case linphone::MediaEncryption::DTLS:
			return "dtls-srtp";
		case linphone::MediaEncryption::None:
			return "none";
	}
	return "Error - MediaEncryption2string is missing a case of MediaEncryption value";
}

/**
 * @brief Convert a configuration string to a linphone::SrtpSuite.
 *
 * @param[in] configString the configuration string, one of: AES_CM_128_HMAC_SHA1_80, AES_CM_128_HMAC_SHA1_32,
 *                         AES_192_CM_HMAC_SHA1_80, AES_192_CM_HMAC_SHA1_32,
 *                         AES_256_CM_HMAC_SHA1_80, AES_256_CM_HMAC_SHA1_32
 *                         AEAD_AES_128_GCM, AEAD_AES_256_GCM
 *
 * @return the converted value, Invalid if the input string was invalid
 **/
linphone::SrtpSuite string2SrtpSuite(const std::string configString) {
	if (configString == std::string{"AES_CM_128_HMAC_SHA1_80"}) {
		return linphone::SrtpSuite::AESCM128HMACSHA180;
	}
	if (configString == std::string{"AES_CM_128_HMAC_SHA1_32"}) {
		return linphone::SrtpSuite::AESCM128HMACSHA132;
	}
	if (configString == std::string{"AES_192_CM_HMAC_SHA1_80"}) {
		return linphone::SrtpSuite::AES192CMHMACSHA180;
	}
	if (configString == std::string{"AES_192_CM_HMAC_SHA1_32"}) {
		return linphone::SrtpSuite::AES192CMHMACSHA132;
	}
	if (configString == std::string{"AES_256_CM_HMAC_SHA1_80"}) {
		return linphone::SrtpSuite::AES256CMHMACSHA180;
	}
	if (configString == std::string{"AES_256_CM_HMAC_SHA1_32"}) {
		return linphone::SrtpSuite::AES256CMHMACSHA132;
	}
	if (configString == std::string{"AEAD_AES_128_GCM"}) {
		return linphone::SrtpSuite::AEADAES128GCM;
	}
	if (configString == std::string{"AEAD_AES_256_GCM"}) {
		return linphone::SrtpSuite::AEADAES256GCM;
	}
	return linphone::SrtpSuite::Invalid;
}

std::string SrtpSuite2string(const linphone::SrtpSuite suite) {
	switch (suite) {
		case linphone::SrtpSuite::AESCM128HMACSHA180:
			return "AES_CM_128_HMAC_SHA1_80";
		case linphone::SrtpSuite::AESCM128HMACSHA132:
			return "AES_CM_128_HMAC_SHA1_32";
		case linphone::SrtpSuite::AES192CMHMACSHA180:
			return "AES_192_CM_HMAC_SHA1_80";
		case linphone::SrtpSuite::AES192CMHMACSHA132:
			return "AES_192_CM_HMAC_SHA1_32";
		case linphone::SrtpSuite::AES256CMHMACSHA180:
			return "AES_256_CM_HMAC_SHA1_80";
		case linphone::SrtpSuite::AES256CMHMACSHA132:
			return "AES_256_CM_HMAC_SHA1_32";
		case linphone::SrtpSuite::AEADAES128GCM:
			return "AEAD_AES_128_GCM";
		case linphone::SrtpSuite::AEADAES256GCM:
			return "AEAD_AES_256_GCM";
		case linphone::SrtpSuite::Invalid:
			return "Invalid";
	}
	return "Invalid";
}

std::string SrtpSuite2string(const std::list<linphone::SrtpSuite> suites) {
	std::string ret{};
	for (const auto suite : suites) {
		ret.append(SrtpSuite2string(suite) + ", ");
	}
	return ret;
}

/**
 * @brief Explode a string into a vector of strings according to a delimiter
 *
 * @param[in] s         the string to explode
 * @param[in] delimiter the delimiter to use
 * @return a vector of strings
 */
std::vector<std::string> explode(const std::string& s, char delimiter) {
	std::vector<std::string> tokens;
	std::string token;
	std::istringstream tokenStream(s);
	while (std::getline(tokenStream, token, delimiter)) {
		tokens.push_back(token);
	}
	return tokens;
}

// Name of the corresponding section in the configuration file
constexpr auto configSection = "b2bua-server::trenscrypter";

} // namespace

std::variant<linphone::Reason, std::shared_ptr<const linphone::Address>>
Trenscrypter::onCallCreate(const linphone::Call& incomingCall, linphone::CallParams& outgoingCallParams) {
	auto callee = incomingCall.getToAddress();
	const auto calleeAddressUriOnly = callee->asStringUriOnly();
	outgoingCallParams.setFromHeader(incomingCall.getRemoteAddress()->asString());

	// Select an outgoing encryption.
	bool outgoingEncryptionSet = false;
	for (auto& outEncSetting : mOutgoingEncryption) {
		if (std::regex_match(calleeAddressUriOnly, outEncSetting.pattern)) {
			SLOGD << FUNC_LOG_PREFIX << ": call to " << calleeAddressUriOnly << " matches regex "
			      << outEncSetting.stringPattern << " assign encryption mode "
			      << MediaEncryption2string(outEncSetting.mode);
			outgoingCallParams.setMediaEncryption(outEncSetting.mode);
			outgoingEncryptionSet = true;
			// Stop at the first matching regexp.
			break;
		}
	}
	if (outgoingEncryptionSet == false) {
		SLOGD << FUNC_LOG_PREFIX << ": call to " << calleeAddressUriOnly << " uses incoming encryption setting";
	}

	// When outgoing encryption mode is sdes, select a crypto suite list setting if a pattern matches.
	if (outgoingCallParams.getMediaEncryption() == linphone::MediaEncryption::SRTP) {
		for (auto& outSrtpSetting : mSrtpConf) {
			if (std::regex_match(calleeAddressUriOnly, outSrtpSetting.pattern)) {
				SLOGD << FUNC_LOG_PREFIX << ": call to " << calleeAddressUriOnly << " matches SRTP suite regex "
				      << outSrtpSetting.stringPattern << " assign Srtp Suites to "
				      << SrtpSuite2string(outSrtpSetting.suites);
				outgoingCallParams.setSrtpSuites(outSrtpSetting.suites);
				break; // stop at the first matching regexp
			}
		}
	}

	// Check the selected outgoing encryption setting is available.
	if (!mCore->isMediaEncryptionSupported(outgoingCallParams.getMediaEncryption())) {
		SLOGD << FUNC_LOG_PREFIX << ": trying to place an outgoing call using "
		      << MediaEncryption2string(outgoingCallParams.getMediaEncryption())
		      << " encryption mode but it is not available";
		return linphone::Reason::NotAcceptable;
	}

	return callee;
}

void Trenscrypter::init(const std::shared_ptr<B2buaCore>& core, const flexisip::ConfigManager& cfg) {
	mCore = core;
	const auto* configRoot = cfg.getRoot();
	const auto* config = configRoot->get<GenericStruct>(configSection);

	// Create a non registered account to force route outgoing call through the proxy.
	const auto factory = linphone::Factory::get();
	auto route = factory->createAddress(
	    configRoot->get<GenericStruct>(b2bua::configSection)->get<ConfigString>("outbound-proxy")->read());
	auto accountParams = mCore->createAccountParams();
	accountParams->setIdentityAddress(factory->createAddress(mCore->getPrimaryContact()));
	accountParams->enableRegister(false);
	accountParams->setServerAddress(route);
	accountParams->setRoutesAddresses({route});
	auto account = mCore->createAccount(accountParams);
	mCore->addAccount(account);
	mCore->setDefaultAccount(account);

	// Parse configuration for outgoing encryption mode.
	auto outgoingEncryptionList = config->get<ConfigStringList>("outgoing-enc-regex")->read();
	// Parse from the list beginning, we shall have couple: encryption_mode regex.
	while (outgoingEncryptionList.size() >= 2) {
		if (const auto outgoingEncryption = StringUtils::string2MediaEncryption(outgoingEncryptionList.front())) {
			outgoingEncryptionList.pop_front();
			try {
				mOutgoingEncryption.emplace_back(*outgoingEncryption, outgoingEncryptionList.front());
			} catch (const std::exception& e) {
				SLOGW << mLogPrefix << ": configuration error, outgoing-enc-regex contains invalid regex ("
				      << outgoingEncryptionList.front() << ")";
			}
			outgoingEncryptionList.pop_front();
		} else {
			SLOGW << mLogPrefix << ": configuration error, outgoing-enc-regex contains invalid encryption mode ("
			      << outgoingEncryptionList.front()
			      << "), valid modes are {zrtp, sdes, dtls-srtp, none}, ignore this setting";
			outgoingEncryptionList.pop_front();
			outgoingEncryptionList.pop_front();
		}
	}

	// Parse configuration for outgoing SRTP suite.
	// We shall have a space separated list of "suites regex suites regex ... suites regex".
	// If no regexp match, use the default configuration from rcfile.
	// Each suite is a ';' separated list of suites.
	auto outgoingSrptSuiteList = config->get<ConfigStringList>("outgoing-srtp-regex")->read();
	while (outgoingSrptSuiteList.size() >= 2) {
		// First part is a ';' separated list of suites, explode it and get each one of them.
		auto srtpSuites = explode(outgoingSrptSuiteList.front(), ';');
		std::list<linphone::SrtpSuite> srtpCryptoSuites{};
		// Turn the string list into an std::list of linphone::SrtpSuite.
		for (auto& suiteName : srtpSuites) {
			srtpCryptoSuites.push_back(string2SrtpSuite(suiteName));
		}
		if (srtpCryptoSuites.size() > 0) {
			outgoingSrptSuiteList.pop_front();
			// Get the associated regex.
			try {
				mSrtpConf.emplace_back(srtpCryptoSuites, outgoingSrptSuiteList.front());
			} catch (std::exception& e) {
				BCTBX_SLOGE << "b2bua configuration error: outgoing-srtp-regex contains invalid regex : "
				            << outgoingSrptSuiteList.front();
			}
			outgoingSrptSuiteList.pop_front();
		} else {
			BCTBX_SLOGE << "b2bua configuration error: outgoing-srtp-regex contains invalid suite: "
			            << outgoingSrptSuiteList.front() << ". Ignore this setting";
			outgoingSrptSuiteList.pop_front();
			outgoingSrptSuiteList.pop_front();
		}
	}
}

namespace {

// Statically define default configuration items.
auto& defineConfig = ConfigManager::defaultInit().emplace_back([](GenericStruct& root) {
	ConfigItemDescriptor items[] = {
	    {
	        StringList,
	        "outgoing-enc-regex",
	        "Select the call outgoing encryption mode, this is a list of regular expressions and encryption mode.\n"
	        "Valid encryption modes are: zrtp, dtls-srtp, sdes, none.\n\n"
	        "The list is formatted in the following mode:\n"
	        "mode1 regex1 mode2 regex2 ... moden regexn\n"
	        "regex use posix syntax, any invalid one is skipped\n"
	        "Each regex is applied, in the given order, on the callee sip uri(including parameters if any). First "
	        "match "
	        "found determines the encryption mode. "
	        "if no regex matches, the incoming call encryption mode is used.\n\n"
	        "Example: zrtp .*@sip\\.secure-example\\.org dtsl-srtp .*dtls@sip\\.example\\.org zrtp "
	        ".*zrtp@sip\\.example\\.org sdes .*@sip\\.example\\.org\n"
	        "In this example: the address is matched in order with\n"
	        ".*@sip\\.secure-example\\.org so any call directed to an address on domain sip.secure-example-org uses "
	        "zrtp "
	        "encryption mode\n"
	        ".*dtls@sip\\.example\\.org any call on sip.example.org to a username ending with dtls uses dtls-srtp "
	        "encryption mode\n"
	        ".*zrtp@sip\\.example\\.org any call on sip.example.org to a username ending with zrtp uses zrtp "
	        "encryption "
	        "mode\n"
	        "The previous example will fail to match if the call is directed to a specific device(having a GRUU as "
	        "callee "
	        "address)\n"
	        "To ignore sip URI parameters, use (;.*)? at the end of the regex. Example: "
	        ".*@sip\\.secure-example\\.org(;.*)?\n"
	        "Default:"
	        "Selected encryption mode(if any) is enforced and the call will fail if the callee does not support this "
	        "mode",
	        "",
	    },
	    {
	        StringList,
	        "outgoing-srtp-regex",
	        "Outgoing SRTP crypto suite in SDES encryption mode:\n"
	        "Select the call outgoing SRTP crypto suite when outgoing encryption mode is SDES, this is a list of "
	        "regular "
	        "expressions and crypto suites list.\n"
	        "Valid srtp crypto suites are :\n"
	        "AES_CM_128_HMAC_SHA1_80, AES_CM_128_HMAC_SHA1_32\n"
	        "AES_192_CM_HMAC_SHA1_80, AES_192_CM_HMAC_SHA1_32 // currently not supported\n"
	        "AES_256_CM_HMAC_SHA1_80, AES_256_CM_HMAC_SHA1_80\n"
	        "AEAD_AES_128_GCM, AEAD_AES_256_GCM\n"
	        "\n"
	        "The list is formatted in the following mode:\n"
	        "cryptoSuiteList1 regex1 cryptoSuiteList2 regex2 ... crytoSuiteListn regexn\n"
	        "with cryptoSuiteList being a ; separated list of crypto suites.\n"
	        "\n"
	        "Regex use posix syntax, any invalid one is skipped\n"
	        "Each regex is applied, in the given order, on the callee sip uri(including parameters if any). First "
	        "match "
	        "found determines the crypto suite list used.\n"
	        "\n"
	        "if no regex matches, core setting is applied\n"
	        "or default to "
	        "AES_CM_128_HMAC_SHA1_80;AES_CM_128_HMAC_SHA1_32;AES_256_CM_HMAC_SHA1_80;AES_256_CM_HMAC_SHA1_32 when no "
	        "core "
	        "setting is available\n"
	        "\n"
	        "Example:\n"
	        "AES_256_CM_HMAC_SHA1_80;AES_256_CM_HMAC_SHA1_32 .*@sip\\.secure-example\\.org AES_CM_128_HMAC_SHA1_80 "
	        ".*@sip\\.example\\.org\n"
	        "\n"
	        "In this example: the address is matched in order with\n"
	        ".*@sip\\.secure-example\\.org so any call directed to an address on domain sip.secure-example-org uses "
	        "AES_256_CM_HMAC_SHA1_80;AES_256_CM_HMAC_SHA1_32 suites (in that order)\n"
	        ".*@sip\\.example\\.org any call directed to an address on domain sip.example.org use "
	        "AES_CM_128_HMAC_SHA1_80 "
	        "suite\n"
	        "The previous example will fail to match if the call is directed to a specific device(having a GRUU as "
	        "callee "
	        "address)\n"
	        "To ignore sip URI parameters, use (;.*)? at the end of the regex. Example: "
	        ".*@sip\\.secure-example\\.org(;.*)?\n"
	        "Default:",
	        "",
	    },
	    config_item_end,
	};

	root.addChild(std::make_unique<GenericStruct>(configSection, "Encryption transcoder bridge parameters.", 0))
	    ->addChildrenValues(items);
});

} // namespace

} // namespace flexisip::b2bua::trenscrypter