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

#include "trenscrypter.hh"

#include "exceptions/bad-configuration.hh"
#include "utils/string-utils.hh"

#define FUNC_LOG_PREFIX (mLogPrefix + "::" + __func__ + "()")

namespace flexisip::b2bua::trenscrypter {
namespace {

/**
 * @brief Convert a linphone::MediaEncryption into an std::string.
 *
 * @param[in] mode the linphone::MediaEncryption to convert
 * @return the corresponding string, one of {zrtp, sdes, dtls-srtp, none}, or an error message if no match was found
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
 * @brief Convert a configuration string into a linphone::SrtpSuite.
 *
 * @param[in] configString the configuration string, one of: AES_CM_128_HMAC_SHA1_80, AES_CM_128_HMAC_SHA1_32,
 *                         AES_192_CM_HMAC_SHA1_80, AES_192_CM_HMAC_SHA1_32,
 *                         AES_256_CM_HMAC_SHA1_80, AES_256_CM_HMAC_SHA1_32
 *                         AEAD_AES_128_GCM, AEAD_AES_256_GCM
 *
 * @return the converted value, linphone::SrtpSuite::Invalid if the input string was invalid
 **/
linphone::SrtpSuite string2SrtpSuite(const std::string& configString) {
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

/**
 * @brief Convert a linphone::SrtpSuite into an std::string.
 *
 * @param[in] suite the linphone::SrtpSuite to convert
 * @return the corresponding string, or "Invalid" if not match was found
 **/
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

/**
 * @brief Convert an std::list of linphone::SrtpSuite into an std::string containing all converted linphone::SrtpSuite,
 * each one separated by ", ".
 *
 * @param[in] suites the std::list of linphone::SrtpSuite to convert
 * @return the corresponding string
 **/
std::string SrtpSuite2string(const std::list<linphone::SrtpSuite>& suites) {
	std::string ret{};
	for (const auto suite : suites) {
		ret.append(SrtpSuite2string(suite) + ", ");
	}
	return ret;
}

// Name of the corresponding section in the configuration file.
const auto configSection = b2bua::configSection + std::string{"::trenscrypter"};

} // namespace

std::variant<linphone::Reason, std::shared_ptr<const linphone::Address>>
Trenscrypter::onCallCreate(const linphone::Call& incomingCall, linphone::CallParams& outgoingCallParams) {
	const auto callee = incomingCall.getToAddress();
	const auto calleeAddressUriOnly = callee->asStringUriOnly();
	outgoingCallParams.setFromHeader(incomingCall.getRemoteAddress()->asString());
	outgoingCallParams.setAccount(mCore->getDefaultAccount());

	// Select an outgoing encryption.
	bool outgoingEncryptionSet = false;
	for (const auto& outEncSetting : mOutgoingEncryption) {
		if (std::regex_match(calleeAddressUriOnly, outEncSetting.pattern)) {
			SLOGD << FUNC_LOG_PREFIX << ": call to " << calleeAddressUriOnly << " matches regex "
			      << outEncSetting.stringPattern << ", assign encryption mode "
			      << MediaEncryption2string(outEncSetting.mode);
			outgoingCallParams.setMediaEncryption(outEncSetting.mode);
			outgoingEncryptionSet = true;
			// Stop at the first matching regexp.
			break;
		}
	}

	if (outgoingEncryptionSet == false) {
		const auto incomingEncryptionSetting = incomingCall.getParams()->getMediaEncryption();
		outgoingCallParams.setMediaEncryption(incomingEncryptionSetting);
		SLOGD << FUNC_LOG_PREFIX << ": call to " << calleeAddressUriOnly << " uses incoming encryption setting ("
		      << static_cast<int>(incomingEncryptionSetting) << ")";
	}

	// When outgoing encryption mode is sdes, select a crypto suite list setting if a pattern matches.
	if (outgoingCallParams.getMediaEncryption() == linphone::MediaEncryption::SRTP) {
		for (const auto& outSrtpSetting : mSrtpConf) {
			if (std::regex_match(calleeAddressUriOnly, outSrtpSetting.pattern)) {
				SLOGD << FUNC_LOG_PREFIX << ": call to " << calleeAddressUriOnly << " matches SRTP suite regex "
				      << outSrtpSetting.stringPattern << ", assign Srtp Suites to "
				      << SrtpSuite2string(outSrtpSetting.suites);
				outgoingCallParams.setSrtpSuites(outSrtpSetting.suites);
				// Stop at the first matching regexp
				break;
			}
		}
	}

	// Verify the selected outgoing encryption setting is available.
	if (!mCore->isMediaEncryptionSupported(outgoingCallParams.getMediaEncryption())) {
		SLOGD << FUNC_LOG_PREFIX << ": trying to place an outgoing call using "
		      << MediaEncryption2string(outgoingCallParams.getMediaEncryption())
		      << " encryption mode but it is not available";
		return linphone::Reason::NotAcceptable;
	}

	return callee;
}

std::shared_ptr<linphone::Address> Trenscrypter::onTransfer(const linphone::Call&) {
	return nullptr;
}

void Trenscrypter::init(const std::shared_ptr<B2buaCore>& core, const flexisip::ConfigManager& cfg) {
	mCore = core;
	const auto* configRoot = cfg.getRoot();
	const auto* config = configRoot->get<GenericStruct>(configSection);
	const auto* b2buaConfig = configRoot->get<GenericStruct>(b2bua::configSection);

	// Change server address of default b2bua account to force routing outgoing calls through the proxy.
	const auto factory = linphone::Factory::get();
	const auto route = factory->createAddress(b2buaConfig->get<ConfigString>("outbound-proxy")->read());
	const auto& defaultAccount = mCore->getDefaultAccount();
	if (defaultAccount) {
		auto accountParams = defaultAccount->getParams()->clone();
		accountParams->setServerAddress(route);
		accountParams->setRoutesAddresses({route});
		defaultAccount->setParams(accountParams);
	} else {
		throw FlexisipException{"failed to retrieve default b2bua account, cannot start B2BUA server"};
	}

	const auto* outgoingEncRegex = config->get<ConfigStringList>("outgoing-enc-regex");
	auto outgoingEncryptionList = outgoingEncRegex->read();
	// Parse configuration for outgoing encryption mode.
	// Parse from the list beginning, we must have a couple: {encryption_mode, regex}.
	while (outgoingEncryptionList.size() >= 2) {
		if (const auto& outgoingEncryption = string_utils::string2MediaEncryption(outgoingEncryptionList.front())) {
			outgoingEncryptionList.pop_front();
			try {
				mOutgoingEncryption.emplace_back(*outgoingEncryption, outgoingEncryptionList.front());
			} catch (const std::exception&) {
				throw BadConfiguration{outgoingEncRegex->getCompleteName() + " contains invalid regex (" +
				                       outgoingEncryptionList.front() + ")"};
			}
			outgoingEncryptionList.pop_front();
		} else {
			throw BadConfiguration{outgoingEncRegex->getCompleteName() + " contains invalid encryption mode (" +
			                       outgoingEncryptionList.front() + ")"};
		}
	}

	// Parse configuration for outgoing SRTP suite.
	// We must have a space separated list of "{suites, regex},  {suites, regex}, etc...".
	// Each suite is a ';' separated list of suites.
	const auto* outgoingSrptRegex = config->get<ConfigStringList>("outgoing-srtp-regex");
	auto outgoingSrptSuiteList = outgoingSrptRegex->read();
	while (outgoingSrptSuiteList.size() >= 2) {
		// First part is a ';' separated list of suites, explode it and retrieve each one of them.
		const auto srtpSuites = string_utils::split(outgoingSrptSuiteList.front(), ";");
		std::list<linphone::SrtpSuite> srtpCryptoSuites{};

		// Convert the string list into a list of linphone::SrtpSuite.
		for (const auto& suiteName : srtpSuites) {
			srtpCryptoSuites.push_back(string2SrtpSuite(suiteName));
		}

		if (!srtpCryptoSuites.empty()) {
			outgoingSrptSuiteList.pop_front();
			try {
				mSrtpConf.emplace_back(srtpCryptoSuites, outgoingSrptSuiteList.front());
			} catch (const std::exception&) {
				throw BadConfiguration{outgoingSrptRegex->getCompleteName() + " contains invalid regex (" +
				                       outgoingSrptSuiteList.front() + ")"};
			}
			outgoingSrptSuiteList.pop_front();
		} else {
			throw BadConfiguration{outgoingSrptRegex->getCompleteName() + " contains invalid suite (" +
			                       outgoingSrptSuiteList.front() + ")"};
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
	        "Outgoing call encryption mode.\n"
	        "This is a list of regular expressions and encryption modes.\n"
	        "Valid encryption modes are: zrtp, dtls-srtp, sdes, none.\n"
	        "The list format must be as follows:\n"
	        "mode1 regex1 mode2 regex2 ... modeN regexN\n"
	        "Regex uses posix syntax, any invalid input will throw an error and prevent the server from starting.\n"
	        "Each regex is applied on the callee SIP URI (including parameters if any) in the provided order.\n"
	        "The first match will determine the encryption mode. If no regex matches, the incoming call encryption "
	        "mode is used.\n\n"
	        "Example: zrtp .*@sip\\.secure-example\\.org dtsl-srtp .*dtls@sip\\.example\\.org zrtp "
	        ".*zrtp@sip\\.example\\.org sdes .*@sip\\.example\\.org\n"
	        "In this example: the address matches\n"
	        "	.*@sip\\.secure-example\\.org so any call to an address on the domain sip.secure-example.org "
	        "will use zrtp encryption\n"
	        "	.*dtls@sip\\.example\\.org so any call on sip.example.org to a username ending with dtls will use "
	        "dtls-srtp encryption\n"
	        "	.*zrtp@sip\\.example\\.org so any call on sip.example.org to a username ending with zrtp will use zrtp "
	        "encryption\n\n"
	        "The previous example will fail to match if the call is intended to a specific device (contains a GRUU "
	        "address as the callee address).\n"
	        "To ignore sip URI parameters, use (;.*)? at the end of the regex.\n"
	        "Example: .*@sip\\.secure-example\\.org(;.*)?\n\n"
	        "Default behavior is to apply the selected encryption mode (if any) by the caller. The call will fail if "
	        "the callee does not support this mode.\n",
	        "",
	    },
	    {
	        StringList,
	        "outgoing-srtp-regex",
	        "Outgoing call SRTP crypto suites when SDES is used as encryption.\n"
	        "This is a list of regular expressions and crypto suites.\n"
	        "Valid srtp crypto suites are:\n"
	        "AES_CM_128_HMAC_SHA1_80, AES_CM_128_HMAC_SHA1_32, AES_192_CM_HMAC_SHA1_80, AES_192_CM_HMAC_SHA1_32 "
	        "(currently not supported), AES_256_CM_HMAC_SHA1_80, AES_256_CM_HMAC_SHA1_80, AEAD_AES_128_GCM, "
	        "AEAD_AES_256_GCM\n"
	        "The list format must be as follows:\n"
	        "suite1 regex1 suite2 regex2 ... suiteN regexN\n"
	        "The parameter 'suite' is a ';' separated list of crypto suites.\n"
	        "Regex uses posix syntax, any invalid input will throw an error and prevent the server from starting.\n"
	        "Each regex is applied on the callee SIP URI (including parameters if any) in the provided order.\n"
	        "The first match will determine the crypto suite list. If no regex matches, core settings are applied or "
	        "defaults to\n"
	        "AES_CM_128_HMAC_SHA1_80;AES_CM_128_HMAC_SHA1_32;AES_256_CM_HMAC_SHA1_80;AES_256_CM_HMAC_SHA1_32 when no "
	        "core settings are available.\n\n"
	        "Example:\n"
	        "AES_256_CM_HMAC_SHA1_80;AES_256_CM_HMAC_SHA1_32 .*@sip\\.secure-example\\.org AES_CM_128_HMAC_SHA1_80 "
	        ".*@sip\\.example\\.org\n"
	        "In this example: the address matches\n"
	        "	.*@sip\\.secure-example\\.org so any call to an address on the domain sip.secure-example.org will use "
	        "AES_256_CM_HMAC_SHA1_80;AES_256_CM_HMAC_SHA1_32 (in that precise order)\n"
	        "	.*@sip\\.example\\.org so any call to an address on the domain sip.example.org will use "
	        "AES_CM_128_HMAC_SHA1_80\n"
	        "The previous example will fail to match if the call is intended to a specific device (contains a GRUU "
	        "address as the callee address).\n"
	        "To ignore SIP URI parameters, use (;.*)? at the end of the regex.\n"
	        "Example: .*@sip\\.secure-example\\.org(;.*)?\n",
	        "",
	    },
	    config_item_end,
	};

	root.addChild(
	        std::make_unique<GenericStruct>(configSection, "B2BUA server application: media encryption transcoder.", 0))
	    ->addChildrenValues(items);
});

} // namespace

} // namespace flexisip::b2bua::trenscrypter