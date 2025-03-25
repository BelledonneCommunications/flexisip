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

#include "b2bua-core.hh"

#include <regex>

#include "bctoolbox/logging.h"
#include "linphone/misc.h"
#include "mediastreamer2/msconference.h"

#include "exceptions/bad-configuration.hh"
#include "flexisip/flexisip-version.h"
#include "flexisip/utils/sip-uri.hh"
#include "utils/configuration/media.hh"
#include "utils/configuration/transport.hh"
#include "utils/string-utils.hh"

namespace flexisip::b2bua {

using namespace std;

shared_ptr<B2buaCore> B2buaCore::create(linphone::Factory& factory, const GenericStruct& config) {
	const auto configLinphone = factory.createConfig("");
	// Do not send information on the local conference to UACs so they do not know they are actually in a conference.
	configLinphone->setBool("misc", "hide_conferences", true);
	// Disable the possibility for UACs to subscribe to the local conference events.
	configLinphone->setBool("misc", "conference_event_log_enabled", false);
	// Remove call logs and disable db to avoid memory accumulation
	configLinphone->setInt("misc", "history_max_size", 0);
	// Do not reject INVITE requests that contain an already known Call-ID.
	configLinphone->setBool("sip", "reject_duplicated_calls", false);
	// Do not automatically accept update: we might want to update peer call before.
	configLinphone->setBool("sip", "defer_update_default", true);
	// Prevent the default log handler from being reset while LinphoneCore construction.
	configLinphone->setBool("logging", "disable_stdout", true);
	// We may want to use unsupported codecs (h264) in the conference.
	configLinphone->setBool("video", "dont_check_codecs", true);
	// Make sure the videostream can be started when using unsupported codec.
	configLinphone->setBool("video", "fallback_to_dummy_codec", true);
	// Force to use one port for each account the B2BUA sever manages (SIP-Bridge).
	const auto oneConnectionPerAccount = config.get<ConfigBoolean>("one-connection-per-account")->read();
	configLinphone->setBool("sip", "accounts_channel_isolation", oneConnectionPerAccount);
	configLinphone->setRange("sip", "refresh_window", 50, 90);
	// Instructs the core not to automatically accept REFER requests. So we can transfer them to the other call leg.
	configLinphone->setBool("sip", "auto_accept_refer", false);
	// Do not automatically terminate calls once transfer has succeeded (NOTIFY 200 OK received).
	configLinphone->setBool("sip", "terminate_call_upon_transfer_completion", false);
	// Do not automatically accept replacing calls (INVITE requests with "Replaces" header).
	configLinphone->setBool("sip", "auto_answer_replacing_calls", false);

	const auto core = factory.createCoreWithConfig(configLinphone, nullptr);
	core->setLabel("Flexisip B2BUA");
	core->enableConferenceServer(true);
	// Disable DB storage to avoid memory accumulation
	core->enableDatabase(false);
	// Maximum number of calls the server can bridge concurrently.
	// Since there are two legs per call, the core should be configured with twice the number of maximum calls.
	const auto* maxCallsParameter = config.get<ConfigInt>("max-calls");
	const auto maxCalls = maxCallsParameter->read();
	if (maxCalls <= 0) {
		throw BadConfiguration{maxCallsParameter->getCompleteName() + " must be strictly positive"};
	}
	core->setMaxCalls(maxCalls * 2);
	// Share media resources in the local conference (that is how media is transmitted to the other call leg).
	core->setMediaResourceMode(linphone::MediaResourceMode::SharedMediaResources);
	// No sound card shall be used in calls.
	core->setUseFiles(true);
	core->enableEchoCancellation(false);
	// Create default account for the server.
	const auto accountParams = core->createAccountParams();
	const auto localhostAddress = factory.createAddress("sip:localhost");
	accountParams->setIdentityAddress(factory.createAddress("sip:flexisip-b2bua@localhost"));
	accountParams->enableRegister(false);
	accountParams->setServerAddress(localhostAddress);
	const auto account = core->createAccount(accountParams);
	account->setContactAddress(localhostAddress);
	core->addAccount(account);
	core->setDefaultAccount(account);
	// Forward DTMF via out-of-band RTP ...
	core->setUseRfc2833ForDtmf(true);
	// ... or via SIP INFO if unsupported by media.
	core->setUseInfoForDtmf(true);
	// Instructs the B2BUA that the layout of the conference is already defined.
	core->setDefaultConferenceLayout(linphone::Conference::Layout::ActiveSpeaker);
	// Do not auto answer 180 on incoming calls, relay the one from the other part.
	core->enableAutoSendRinging(false);
	core->setZrtpSecretsFile(":memory:");
	// Give enough time to the outgoing call (legB) to establish while we leave the incoming one (legA) ringing.
	// See RFC 3261 §16.6 step 11 for the duration.
	core->setIncTimeout(4 * 60);

	const auto userAgent = parseUserAgentFromConfig(config.get<ConfigString>("user-agent")->read());
	core->setUserAgent(userAgent.first, userAgent.second);

	// B2BUA shall never take the initiative of accepting or starting video calls.
	// Stick to incoming call parameters for that.
	const auto videoActivationPolicy = factory.createVideoActivationPolicy();
	// Accept incoming video call so the request is forwarded to legB.
	// Acceptance from legB is checked before accepting legA.
	videoActivationPolicy->setAutomaticallyAccept(true);
	videoActivationPolicy->setAutomaticallyInitiate(false);
	core->setVideoActivationPolicy(videoActivationPolicy);

	const auto natPolicy = core->createNatPolicy();
	const auto natAddressesParameter = config.get<ConfigStringList>("nat-addresses");
	if (config.get<ConfigBoolean>("enable-ice")->read()) {
		natPolicy->enableIce(true);
		configuration_utils::configureNatAddresses(natPolicy, natAddressesParameter);
	} else if (!natAddressesParameter->read().empty()) {
		throw BadConfiguration{"NAT addresses cannot be configured if ICE is not enabled"};
	} else {
		natPolicy->enableIce(false);
	}

	core->setNatPolicy(natPolicy);

	const auto& forceCodec = [&config, &core = *core, &configLinphone](const auto& flexisipConfigName,
	                                                                   const auto& linphoneConfigName,
	                                                                   const auto& codecList, const auto& regEx) {
		const auto* configField = config.get<ConfigString>(flexisipConfigName);
		const auto& configDesc = configField->read();
		if (configDesc.empty()) return;

		smatch res{};
		if (!regex_match(configDesc, res, regEx))
			throw BadConfiguration(configField->getCompleteName() + " (" + configDesc +
			                       ") does not have the expected format.");
		const auto codec = res[1].str();
		string rate;
		if (res.size() == 3) rate = res[2];

		bool enabled = false;
		for (const auto& payloadType : (core.*codecList)()) {
			if (string_utils::iequals(payloadType->getMimeType(), codec) &&
			    (rate.empty() || to_string(payloadType->getClockRate()) == rate)) {
				payloadType->enable(true);
				enabled = true;
			} else { // disable all other codecs
				payloadType->enable(false);
				SLOGD << "Disabling " << payloadType->getDescription() << " to force " << configDesc;
			}
		}
		if (!enabled) {
			throw BadConfiguration("B2BUA core failed to enable " + configField->getCompleteName() + " with codec " +
			                       configDesc);
		}

		// We know for certain that the codec used in both legs will be the same (the one we just forced), so we can
		// enable media bridging (payload forwarding without decoding).
		configLinphone->setInt(linphoneConfigName, "conference_mode", MSConferenceModeRouterPayload);
	};

	// If an audio codec is set in configuration, enable only that one.
	// Expected config format: <codec>/<sample rate>
	forceCodec("audio-codec", "sound", &linphone::Core::getAudioPayloadTypes, regex("([a-zA-Z-0-9-]+)/([0-9]+)"));

	// If a video codec is set in config enable only that one.
	// Expected config format: <codec>
	forceCodec("video-codec", "video", &linphone::Core::getVideoPayloadTypes, regex("([a-zA-Z-0-9-]+)"));

	const auto audioPortMin = config.get<ConfigIntRange>("audio-port")->readMin();
	const auto audioPortMax = config.get<ConfigIntRange>("audio-port")->readMax();
	configuration_utils::setMediaPort(audioPortMin, audioPortMax, *core, &linphone::Core::setAudioPort,
	                                  &linphone::Core::setAudioPortRange);

	const auto videoPortMin = config.get<ConfigIntRange>("video-port")->readMin();
	const auto videoPortMax = config.get<ConfigIntRange>("video-port")->readMax();
	configuration_utils::setMediaPort(videoPortMin, videoPortMax, *core, &linphone::Core::setVideoPort,
	                                  &linphone::Core::setVideoPortRange);

	const auto* noRTPTimeoutParameter = config.get<ConfigDuration<chrono::seconds>>("no-rtp-timeout");
	const auto noRTPTimeout = noRTPTimeoutParameter->read();
	if (noRTPTimeout <= 0ms) {
		const auto parameterName = noRTPTimeoutParameter->getCompleteName();
		throw BadConfiguration{"invalid value for '" + parameterName + "', duration must be strictly positive"};
	}
	core->setNortpTimeout(static_cast<int>(chrono::duration_cast<chrono::seconds>(noRTPTimeout).count()));

	const auto* maxCallDurationParameter = config.get<ConfigDuration<chrono::seconds>>("max-call-duration");
	const auto maxCallDuration = maxCallDurationParameter->read();
	if (maxCallDuration < 0ms) {
		const auto parameterName = maxCallDurationParameter->getCompleteName();
		throw BadConfiguration{"invalid value for '" + parameterName + "', duration must be positive"};
	}
	core->setInCallTimeout(static_cast<int>(chrono::duration_cast<chrono::seconds>(maxCallDuration).count()));

	// Get transport from flexisip configuration.
	const auto b2buaTransport = factory.createTransports();
	configuration_utils::configureTransport(b2buaTransport, config.get<ConfigString>("transport"));
	core->setTransports(b2buaTransport);

	static_assert(sizeof(B2buaCore) == sizeof(decltype(*core)));
	static_assert(alignof(B2buaCore) == alignof(decltype(*core)));
	return reinterpret_pointer_cast<B2buaCore>(core);
}

pair<string, string> parseUserAgentFromConfig(const string& value) {
	smatch res{};
	if (regex_match(value, res, regex(R"(^([a-zA-Z0-9-.!%*_+`'~]+)(?:\/([a-zA-Z0-9-.!%*_+`'~]+|\{version\}))?$)"))) {
		return {res[1], res[2] == "{version}" ? FLEXISIP_GIT_VERSION : res[2].str()};
	}

	throw BadConfiguration{"user-agent parameter is ill-formed, use the following syntax: <name>[/<version>]"};
}

} // namespace flexisip::b2bua