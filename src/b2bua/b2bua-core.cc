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

#include "flexisip/flexisip-version.h"
#include "flexisip/utils/sip-uri.hh"
#include "utils/media/media.hh"

#include "exceptions/bad-configuration.hh"
#include "utils/string-utils.hh"

namespace flexisip::b2bua {

using namespace std;

shared_ptr<B2buaCore> B2buaCore::create(linphone::Factory& factory, const GenericStruct& config) {
	const auto& configLinphone = factory.createConfig("");
	configLinphone->setBool("misc", "conference_server_enabled", true);
	configLinphone->setInt("misc", "max_calls", 1000);
	// Share media resources.
	configLinphone->setInt("misc", "media_resources_mode", 1);
	configLinphone->setBool("sip", "reject_duplicated_calls", false);
	// Forward DTMF via out-of-band RTP ...
	configLinphone->setBool("sip", "use_rfc2833", true);
	// ... or via SIP INFO if unsupported by media
	configLinphone->setBool("sip", "use_info", true);
	// Do not automatically accept update: we might want to update peer call before.
	configLinphone->setBool("sip", "defer_update_default", true);
	configLinphone->setBool("misc", "conference_event_log_enabled", false);
	configLinphone->setInt("misc", "conference_layout", static_cast<int>(linphone::Conference::Layout::ActiveSpeaker));
	// Prevent the default log handler from being reset while LinphoneCore construction.
	configLinphone->setBool("logging", "disable_stdout", true);
	// We may want to use unsupported codecs (h264) in the conference.
	configLinphone->setBool("video", "dont_check_codecs", true);
	// Make sure the videostream can be started when using unsupported codec.
	configLinphone->setBool("video", "fallback_to_dummy_codec", true);
	configLinphone->setBool("sip", "accounts_channel_isolation",
	                        config.get<ConfigBoolean>("one-connection-per-account")->read());
	configLinphone->setRange("sip", "refresh_window", 50, 90);
	// Instructs the core not to automatically accept REFER requests. So we can transfer them to the other call leg.
	configLinphone->setInt("sip", "auto_accept_refer", 0);
	// Do not automatically terminate calls once transfer has succeeded (NOTIFY 200 OK received).
	configLinphone->setInt("sip", "terminate_call_upon_transfer_completion", 0);

	const auto& core = factory.createCoreWithConfig(configLinphone, nullptr);
	core->setLabel("Flexisip B2BUA");
	core->getConfig()->setString("storage", "backend", "sqlite3");
	core->getConfig()->setString("storage", "uri", ":memory:");
	// No sound card shall be used in calls.
	core->setUseFiles(true);
	core->enableEchoCancellation(false);
	// TODO: get primary contact from config, do we really need one?
	core->setPrimaryContact("sip:b2bua@localhost");
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
	auto policy = linphone::Factory::get()->createVideoActivationPolicy();
	// Accept incoming video call so the request is forwarded to legB.
	// Acceptance from legB is checked before accepting legA.
	policy->setAutomaticallyAccept(true);
	policy->setAutomaticallyInitiate(false);
	core->setVideoActivationPolicy(policy);

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
		const auto& codec = res[1].str();
		string rate;
		if (res.size() == 3) rate = res[2];

		bool enabled = false;
		for (const auto& payloadType : (core.*codecList)()) {
			if (StringUtils::iequals(payloadType->getMimeType(), codec) &&
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

	const int audioPortMin = config.get<ConfigIntRange>("audio-port")->readMin();
	const int audioPortMax = config.get<ConfigIntRange>("audio-port")->readMax();
	setMediaPort(audioPortMin, audioPortMax, *core, &linphone::Core::setAudioPort, &linphone::Core::setAudioPortRange);

	const int videoPortMin = config.get<ConfigIntRange>("video-port")->readMin();
	const int videoPortMax = config.get<ConfigIntRange>("video-port")->readMax();
	setMediaPort(videoPortMin, videoPortMax, *core, &linphone::Core::setVideoPort, &linphone::Core::setVideoPortRange);

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
	const auto& b2buaTransport = factory.createTransports();
	b2buaTransport->setUdpPort(LC_SIP_TRANSPORT_DONTBIND);
	b2buaTransport->setTcpPort(LC_SIP_TRANSPORT_DONTBIND);
	b2buaTransport->setTlsPort(LC_SIP_TRANSPORT_DONTBIND);
	b2buaTransport->setDtlsPort(LC_SIP_TRANSPORT_DONTBIND);
	if (string mTransport = config.get<ConfigString>("transport")->read(); !mTransport.empty()) {
		try {
			const auto urlTransport = SipUri{mTransport};
			const auto scheme = urlTransport.getScheme();
			const auto transportParam = urlTransport.getParam("transport");
			auto listeningPort = stoi(urlTransport.getPort(true));
			if (listeningPort == 0) {
				listeningPort = LC_SIP_TRANSPORT_RANDOM;
			}
			if (scheme == "sip") {
				if (transportParam.empty() || transportParam == "udp") {
					b2buaTransport->setUdpPort(listeningPort);
				} else if (transportParam == "tcp") {
					b2buaTransport->setTcpPort(listeningPort);
				} else if (transportParam == "tls") {
					b2buaTransport->setTlsPort(listeningPort);
				} else {
					throw sofiasip::InvalidUrlError{
					    mTransport, "invalid transport parameter value for 'sip' scheme: "s + transportParam};
				}
			} else if (scheme == "sips") {
				if (transportParam == "udp") {
					b2buaTransport->setDtlsPort(listeningPort);
				} else if (transportParam.empty() || transportParam == "tcp") {
					b2buaTransport->setTlsPort(listeningPort);
				} else {
					throw sofiasip::InvalidUrlError{
					    mTransport, "invalid transport parameter value for 'sips' scheme: "s + transportParam};
				}
			}
		} catch (const sofiasip::InvalidUrlError& e) {
			LOGF("B2bua server: Your configured b2bua transport(\"%s\") is not an URI.\n"
			     "%s",
			     mTransport.c_str(), e.what());
		}
	}

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