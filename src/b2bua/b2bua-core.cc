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

#include "utils/string-utils.hh"

namespace flexisip::b2bua {

using namespace std;

shared_ptr<B2buaCore> B2buaCore::create(linphone::Factory& factory, const GenericStruct& config) {
	const auto& configLinphone = factory.createConfig("");
	configLinphone->setBool("misc", "conference_server_enabled", true);
	configLinphone->setInt("misc", "max_calls", 1000);
	configLinphone->setInt("misc", "media_resources_mode", 1); // share media resources
	configLinphone->setBool("sip", "reject_duplicated_calls", false);
	configLinphone->setBool("sip", "use_rfc2833", true); // Forward DTMF via out-of-band RTP...
	configLinphone->setBool("sip", "use_info", true);    // ...or via SIP INFO if unsupported by media
	configLinphone->setBool("sip", "defer_update_default",
	                        true); // do not automatically accept update: we might want to update peer call before
	configLinphone->setBool("misc", "conference_event_log_enabled", false);
	configLinphone->setInt("misc", "conference_layout", static_cast<int>(linphone::Conference::Layout::ActiveSpeaker));
	// Prevent the default log handler from being reset while LinphoneCore construction.
	configLinphone->setBool("logging", "disable_stdout", true);
	// we may want to use unsupported codecs (h264) in the conference
	configLinphone->setBool("video", "dont_check_codecs", true);
	// make sure the videostream can be started when using unsupported codec
	configLinphone->setBool("video", "fallback_to_dummy_codec", true);
	configLinphone->setBool("sip", "accounts_channel_isolation",
	                        config.get<ConfigBoolean>("one-connection-per-account")->read());
	configLinphone->setRange("sip", "refresh_window", 50, 90);

	const auto& core = factory.createCoreWithConfig(configLinphone, nullptr);
	core->setLabel("Flexisip B2BUA");
	core->getConfig()->setString("storage", "backend", "sqlite3");
	core->getConfig()->setString("storage", "uri", ":memory:");
	core->setUseFiles(true); // No sound card shall be used in calls
	core->enableEchoCancellation(false);
	core->setPrimaryContact("sip:b2bua@localhost"); // TODO: get primary contact from config, do we really need one?
	core->enableAutoSendRinging(false); // Do not auto answer 180 on incoming calls, relay the one from the other part.
	core->setZrtpSecretsFile(":memory:");
	// Give enough time to the outgoing call (legB) to establish while we leave the incoming one (legA) ringing
	// See RFC 3261 §16.6 step 11 for the duration
	core->setIncTimeout(4 * 60);

	// Read user-agent parameter.
	smatch res{};
	const auto value = config.get<ConfigString>("user-agent")->read();
	if (regex_match(value, res, regex(R"(^([a-zA-Z0-9-.!%*_+`'~]+)(?:\/([a-zA-Z0-9-.!%*_+`'~]+|\{version\}))?$)"))) {
		core->setUserAgent(res[1], res[2] == "{version}" ? FLEXISIP_GIT_VERSION : res[2].str());
	} else {
		throw runtime_error("user-agent parameter is ill-formed, use the following syntax: <name>[/<version>]");
	}

	// b2bua shall never take the initiative of accepting or starting video calls
	// stick to incoming call parameters for that
	auto policy = linphone::Factory::get()->createVideoActivationPolicy();
	policy->setAutomaticallyAccept(true); // accept incoming video call so the request is forwarded to legB, acceptance
	                                      // from legB is checked before accepting legA
	policy->setAutomaticallyInitiate(false);
	core->setVideoActivationPolicy(policy);

	const auto& forceCodec = [&config, &core = *core, &configLinphone](const auto& flexisipConfigName,
	                                                                   const auto& linphoneConfigName,
	                                                                   const auto& codecList) {
		const auto* configField = config.get<ConfigString>(flexisipConfigName);
		const auto& payloadDesc = configField->read();
		if (payloadDesc.empty()) return;
		const auto& parts = StringUtils::split(string_view(payloadDesc), "/");
		if (parts.size() < 2) {
			throw runtime_error(configField->getCompleteName() +
			                    " misconfigured. Expected something like <codec>/<sample rate>, e.g. 'speex/8000'");
		}
		const auto codec = parts[0];
		const auto rate = parts[1];

		for (const auto& payloadType : (core.*codecList)()) {
			if (payloadType->getMimeType() == codec && to_string(payloadType->getClockRate()) == rate) {
				payloadType->enable(true);
			} else { // disable all other codecs
				payloadType->enable(false);
				SLOGD << "Disabling " << payloadType->getDescription() << " to force " << codec << "/" << rate;
			}
		}

		// We know for certain that the codec used in both legs will be the same (the one we just forced), so we can
		// enable media bridging (payload forwarding without decoding)
		configLinphone->setInt(linphoneConfigName, "conference_mode", MSConferenceModeRouterPayload);
	};

	// if an audio codec is set in config enable only that one
	forceCodec("audio-codec", "sound", &linphone::Core::getAudioPayloadTypes);
	// if a video codec is set in config enable only that one
	forceCodec("video-codec", "video", &linphone::Core::getVideoPayloadTypes);

	const int audioPortMin = config.get<ConfigIntRange>("audio-port")->readMin();
	const int audioPortMax = config.get<ConfigIntRange>("audio-port")->readMax();
	core->setAudioPort(audioPortMin == audioPortMax ? audioPortMin : -1);
	core->setAudioPortRange(audioPortMin, audioPortMax);

	const int videoPortMin = config.get<ConfigIntRange>("video-port")->readMin();
	const int videoPortMax = config.get<ConfigIntRange>("video-port")->readMax();
	core->setVideoPort(videoPortMin == videoPortMax ? videoPortMin : -1);
	core->setVideoPortRange(videoPortMin, videoPortMax);

	// set no-RTP timeout
	const auto noRTPTimeout = config.get<ConfigInt>("no-rtp-timeout")->read();
	if (noRTPTimeout <= 0) {
		LOGF("'%s' must be higher than 0", config.getCompleteName().c_str());
	}
	core->setNortpTimeout(noRTPTimeout);

	core->setInCallTimeout(config.get<ConfigInt>("max-call-duration")->read());

	// Get transport from flexisip configuration
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
					    mTransport, "invalid transport parameter value for 'sips' scheme: "s + transportParam};
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

} // namespace flexisip::b2bua
