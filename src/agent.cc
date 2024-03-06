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

#include <algorithm>
#include <memory>
#include <sstream>

#include <netdb.h>
#include <sys/socket.h>

#include <sofia-sip/sip.h>
#include <sofia-sip/su_md5.h>
#include <sofia-sip/su_tagarg.h>
#include <sofia-sip/tport.h>
#include <sofia-sip/tport_tag.h>

#include <bctoolbox/ownership.hh>

#include "flexisip/flexisip-version.h"
#include "flexisip/logmanager.hh"
#include "flexisip/module.hh"

#include "agent.hh"
#include "auth/db/authdb.hh"
#include "domain-registrations.hh"
#include "etchosts.hh"
#include "module-toolbox.hh"
#include "nat/contact-correction-strategy.hh"
#include "nat/flow-token-strategy.hh"
#include "plugin/plugin-loader.hh"
#include "utils/uri-utils.hh"

#define IPADDR_SIZE 64

using namespace std;
using namespace sofiasip;

namespace flexisip {

namespace {
void createAgentCounters(GenericStruct& root) {
	auto* globalConfig = root.get<GenericStruct>("global");
	auto createCounter = [&globalConfig](string keyprefix, string helpprefix, string value) {
		return globalConfig->createStat(keyprefix + value, helpprefix + value + ".");
	};

	{
		string key = "count-incoming-request-";
		string help = "Number of incoming requests with method name ";
		createCounter(key, help, "register");
		createCounter(key, help, "invite");
		createCounter(key, help, "ack");
		createCounter(key, help, "info");
		createCounter(key, help, "bye");
		createCounter(key, help, "cancel");
		createCounter(key, help, "message");
		createCounter(key, help, "decline");
		createCounter(key, help, "options");
		createCounter(key, help, "unknown");
	}
	{
		string key = "count-incoming-response-";
		string help = "Number of incoming response with status ";
		createCounter(key, help, "100");
		createCounter(key, help, "101");
		createCounter(key, help, "180");
		createCounter(key, help, "200");
		createCounter(key, help, "202");
		createCounter(key, help, "401");
		createCounter(key, help, "404");
		createCounter(key, help, "407");
		createCounter(key, help, "408");
		createCounter(key, help, "486");
		createCounter(key, help, "487");
		createCounter(key, help, "488");
		createCounter(key, help, "603");
		createCounter(key, help, "unknown");
	}
	{
		string key = "count-reply-";
		string help = "Number of replied ";
		createCounter(key, help, "100");
		createCounter(key, help, "101");
		createCounter(key, help, "180");
		createCounter(key, help, "200");
		createCounter(key, help, "202");
		createCounter(key, help, "401");
		createCounter(key, help, "404");
		createCounter(key, help, "407");
		createCounter(key, help, "408"); // request timeout
		createCounter(key, help, "486");
		createCounter(key, help, "487"); // Request canceled
		createCounter(key, help, "488");
		createCounter(key, help, "unknown");
	}
}
} // namespace

void Agent::onDeclare(const GenericStruct& root) {
	auto* global = root.get<GenericStruct>("global");
	{
		string key = "count-incoming-request-";
		mCountIncomingRegister = global->getStat(key + "register");
		mCountIncomingInvite = global->getStat(key + "invite");
		mCountIncomingAck = global->getStat(key + "ack");
		mCountIncomingInfo = global->getStat(key + "info");
		mCountIncomingBye = global->getStat(key + "bye");
		mCountIncomingCancel = global->getStat(key + "cancel");
		mCountIncomingMessage = global->getStat(key + "message");
		mCountIncomingDecline = global->getStat(key + "decline");
		mCountIncomingOptions = global->getStat(key + "options");
		mCountIncomingReqUnknown = global->getStat(key + "unknown");
	}
	{
		string key = "count-incoming-response-";
		mCountIncoming100 = global->getStat(key + "100");
		mCountIncoming101 = global->getStat(key + "101");
		mCountIncoming180 = global->getStat(key + "180");
		mCountIncoming200 = global->getStat(key + "200");
		mCountIncoming202 = global->getStat(key + "202");
		mCountIncoming401 = global->getStat(key + "401");
		mCountIncoming404 = global->getStat(key + "404");
		mCountIncoming407 = global->getStat(key + "407");
		mCountIncoming408 = global->getStat(key + "408");
		mCountIncoming486 = global->getStat(key + "486");
		mCountIncoming487 = global->getStat(key + "487");
		mCountIncoming488 = global->getStat(key + "488");
		mCountIncoming603 = global->getStat(key + "603");
		mCountIncomingResUnknown = global->getStat(key + "unknown");
	}
	{
		string key = "count-reply-";
		mCountReply100 = global->getStat(key + "100");
		mCountReply101 = global->getStat(key + "101");
		mCountReply180 = global->getStat(key + "180");
		mCountReply200 = global->getStat(key + "200");
		mCountReply202 = global->getStat(key + "202");
		mCountReply401 = global->getStat(key + "401");
		mCountReply404 = global->getStat(key + "404");
		mCountReply407 = global->getStat(key + "407");
		mCountReply408 = global->getStat(key + "408"); // request timeout
		mCountReply486 = global->getStat(key + "486");
		mCountReply487 = global->getStat(key + "487"); // Request canceled
		mCountReply488 = global->getStat(key + "488");
		mCountReplyResUnknown = global->getStat(key + "unknown");
	}

	string uniqueId = global->get<ConfigString>("unique-id")->read();
	if (!uniqueId.empty()) {
		if (uniqueId.length() == 16) {
			transform(uniqueId.begin(), uniqueId.end(), uniqueId.begin(), ::tolower);
			if (find_if(uniqueId.begin(), uniqueId.end(), [](char c) -> bool { return !::isxdigit(c); }) ==
			    uniqueId.end()) {
				mUniqueId = uniqueId;
			} else {
				SLOGE << "'uniqueId' parameter must hold an hexadecimal number";
			}
		} else {
			SLOGE << "'uniqueId' parameter must have 16 characters. Skipping it";
		}
	}

	const auto rtpBindAddress = global->get<ConfigStringList>("rtp-bind-address")->read();
	if (rtpBindAddress.size() != 2) {
		LOGA("Config entry [rtp-bind-address] must have 2 and only 2 ip addresses, IPV4 first, IPV6 second");
	}
	mRtpBindIp = rtpBindAddress.front();
	mRtpBindIp6 = rtpBindAddress.back();
}

static string absolutePath(const string& currdir, const string& file) {
	if (file.empty()) return file;
	if (file.at(0) == '/') return file;
	return currdir + "/" + file;
}

void Agent::checkAllowedParams(const url_t* uri) {
	sofiasip::Home home;
	if (!uri->url_params) return;
	char* params = su_strdup(home.home(), uri->url_params);
	/*remove all the allowed params and see if something else is remaning at the end*/
	params = url_strip_param_string(params, "tls-certificates-dir");
	params = url_strip_param_string(params, "tls-certificates-file");
	params = url_strip_param_string(params, "tls-certificates-private-key");
	params = url_strip_param_string(params, "tls-certificates-ca-file");
	params = url_strip_param_string(params, "require-peer-certificate");
	params = url_strip_param_string(params, "maddr");
	params = url_strip_param_string(params, "tls-verify-incoming");
	params = url_strip_param_string(params, "tls-allow-missing-client-certificate");
	params = url_strip_param_string(params, "tls-verify-outgoing");
	// make sure that there is no misstyped params in the url:
	if (params && strlen(params) > 0) {
		LOGF("Bad parameters '%s' given in transports definition.", params);
	}
}

void Agent::initializePreferredRoute() {
	// Adding internal transport to transport in "cluster" case
	const auto* cluster = mConfigManager->getRoot()->get<GenericStruct>("cluster");
	if (cluster->get<ConfigBoolean>("enabled")->read()) {
		const auto* internalTransportParam = cluster->get<ConfigString>("internal-transport");
		auto internalTransport = internalTransportParam->read();

		auto pos = internalTransport.find("\%auto");
		if (pos != string::npos) {
			SLOGW << "using '\%auto' token in '" << internalTransportParam->getCompleteName() << "' is deprecated";
			char result[NI_MAXHOST] = {0};
			// Currently only IpV4
			if (bctbx_get_local_ip_for(AF_INET, nullptr, 0, result, sizeof(result)) != 0) {
				LOGF("%%auto couldn't be resolved");
			}
			internalTransport.replace(pos, sizeof("\%auto") - 1, result);
		}

		try {
			SipUri url{internalTransport};
			mPreferredRouteV4 = url_hdup(&mHome, url.get());
			LOGD("Agent's preferred IP for internal routing find: v4: %s", internalTransport.c_str());
		} catch (const sofiasip::InvalidUrlError& e) {
			LOGF("invalid URI in '%s': %s", internalTransportParam->getCompleteName().c_str(), e.getReason().c_str());
		}
	}
}

void Agent::loadModules() {
	for (const auto& module : mModules) {
		// Check in all cases, even if not enabled,
		// to allow safe dynamic activation of the module
		module->checkConfig();
		module->load();
	}
	if (mDrm) mDrm->load(mPassphrase);
	mPassphrase = "";
}

#if ENABLE_MDNS
static void mDnsRegisterCallback(void* data, int error) {
	if (error != 0) LOGE("Error while registering a mDNS service");
}
#endif

void Agent::startMdns() {
#if ENABLE_MDNS
	/* Get Informations about mDNS register */
	GenericStruct* mdns = mConfigManager->getRoot()->get<GenericStruct>("mdns-register");
	bool mdnsEnabled = mdns->get<ConfigBoolean>("enabled")->read();
	if (mdnsEnabled) {
		if (!belle_sip_mdns_register_available()) LOGF("Belle-sip does not have mDNS activated!");

		string mdnsDomain =
		    mConfigManager->getRoot()->get<GenericStruct>("cluster")->get<ConfigString>("cluster-domain")->read();
		int mdnsPrioMin = mdns->get<ConfigIntRange>("mdns-priority")->readMin();
		int mdnsPrioMax = mdns->get<ConfigIntRange>("mdns-priority")->readMax();
		int mdnsWeight = mdns->get<ConfigInt>("mdns-weight")->read();
		int mdnsTtl = mdns->get<ConfigDuration<chrono::milliseconds>>("mdns-ttl")->read().count();

		/* Get hostname of the machine */
		char hostname[HOST_NAME_MAX];
		int err = gethostname(hostname, sizeof(hostname));
		if (err != 0) {
			LOGE("Cannot retrieve machine hostname.");
		} else {
			int prio;
			if (mdnsPrioMin == mdnsPrioMax) {
				prio = mdnsPrioMin;
			} else {
				/* Randomize the priority */
				prio = belle_sip_random() % (mdnsPrioMax - mdnsPrioMin + 1) + mdnsPrioMin;
				LOGD("Multicast DNS services will be started with priority: %d", prio);
			}

			LOGD("Registering multicast DNS services.");
			for (tport_t* tport = tport_primaries(nta_agent_tports(mAgent)); tport != NULL; tport = tport_next(tport)) {
				char registerName[512];
				const tp_name_t* name = tport_name(tport);
				snprintf(registerName, sizeof(registerName), "%s_%s_%s", hostname, name->tpn_proto, name->tpn_port);

				belle_sip_mdns_register_t* reg = belle_sip_mdns_register(
				    "sip", name->tpn_proto, mdnsDomain.c_str(), registerName, atoi(name->tpn_port), prio, mdnsWeight,
				    mdnsTtl, mDnsRegisterCallback, NULL);
				mMdnsRegisterList.push_back(reg);
			}
		}
	}
#endif
}

static void timerfunc([[maybe_unused]] su_root_magic_t* magic, [[maybe_unused]] su_timer_t* t, Agent* a) {
	a->idle();
}

void Agent::start(const string& transport_override, const string& passphrase) {
	char cCurrDir[FILENAME_MAX];
	if (!getcwd(cCurrDir, sizeof(cCurrDir))) {
		LOGA("Could not get current file path");
	}
	string currDir = cCurrDir;

	GenericStruct* global = mConfigManager->getRoot()->get<GenericStruct>("global");
	list<string> transports = global->get<ConfigStringList>("transports")->read();
	string ciphers = global->get<ConfigString>("tls-ciphers")->read();
	// sofia needs a value in millseconds.
	auto tports_idle_timeout = global->get<ConfigDuration<chrono::seconds>>("idle-timeout")->read().count();
	bool globalVerifyIn = global->get<ConfigBoolean>("require-peer-certificate")->read();
	auto t1x64 = global->get<ConfigDuration<chrono::milliseconds>>("transaction-timeout")->read().count();
	int udpmtu = global->get<ConfigInt>("udp-mtu")->read();
	auto incompleteIncomingMessageTimeout = 600L * 1000L; /*milliseconds*/
	auto keepAliveInterval = global->get<ConfigDuration<chrono::seconds>>("keepalive-interval")->read().count();
	unsigned int queueSize = (unsigned int)global->get<ConfigInt>("tport-message-queue-size")->read();

	mProxyToProxyKeepAliveInterval =
	    global->get<ConfigDuration<chrono::seconds>>("proxy-to-proxy-keepalive-interval")->read().count();

	const auto* natHelperConfig = mConfigManager->getRoot()->get<GenericStruct>("module::NatHelper");
	const auto& strategy = natHelperConfig->get<ConfigString>("nat-traversal-strategy")->read();
	if (strategy == "contact-correction") {
		const auto& contactCorrectionParameter = natHelperConfig->get<ConfigString>("contact-correction-param")->read();
		mNatTraversalStrategy = make_shared<ContactCorrectionStrategy>(this, contactCorrectionParameter);
	} else if (strategy == "flow-token") {
		const auto forceFlowTokenExpr = natHelperConfig->get<ConfigBooleanExpression>("force-flow-token")->read();
		mNatTraversalStrategy = make_shared<FlowTokenStrategy>(this, forceFlowTokenExpr, FLOW_TOKEN_HASH_KEY_FILE_PATH);
	} else {
		throw runtime_error("unknown value for \"nat-traversal-strategy\" (" + strategy + ")");
	}

	mTimer = su_timer_create(mRoot->getTask(), 5000);
	su_timer_set_for_ever(mTimer, reinterpret_cast<su_timer_f>(timerfunc), this);

	nta_agent_set_params(mAgent, NTATAG_SIP_T1X64(t1x64), NTATAG_RPORT(1), NTATAG_TCP_RPORT(1),
	                     NTATAG_TLS_RPORT(1),    // use rport in vias added to outgoing requests for all protocols
	                     NTATAG_SERVER_RPORT(2), // always add a rport parameter even if the request doesn't have it*/
	                     NTATAG_UDP_MTU(udpmtu), TAG_END());

	const auto mainTlsConfigInfo = getTlsConfigInfo(global);

	if (!transport_override.empty()) {
		transports = ConfigStringList::parse(transport_override);
	}

	for (const auto& uri : transports) {
		Url url{uri};
		int err;
		su_home_t home;
		su_home_init(&home);
		LOGD("Enabling transport %s", uri.c_str());
		if (uri.find("sips") == 0) {
			unsigned int tls_policy = 0;

			if (globalVerifyIn) tls_policy |= TPTLS_VERIFY_INCOMING;

			if (url.getBoolParam("tls-verify-incoming", false) || url.getBoolParam("require-peer-certificate", false)) {
				tls_policy |= TPTLS_VERIFY_INCOMING;
			}

			if (url.getBoolParam("tls-allow-missing-client-certificate", false)) {
				tls_policy |= TPTLS_VERIFY_ALLOW_MISSING_CERT_IN;
			}

			if (url.getBoolParam("tls-verify-outgoing", true)) {
				tls_policy |= TPTLS_VERIFY_OUTGOING | TPTLS_VERIFY_SUBJECTS_OUT;
			}

			checkAllowedParams(url.get());
			mPassphrase = passphrase;

			auto uriTlsConfigInfo = url.getTlsConfigInfo();
			auto finalTlsConfigInfo =
			    uriTlsConfigInfo.mode != TlsMode::NONE ? std::move(uriTlsConfigInfo) : mainTlsConfigInfo;
			if (finalTlsConfigInfo.mode == TlsMode::OLD) {
				finalTlsConfigInfo.certifDir = absolutePath(currDir, finalTlsConfigInfo.certifDir);

				err = nta_agent_add_tport(
				    mAgent, (const url_string_t*)url.get(), TPTAG_CERTIFICATE(finalTlsConfigInfo.certifDir.c_str()),
				    TPTAG_TLS_PASSPHRASE(mPassphrase.c_str()), TPTAG_TLS_CIPHERS(ciphers.c_str()),
				    TPTAG_TLS_VERIFY_POLICY(tls_policy), TPTAG_IDLE(tports_idle_timeout),
				    TPTAG_TIMEOUT(incompleteIncomingMessageTimeout), TPTAG_KEEPALIVE(keepAliveInterval),
				    TPTAG_SDWN_ERROR(1), TPTAG_QUEUESIZE(queueSize), TAG_END());
			} else {
				finalTlsConfigInfo.certifFile = absolutePath(currDir, finalTlsConfigInfo.certifFile);
				finalTlsConfigInfo.certifPrivateKey = absolutePath(currDir, finalTlsConfigInfo.certifPrivateKey);
				finalTlsConfigInfo.certifCaFile = absolutePath(currDir, finalTlsConfigInfo.certifCaFile);

				err = nta_agent_add_tport(mAgent, (const url_string_t*)url.get(),
				                          TPTAG_CERTIFICATE_FILE(finalTlsConfigInfo.certifFile.c_str()),
				                          TPTAG_CERTIFICATE_PRIVATE_KEY(finalTlsConfigInfo.certifPrivateKey.c_str()),
				                          TPTAG_CERTIFICATE_CA_FILE(finalTlsConfigInfo.certifCaFile.c_str()),
				                          TPTAG_TLS_PASSPHRASE(mPassphrase.c_str()), TPTAG_TLS_CIPHERS(ciphers.c_str()),
				                          TPTAG_TLS_VERIFY_POLICY(tls_policy), TPTAG_IDLE(tports_idle_timeout),
				                          TPTAG_TIMEOUT(incompleteIncomingMessageTimeout),
				                          TPTAG_KEEPALIVE(keepAliveInterval), TPTAG_SDWN_ERROR(1),
				                          TPTAG_QUEUESIZE(queueSize), TAG_END());
			}
		} else {
			err =
			    nta_agent_add_tport(mAgent, (const url_string_t*)url.get(), TPTAG_IDLE(tports_idle_timeout),
			                        TPTAG_TIMEOUT(incompleteIncomingMessageTimeout), TPTAG_KEEPALIVE(keepAliveInterval),
			                        TPTAG_SDWN_ERROR(1), TPTAG_QUEUESIZE(queueSize), TAG_END());
		}
		if (err == -1) {
			const auto transport = url.getParam("transport");
			if (strcasecmp(transport.c_str(), "tls") == 0) {
				LOGF("Specifying an URI with transport=tls is not understood in flexisip configuration. Use 'sips' uri "
				     "scheme instead.");
			}
			LOGF("Could not enable transport %s: %s", uri.c_str(), strerror(errno));
		}
		su_home_deinit(&home);
	}

	/* Setup the internal transport*/
	if (mPreferredRouteV4 != nullptr) {
		if (nta_agent_add_tport(mAgent, (const url_string_t*)mPreferredRouteV4, TPTAG_IDLE(tports_idle_timeout),
		                        TPTAG_TIMEOUT(incompleteIncomingMessageTimeout), TPTAG_IDENT(sInternalTransportIdent),
		                        TPTAG_KEEPALIVE(keepAliveInterval), TPTAG_QUEUESIZE(queueSize), TPTAG_SDWN_ERROR(1),
		                        TAG_END()) == -1) {
			char prefRouteV4[266];
			url_e(prefRouteV4, sizeof(prefRouteV4), mPreferredRouteV4);
			LOGF("Could not enable internal transport %s: %s", prefRouteV4, strerror(errno));
		}
		tp_name_t tn = {0};
		tn.tpn_ident = (char*)sInternalTransportIdent;
		mInternalTport = tport_by_name(nta_agent_tports(mAgent), &tn);
		if (!mInternalTport) {
			LOGF("Could not obtain pointer to internal tport. Bug somewhere.");
		}
	}

	tport_t* primaries = tport_primaries(nta_agent_tports(mAgent));
	if (primaries == NULL) LOGF("No sip transport defined.");

	startMdns();

	/*
	 * Iterate on all the transports enabled or implicitely configured (case of 'sip:*') in order to guess useful
	 *information from an empiric manner:
	 * mPublicIpV4/mPublicIpV6 is the public IP of the proxy, assuming there's only one.
	 * mPreferredRouteV4/mPreferredRouteV6 is a private interface of the proxy that can be used for inter flexisip nodes
	 *SIP communication.
	 * mRtpBindIp/mRtpBindIp6 is a local address to bind rtp ports. It is taken from maddr parameter of the public
	 *transport of the proxy.
	 * This algo is really empiric and aims at satisfy most common needs but cannot satisfy all of them.
	 **/
	su_md5_t ctx;
	su_md5_init(&ctx);

	LOGD("Agent 's primaries are:");
	for (tport_t* tport = primaries; tport != NULL; tport = tport_next(tport)) {
		auto name = tport_name(tport);
		char url[512];
		snprintf(url, sizeof(url), "sip:%s:%s;transport=%s;maddr=%s", name->tpn_canon, name->tpn_port, name->tpn_proto,
		         name->tpn_host);
		su_md5_strupdate(&ctx, url);
		LOGD("\t%s", url);
		auto isIpv6 = strchr(name->tpn_host, ':') != nullptr;

		// The public and bind values are different
		// which is the case of transport with sip:public;maddr=bind
		// where public is the hostname or ip address publicly announced
		// and maddr the real ip we listen on.
		// Useful for a scenario where the flexisip is behind a router.
		auto formatedHost = ModuleToolbox::getHost(name->tpn_canon);
		if (isIpv6 && mPublicIpV6.empty()) {
			mPublicIpV6 = formatedHost;
		} else if (!isIpv6 && mPublicIpV4.empty()) {
			mPublicIpV4 = formatedHost;
		}

		if (mNodeUri == nullptr) {
			mNodeUri = urlFromTportName(&mHome, name);
			auto clusterDomain =
			    mConfigManager->getRoot()->get<GenericStruct>("cluster")->get<ConfigString>("cluster-domain")->read();
			if (!clusterDomain.empty()) {
				auto tmp_name = *name;
				tmp_name.tpn_canon = clusterDomain.c_str();
				tmp_name.tpn_port = nullptr;
				mClusterUri = urlFromTportName(&mHome, &tmp_name);
			}
		}

		mTransports.emplace_back(formatedHost, name->tpn_port, name->tpn_proto,
		                         computeResolvedPublicIp(formatedHost, AF_INET),
		                         computeResolvedPublicIp(formatedHost, AF_INET6), name->tpn_host);
	}

	bool clusterModeEnabled =
	    mConfigManager->getRoot()->get<GenericStruct>("cluster")->get<ConfigBoolean>("enabled")->read();
	mDefaultUri = (clusterModeEnabled && mClusterUri) ? mClusterUri : mNodeUri;

	mPublicResolvedIpV4 = computeResolvedPublicIp(mPublicIpV4, AF_INET);
	if (mPublicResolvedIpV4.empty()) {
		mPublicResolvedIpV4 = mRtpBindIp;
	}

	if (!mPublicIpV6.empty()) {
		mPublicResolvedIpV6 = computeResolvedPublicIp(mPublicIpV6, AF_INET6);
	} else {
		/*attempt to resolve as ipv6, in case it is a hostname*/
		mPublicResolvedIpV6 = computeResolvedPublicIp(mPublicIpV4, AF_INET6);
		if (!mPublicResolvedIpV6.empty()) {
			mPublicIpV6 = mPublicIpV4;
		}
	}
	if (mPublicResolvedIpV6.empty()) {
		LOGW("This flexisip instance has no public IPv6 address detected.");
	}

	// Generate the unique ID if it has not been specified in Flexisip's settings
	if (mUniqueId.empty()) {
		char digest[(SU_MD5_DIGEST_SIZE * 2) + 1];
		su_md5_hexdigest(&ctx, digest);
		su_md5_deinit(&ctx);
		digest[16] = '\0'; // keep half of the digest, should be enough
		// compute a network wide unique id
		mUniqueId = digest;
		SLOGD << "Generating the unique ID: " << mUniqueId;
	} else {
		SLOGD << "Static unique ID: " << mUniqueId;
	}

	if (mPublicResolvedIpV6.empty() && mPublicResolvedIpV4.empty()) {
		LOGF("The default public address of the server could not be resolved (%s / %s). Cannot continue.",
		     mPublicIpV4.c_str(), mPublicIpV6.c_str());
	}

	LOGD("Agent public hostname/ip: v4:%s v6:%s", mPublicIpV4.c_str(), mPublicIpV6.c_str());
	LOGD("Agent public resolved hostname/ip: v4:%s v6:%s", mPublicResolvedIpV4.c_str(), mPublicResolvedIpV6.c_str());
	LOGD("Agent's _default_ RTP bind ip address: v4:%s v6:%s", mRtpBindIp.c_str(), mRtpBindIp6.c_str());

	startLogWriter();

	loadModules();
}

TlsConfigInfo Agent::getTlsConfigInfo(const GenericStruct* global) {
	TlsConfigInfo tlsConfigInfoFromConf{};
	tlsConfigInfoFromConf.certifDir = global->get<ConfigString>("tls-certificates-dir")->read();
	tlsConfigInfoFromConf.certifFile = global->get<ConfigString>("tls-certificates-file")->read();
	tlsConfigInfoFromConf.certifPrivateKey = global->get<ConfigString>("tls-certificates-private-key")->read();
	tlsConfigInfoFromConf.certifCaFile = global->get<ConfigString>("tls-certificates-ca-file")->read();
	if (tlsConfigInfoFromConf.certifFile.empty() ^ tlsConfigInfoFromConf.certifPrivateKey.empty()) {
		LOGA("If you specified tls-certificates-file you MUST specify tls-certificates-private-key too and vice versa");
	}
	if (!tlsConfigInfoFromConf.certifFile.empty()) {
		tlsConfigInfoFromConf.mode = TlsMode::NEW;
		SLOGD << "Main tls certs file [" << tlsConfigInfoFromConf.certifFile << "], main private key file ["
		      << tlsConfigInfoFromConf.certifPrivateKey << "], main CA file [" << tlsConfigInfoFromConf.certifCaFile
		      << "].";

	} else {
		tlsConfigInfoFromConf.mode = TlsMode::OLD;
		SLOGD << "Main tls certs dir : " << tlsConfigInfoFromConf.certifDir
		      << " . Be careful you are using a deprecated config tls-certificates-dir.";
	}

	return tlsConfigInfoFromConf;
}

void Agent::addConfigSections(ConfigManager& cfg) {
	// Modules are statically register into the ModuleInfoManager singleton.
	// Ask the ModuleInfoManager to build a valid module info chain, according to module's placement hints.
	list<ModuleInfoBase*> moduleInfoChain = ModuleInfoManager::get()->buildModuleChain();

	// Add modules config section.
	GenericStruct* cr = cfg.getRoot();
	for (ModuleInfoBase* moduleInfo : moduleInfoChain) {
		moduleInfo->declareConfig(*cr);
	}
	createAgentCounters(*cr);
	DomainRegistrationManager::declareConfig(*cr);
}

void Agent::addPluginsConfigSections(ConfigManager& cfg) {
	// Load plugins .so files. They will automatically register into the ModuleInfoManager singleton.
	GenericStruct* cr = cfg.getRoot();
	GenericStruct* global = cr->get<GenericStruct>("global");
	const string& pluginDir = global->get<ConfigString>("plugins-dir")->read();
	for (const string& pluginName : global->get<ConfigStringList>("plugins")->read()) {
		SLOGI << "Loading [" << pluginName << "] plugin...";
		PluginLoader pluginLoader(pluginDir + "/lib" + pluginName + ".so");
		const ModuleInfoBase* moduleInfo = pluginLoader.getModuleInfo();
		if (!moduleInfo) {
			LOGF("Unable to load plugin [%s]: %s", pluginName.c_str(), pluginLoader.getError().c_str());
			return;
		}
		moduleInfo->declareConfig(*cr);
	}
}
// -----------------------------------------------------------------------------

Agent::Agent(const std::shared_ptr<sofiasip::SuRoot>& root,
             const std::shared_ptr<ConfigManager>& cm,
             const std::shared_ptr<AuthDbBackendOwner>& authDbOwner,
             const std::shared_ptr<RegistrarDb>& registrarDb)
    : mRoot{root}, mConfigManager{cm}, mAuthDbOwner{authDbOwner}, mRegistrarDb{registrarDb} {
	LOGT("New Agent[%p]", this);
	mHttpEngine = nth_engine_create(root->getCPtr(), NTHTAG_ERROR_MSG(0), TAG_END());
	GenericStruct* cr = cm->getRoot();

	EtcHostsResolver::get();

	// Ask the ModuleInfoManager to build a valid module info chain, according to module's placement hints.
	list<ModuleInfoBase*> moduleInfoChain = ModuleInfoManager::get()->buildModuleChain();

	// Instanciate the modules.
	for (ModuleInfoBase* moduleInfo : moduleInfoChain) {
		SLOGI << "Creating module instance of "
		      << "[" << moduleInfo->getModuleName() << "].";
		mModules.push_back(moduleInfo->create(this));
	}

	mServerString = "Flexisip/" FLEXISIP_GIT_VERSION " (sofia-sip-nta/" NTA_VERSION ")";

	onDeclare(*cr);

	struct ifaddrs* net_addrs;
	int err = getifaddrs(&net_addrs);
	if (err == 0) {
		struct ifaddrs* ifa = net_addrs;
		while (ifa != NULL) {
			if (ifa->ifa_netmask != NULL && ifa->ifa_addr != NULL) {
				LOGD("New network: %s", Network::print(ifa).c_str());
				mNetworks.push_front(Network(ifa));
			}
			ifa = ifa->ifa_next;
		}
		freeifaddrs(net_addrs);
	} else {
		LOGE("Can't find interface addresses: %s", strerror(err));
	}

	/**
	 * We use NTATAG_CANCEL_487(0) so sofia-sip don't return a 487 responses to incoming CANCEL request automatically.
	 * In fact CANCEL request will be sent using nta_outgoing_tcancel with NTATAG_CANCEL_2543(1) leading to 487
	 * responses on each cancelled branches.
	 */
	mAgent = nta_agent_create(root->getCPtr(), (url_string_t*)-1, &Agent::messageCallback, (nta_agent_magic_t*)this,
	                          NTATAG_CANCEL_487(0), TAG_END());
	su_home_init(&mHome);
	mPreferredRouteV4 = nullptr;
	mPreferredRouteV6 = nullptr;
	mDrm = new DomainRegistrationManager(this);
	mProxyToProxyKeepAliveInterval = 0;

	mConfigManager->getGlobal()->get<ConfigStringList>("aliases")->setConfigListener(this);
	mAliases = mConfigManager->getGlobal()->get<ConfigStringList>("aliases")->read();
	LOGD("List of host aliases:");
	for (const auto& alias : mAliases) {
		LOGD("%s", alias.c_str());
	}

	mUseRfc2543RecordRoute = mConfigManager->getGlobal()->get<ConfigBoolean>("use-rfc2543-record-route")->read();

	mRegistrarDb->setLatestExpirePredicate([weakAg = weak_from_this()](const url_t* url) {
		auto agent = weakAg.lock();
		if (agent == nullptr) return false;
		return agent->isUs(url);
	});

	initializePreferredRoute();
}

Agent::~Agent() {
	LOGT("Destroy Agent[%p]", this);
#if ENABLE_MDNS
	for (belle_sip_mdns_register_t* reg : mMdnsRegisterList) {
		belle_sip_mdns_unregister(reg);
	}
#endif

	mTerminating = true;

	// We need to clear modules before calling destroy on sofia agent.
	mModules.clear();

	if (mTimer) su_timer_destroy(mTimer);
	if (mDrm) delete mDrm;
	if (mAgent) nta_agent_destroy(mAgent);
	if (mHttpEngine) nth_engine_destroy(mHttpEngine);
	su_home_deinit(&mHome);
}

const char* Agent::getServerString() const {
	return mServerString.c_str();
}

string Agent::getPreferredRoute() const {
	if (!mPreferredRouteV4) return string();

	char prefUrl[266];
	url_e(prefUrl, sizeof(prefUrl), mPreferredRouteV4);
	return string(prefUrl);
}

bool Agent::doOnConfigStateChanged(const ConfigValue& conf, ConfigState state) {
	LOGD("Configuration of agent changed for key %s to %s", conf.getName().c_str(), conf.get().c_str());

	if (conf.getName() == "aliases" && state == ConfigState::Committed) {
		mAliases = ((ConfigStringList*)(&conf))->read();
		LOGD("Global aliases updated");
	}
	return true;
}

void Agent::unloadConfig() {
	for (const auto& module : mModules) {
		module->unload();
	}
}

string Agent::computeResolvedPublicIp(const string& host, int family) const {
	int err;
	struct addrinfo hints;
	string dest;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = family;
	struct addrinfo* result;

	dest.clear();
	if (host.empty()) return dest;
	dest = (host[0] == '[') ? host.substr(1, host.size() - 2) : host;

	err = getaddrinfo(dest.c_str(), NULL, &hints, &result);
	if (err == 0) {
		char ip[NI_MAXHOST];
		err = getnameinfo(result->ai_addr, result->ai_addrlen, ip, sizeof(ip), NULL, 0, NI_NUMERICHOST);
		freeaddrinfo(result);
		if (err == 0) {
			return ip;
		} else {
			LOGE("getnameinfo error: %s for host [%s]", gai_strerror(err), host.c_str());
		}
	} else {
		if (!((UriUtils::isIpv4Address(dest) && family != AF_INET) ||
		      (UriUtils::isIpv6Address(dest) && family != AF_INET6))) {
			LOGW("getaddrinfo error: %s for host [%s] and family=[%i]", gai_strerror(err), host.c_str(), family);
		}
	}
	return "";
}

pair<string, string> Agent::getPreferredIp(const string& destination) const {
	int err;
	struct addrinfo hints;
	string dest = (destination[0] == '[') ? destination.substr(1, destination.size() - 2) : destination;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_flags = AI_NUMERICHOST;
	bool isIpv6;

	struct addrinfo* result;
	err = getaddrinfo(dest.c_str(), NULL, &hints, &result);
	if (err == 0) {
		for (auto it = mNetworks.begin(); it != mNetworks.end(); ++it) {
			if (it->isInNetwork(result->ai_addr)) {
				freeaddrinfo(result);
				return make_pair(it->getIP(), it->getIP());
			}
		}
		freeaddrinfo(result);
	} else {
		LOGE("getPreferredIp() getaddrinfo() error while resolving '%s': %s", dest.c_str(), gai_strerror(err));
	}
	isIpv6 = strchr(dest.c_str(), ':') != NULL;
	if (getResolvedPublicIp(true).empty()) {
		// If no IPv6 available, fallback to ipv4 and relay on NAT64.
		return make_pair(getResolvedPublicIp(), getRtpBindIp());
	}
	return isIpv6 ? make_pair(getResolvedPublicIp(true), getRtpBindIp(true))
	              : make_pair(getResolvedPublicIp(), getRtpBindIp());
}

Agent::Network::Network(const Network& net) : mIP(net.mIP) {
	memcpy(&mPrefix, &net.mPrefix, sizeof(mPrefix));
	memcpy(&mMask, &net.mMask, sizeof(mMask));
}

Agent::Network::Network(const struct ifaddrs* ifaddr) {
	int err = 0;
	char ipAddress[IPADDR_SIZE];
	memset(&mPrefix, 0, sizeof(mPrefix));
	memset(&mMask, 0, sizeof(mMask));
	if (ifaddr->ifa_addr->sa_family == AF_INET) {
		typedef struct sockaddr_in sockt;
		sockt* if_addr = (sockt*)ifaddr->ifa_addr;
		sockt* if_mask = (sockt*)ifaddr->ifa_netmask;
		sockt* prefix = (sockt*)&mPrefix;
		sockt* mask = (sockt*)&mMask;

		mPrefix.ss_family = AF_INET;
		prefix->sin_addr.s_addr = if_addr->sin_addr.s_addr & if_mask->sin_addr.s_addr;
		mask->sin_addr.s_addr = if_mask->sin_addr.s_addr; // 1 chunk of 32 bits
		err = getnameinfo(ifaddr->ifa_addr, sizeof(sockt), ipAddress, IPADDR_SIZE, NULL, 0, NI_NUMERICHOST);
	} else if (ifaddr->ifa_addr->sa_family == AF_INET6) {
		typedef struct sockaddr_in6 sockt;
		sockt* if_addr = (sockt*)ifaddr->ifa_addr;
		sockt* if_mask = (sockt*)ifaddr->ifa_netmask;
		sockt* prefix = (sockt*)&mPrefix;
		sockt* mask = (sockt*)&mMask;

		mPrefix.ss_family = AF_INET6;
		for (int i = 0; i < 8; ++i) { // 8 chunks of 8 bits
			prefix->sin6_addr.s6_addr[i] = if_addr->sin6_addr.s6_addr[i] & if_mask->sin6_addr.s6_addr[i];
			mask->sin6_addr.s6_addr[i] = if_mask->sin6_addr.s6_addr[i];
		}
		err = getnameinfo(ifaddr->ifa_addr, sizeof(sockt), ipAddress, IPADDR_SIZE, NULL, 0, NI_NUMERICHOST);
	}
	if (err == 0) {
		mIP = string(ipAddress);
	} else {
		LOGE("getnameinfo error: %s", strerror(errno));
	}
}

const string Agent::Network::getIP() const {
	return mIP;
}

bool Agent::Network::isInNetwork(const struct sockaddr* addr) const {
	if (addr->sa_family != mPrefix.ss_family) {
		return false;
	}

	if (addr->sa_family == AF_INET) {
		typedef struct sockaddr_in sockt;
		sockt* prefix = (sockt*)&mPrefix;
		sockt* mask = (sockt*)&mMask;
		sockt* if_addr = (sockt*)addr;

		uint32_t test = if_addr->sin_addr.s_addr & mask->sin_addr.s_addr;
		return test == prefix->sin_addr.s_addr;
	} else if (addr->sa_family == AF_INET6) {
		typedef struct sockaddr_in6 sockt;
		sockt* prefix = (sockt*)&mPrefix;
		sockt* mask = (sockt*)&mMask;
		sockt* if_addr = (sockt*)addr;

		for (int i = 0; i < 8; ++i) {
			uint8_t test = if_addr->sin6_addr.s6_addr[i] & mask->sin6_addr.s6_addr[i];
			if (test != prefix->sin6_addr.s6_addr[i]) return false;
		}
		return true;
	} else {
		LOGF("Network::isInNetwork: cannot happen");
	}

	return false;
}

string Agent::Network::print(const struct ifaddrs* ifaddr) {
	stringstream ss;
	int err;
	unsigned int size =
	    (ifaddr->ifa_addr->sa_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
	char result[IPADDR_SIZE];
	ss << "Name: " << ifaddr->ifa_name;

	err = getnameinfo(ifaddr->ifa_addr, size, result, IPADDR_SIZE, NULL, 0, NI_NUMERICHOST);
	if (err != 0) {
		ss << "\tAddress: "
		   << "(Error)";
	} else {
		ss << "\tAddress: " << result;
	}
	err = getnameinfo(ifaddr->ifa_netmask, size, result, IPADDR_SIZE, NULL, 0, NI_NUMERICHOST);
	if (err != 0) {
		ss << "\tMask: "
		   << "(Error)";
	} else {
		ss << "\tMask: " << result;
	}

	return ss.str();
}

int Agent::countUsInVia(sip_via_t* via) const {
	int count = 0;
	for (sip_via_t* v = via; v != NULL; v = v->v_next) {
		if (isUs(v->v_host, v->v_port, true)) ++count;
	}

	return count;
}

bool Agent::isUs(const char* host, const char* port, bool check_aliases) const {
	// skip possibly trailing '.' at the end of host
	char* tmp = nullptr;
	size_t end;
	if (host[end = (strlen(host) - 1)] == '.') {
		tmp = (char*)alloca(end + 1);
		memcpy(tmp, host, end);
		tmp[end] = '\0';
		host = tmp;
	}

	if (check_aliases) {
		/*the checking of aliases ignores the port number, since a domain name in a Route header might resolve to
		 * multiple ports thanks to SRV records */
		list<string>::const_iterator it;
		for (const auto& alias : mAliases) {
			if (ModuleToolbox::urlHostMatch(host, alias.c_str())) return true;
		}
	}

	string matchedHost{host == nullptr ? "" : host};
	string matchedPort{port == nullptr ? "" : port};

	return any_of(mTransports.begin(), mTransports.end(),
	              [&matchedHost, &matchedPort](const auto& t) { return t.is(matchedHost, matchedPort); });
}

sip_via_t* Agent::getNextVia(sip_t* response) {
	sip_via_t* via;
	for (via = response->sip_via; via != NULL; via = via->v_next) {
		if (!isUs(via->v_host, via->v_port, false)) return via;
	}
	return NULL;
}

/**
 * Takes care of an eventual maddr parameter.
 */
bool Agent::isUs(const url_t* url, bool check_aliases) const {
	char maddr[50];
	if (mDrm && mDrm->isUs(url)) return true;
	if (url_param(url->url_params, "maddr", maddr, sizeof(maddr))) {
		return isUs(maddr, url->url_port, check_aliases);
	}
	return isUs(url->url_host, url->url_port, check_aliases);
}

shared_ptr<Module> Agent::findModule(const string& moduleName) const {
	auto it = find_if(mModules.cbegin(), mModules.cend(),
	                  [&moduleName](const auto& m) { return m->getModuleName() == moduleName; });
	return (it != mModules.cend()) ? *it : nullptr;
}

shared_ptr<Module> Agent::findModuleByFunction(const std::string& moduleFunction) const {
	auto it = find_if(mModules.cbegin(), mModules.cend(),
	                  [&moduleFunction](const auto& m) { return m->getInfo()->getFunction() == moduleFunction; });
	return it != mModules.cend() ? *it : nullptr;
}

template <typename SipEventT, typename ModuleIter>
void Agent::doSendEvent(std::shared_ptr<SipEventT> ev, const ModuleIter& begin, const ModuleIter& end) {
	for (auto it = begin; it != end; ++it) {
		ev->mCurrModule = *it;
		(*it)->process(ev);
		if (ev->isTerminated() || ev->isSuspended()) break;
	}
	if (!ev->isTerminated() && !ev->isSuspended()) {
		LOGA("Event not handled %p", ev.get());
	}
}

void Agent::sendRequestEvent(shared_ptr<RequestSipEvent> ev) {
	SipLogContext ctx(ev->getMsgSip());
	sip_t* sip = ev->getMsgSip()->getSip();
	const sip_request_t* req = sip->sip_request;
	const url_t* from_url = sip->sip_from ? sip->sip_from->a_url : NULL;

	SLOGD << "Receiving new Request SIP message " << req->rq_method_name << " from "
	      << (from_url ? url_as_string(ev->getHome(), from_url) : "<invalid from>") << " :\n"
	      << *ev->getMsgSip();
	switch (req->rq_method) {
		case sip_method_register:
			++*mCountIncomingRegister;
			break;
		case sip_method_invite:
			++*mCountIncomingInvite;
			break;
		case sip_method_ack:
			++*mCountIncomingAck;
			break;
		case sip_method_info:
			++*mCountIncomingInfo;
			break;
		case sip_method_cancel:
			++*mCountIncomingCancel;
			break;
		case sip_method_bye:
			++*mCountIncomingBye;
			break;
		case sip_method_message:
			++*mCountIncomingMessage;
			break;
		case sip_method_options:
			++*mCountIncomingOptions;
			break;
		default:
			if (strcmp(req->rq_method_name, "DECLINE") == 0) {
				++*mCountIncomingDecline;
			} else {
				++*mCountIncomingReqUnknown;
			}
			break;
	}

	doSendEvent(ev, mModules.begin(), mModules.end());
}

void Agent::sendResponseEvent(const shared_ptr<ResponseSipEvent>& ev) {
	if (mTerminating) {
		// Avoid throwing a bad weak pointer on GatewayAdapter destruction
		LOGI("Skipping incoming message on expired agent");
		return;
	}
	SipLogContext ctx(ev->getMsgSip());

	SLOGD << "Receiving new Response SIP message: " << ev->getMsgSip()->getSip()->sip_status->st_status << "\n"
	      << *ev->getMsgSip();

	sip_t* sip = ev->getMsgSip()->getSip();
	switch (sip->sip_status->st_status) {
		case 100:
			++*mCountIncoming100;
			break;
		case 101:
			++*mCountIncoming101;
			break;
		case 180:
			++*mCountIncoming180;
			break;
		case 200:
			++*mCountIncoming200;
			break;
		case 202:
			++*mCountIncoming202;
			break;
		case 401:
			++*mCountIncoming401;
			break;
		case 404:
			++*mCountIncoming404;
			break;
		case 407:
			++*mCountIncoming407;
			break;
		case 408:
			++*mCountIncoming408;
			break;
		case 486:
			++*mCountIncoming486;
			break;
		case 487:
			++*mCountIncoming487;
			break;
		case 488:
			++*mCountIncoming488;
			break;
		case 603:
			++*mCountIncoming603;
			break;
		default:
			++*mCountIncomingResUnknown;
			break;
	}

	doSendEvent(ev, mModules.begin(), mModules.end());
}

void Agent::injectRequestEvent(const shared_ptr<RequestSipEvent>& ev) {
	SipLogContext ctx{ev->getMsgSip()};
	auto currModule = ev->mCurrModule.lock(); // Used to be a basic pointer
	SLOGD << "Inject request SIP event [" << ev << "] after " << currModule->getModuleName() << ":\n"
	      << *ev->getMsgSip();
	ev->restartProcessing();
	auto it = find(mModules.cbegin(), mModules.cend(), currModule);
	doSendEvent(ev, ++it, mModules.cend());
	printEventTailSeparator();
}

void Agent::injectResponseEvent(const shared_ptr<ResponseSipEvent>& ev) {
	SipLogContext ctx{ev->getMsgSip()};
	auto currModule = ev->mCurrModule.lock(); // Used to be a basic pointer
	SLOGD << "Injecting response SIP event [" << ev << "] after " << currModule->getModuleName() << ":\n"
	      << *ev->getMsgSip();
	ev->restartProcessing();
	auto it = find(mModules.cbegin(), mModules.cend(), currModule);
	doSendEvent(ev, ++it, mModules.cend());
	printEventTailSeparator();
}

/**
 * This is a dangerous function when called at the wrong time.
 * So we prefer an early abort with a stack trace.
 * Indeed, incoming tport is global in sofia and will be overwritten
 */
tport_t* Agent::getIncomingTport(const msg_t* orig) {
	tport_t* primaries = nta_agent_tports(getSofiaAgent());
	tport_t* tport = tport_delivered_by(primaries, orig);
	if (!tport) {
		/* tport shall never be null for a request, but it may be null for a response, for example
		 * for self-generated 503 responses following a connection refused.
		 */
		const sip_t* sip = (const sip_t*)msg_object(orig);
		if (sip && sip->sip_request != nullptr) {
			LOGA("tport not found");
		}
	}
	return tport;
}

int Agent::onIncomingMessage(msg_t* msg, const sip_t* sip) {
	if (mTerminating) {
		// Avoid throwing a bad weak pointer on GatewayAdapter destruction
		LOGI("Skipping incoming message on expired agent");
		return -1;
	}
	// Assuming sip is derived from msg
	auto ms = make_shared<MsgSip>(ownership::owned(msg));
	if (sip->sip_request) {
		auto ev = make_shared<RequestSipEvent>(shared_from_this(), ms, getIncomingTport(ms->getMsg()));
		sendRequestEvent(ev);
	} else {
		auto ev = make_shared<ResponseSipEvent>(shared_from_this(), ms, getIncomingTport(msg));
		sendResponseEvent(ev);
	}
	printEventTailSeparator();
	return 0;
}

url_t* Agent::urlFromTportName(su_home_t* home, const tp_name_t* name) {
	url_t* url = NULL;
	url_type_e ut = url_sip;

	if (strcasecmp(name->tpn_proto, "tls") == 0) ut = url_sips;

	url = (url_t*)su_alloc(home, sizeof(url_t));
	url_init(url, ut);

	if (strcasecmp(name->tpn_proto, "tcp") == 0) url_param_add(home, url, "transport=tcp");

	url->url_port = su_strdup(home, name->tpn_port);
	url->url_host = su_strdup(home, name->tpn_canon);
	return url;
}

int Agent::messageCallback(nta_agent_magic_t* context, [[maybe_unused]] nta_agent_t* agent, msg_t* msg, sip_t* sip) {
	Agent* a = (Agent*)context;
	return a->onIncomingMessage(msg, sip);
}

void Agent::idle() {
	for (const auto& module : mModules) {
		module->idle();
	}
	if (mConfigManager->mNeedRestart) {
		exit(RESTART_EXIT_CODE);
	}
}

const string& Agent::getUniqueId() const {
	return mUniqueId;
}

su_timer_t* Agent::createTimer(int milliseconds, TimerCallback cb, void* data, bool repeating) {
	auto* timer = su_timer_create(mRoot->getTask(), milliseconds);
	if (repeating) su_timer_set_for_ever(timer, (su_timer_f)cb, data);
	else su_timer_set(timer, (su_timer_f)cb, data);
	return timer;
}

void Agent::stopTimer(su_timer_t* t) {
	su_timer_destroy(t);
}

void Agent::send(const shared_ptr<MsgSip>& ms, url_string_t const* u, tag_type_t tag, tag_value_t value, ...) {
	ta_list ta;
	ta_start(ta, tag, value);
	msg_t* msg = msg_ref_create(ms->getMsg());
	nta_msg_tsend(mAgent, msg, u, ta_tags(ta), TAG_END());
	ta_end(ta);
}

void Agent::incrReplyStat(int status) {
	switch (status) {
		case 100:
			++*mCountReply100;
			break;
		case 101:
			++*mCountReply101;
			break;
		case 180:
			++*mCountReply180;
			break;
		case 200:
			++*mCountReply200;
			break;
		case 202:
			++*mCountReply202;
			break;
		case 401:
			++*mCountReply401;
			break;
		case 404:
			++*mCountReply404;
			break;
		case 407:
			++*mCountReply407;
			break;
		case 408:
			++*mCountReply408;
			break;
		case 486:
			++*mCountReply486;
			break;
		case 487:
			++*mCountReply487;
			break;
		case 488:
			++*mCountReply488;
			break;
		default:
			++*mCountReplyResUnknown;
			break;
	}
}
void Agent::reply(
    const shared_ptr<MsgSip>& ms, int status, char const* phrase, tag_type_t tag, tag_value_t value, ...) {
	incrReplyStat(status);
	ta_list ta;
	ta_start(ta, tag, value);
	msg_t* msg = msg_ref_create(ms->getMsg());
	nta_msg_treply(mAgent, msg, status, phrase, ta_tags(ta));
	ta_end(ta);
}

void Agent::applyProxyToProxyTransportSettings(tport_t* tp) {
	if (mProxyToProxyKeepAliveInterval > 0) {
		unsigned int currentKeepAliveInterval = 0;
		tport_get_params(tp, TPTAG_KEEPALIVE_REF(currentKeepAliveInterval), TAG_END());
		if (currentKeepAliveInterval != mProxyToProxyKeepAliveInterval) {
			LOGD("Applying proxy to proxy keepalive interval for tport [%p]", tp);
			tport_set_params(tp, TPTAG_KEEPALIVE(mProxyToProxyKeepAliveInterval), TAG_END());
		}
	}
}

const std::string Agent::sEventSeparator(110, '=');

void Agent::printEventTailSeparator() {
	LOGD("\n\n%s\n", sEventSeparator.c_str());
}

bool Agent::shouldUseRfc2543RecordRoute() const {
	return mUseRfc2543RecordRoute;
}

} // namespace flexisip
