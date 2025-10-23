/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2025 Belledonne Communications SARL, All rights reserved.

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

#include "agent.hh"

#include <netdb.h>
#include <sys/socket.h>

#include <algorithm>
#include <memory>
#include <sstream>

#include "bctoolbox/ownership.hh"

#include "sofia-sip/nta_stateless.h"
#include "sofia-sip/sip.h"
#include "sofia-sip/su_md5.h"
#include "sofia-sip/su_tagarg.h"
#include "sofia-sip/tport.h"
#include "sofia-sip/tport_tag.h"

#include "auth/db/authdb.hh"
#include "domain-registrations.hh"
#include "etchosts.hh"
#include "exceptions/bad-configuration.hh"
#include "flexisip/flexisip-version.h"
#include "flexisip/logmanager.hh"
#include "flexisip/module.hh"
#include "modules/module-toolbox.hh"
#include "nat/contact-correction-strategy.hh"
#include "nat/flow-token-strategy.hh"
#include "plugin/plugin-loader.hh"
#include "utils/uri-utils.hh"

#define IPADDR_SIZE 64

using namespace std;
using namespace sofiasip;

namespace flexisip {

const string Agent::sEventSeparator(100, '-');

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
		createCounter(key, help, "notify");
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

/**
 * @throw BadConfiguration if one of the network addresses is invalid
 * @throw BadConfiguration if duplicated network addresses were found
 * @return content of the 'network' URI parameter, or 0.0.0.0/0 in case it is empty or used with '*' host.
 */
string getNetworkParameter(const Url& url) {
	static const string defaultNetwork{"0.0.0.0/0"};
	const auto host = url.getHost();
	const bool hostIsIpV6 = uri_utils::isIpv6Address(host.c_str());
	string networkParameter{url.getParam("network")};

	if (networkParameter.empty()) {
		if (!hostIsIpV6) return defaultNetwork;
		return {};
	}

	if (hostIsIpV6) {
		LOGW_CTX(Agent::mLogPrefix) << "The 'network' URI parameter is not supported for IPv6 transports: ignoring";
		return "";
	}
	if (host == "*") {
		LOGW_CTX(Agent::mLogPrefix)
		    << "The 'network' URI parameter cannot be set while using '*' as the host part of a transport: ignoring";
		return defaultNetwork;
	}

	vector<string> networkAddresses{};
	const auto networks = string_utils::split(networkParameter, ",");
	static const regex networkRegex{R"(^((((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4})\/([0-9]|[1-2][0-9]|3[0-2]))$)"};
	for (const auto& network : networks) {
		LOGD_CTX(Agent::mLogPrefix) << "Validating network: " << network;
		smatch matches{};
		if (!regex_match(network, matches, networkRegex)) {
			throw BadConfiguration{"invalid network address '" + network + "' in transport '" + url.str() + "'"};
		}
		if (matches[2].str() == "0.0.0.0" && matches[6].str() != "0") {
			throw BadConfiguration{"network address '" + network + "' is invalid (the mask MUST be 0 for 0.0.0.0)"};
		}
		if (find(networkAddresses.begin(), networkAddresses.end(), network) != networkAddresses.end()) {
			throw BadConfiguration{"duplicated network address '" + network + "' in transport '" + url.str() + "'"};
		}

		networkAddresses.push_back(network);
	}

	return networkParameter;
}

/**
 * @return transport in string format: "sip:host:port;transport=protocol;maddr=address(;network=address)"
 */
string getPrintableTransport(const tport_t* tport) {
	Home home{};
	const auto* name = tport_name(tport);

	stringstream ss{};
	ss << "sip:" << name->tpn_canon << ":" << name->tpn_port << ";transport=" << name->tpn_proto
	   << ";maddr=" << name->tpn_host
	   << (tport_has_network(tport) ? ";network="s + tport_network_str(home.home(), tport) : "");

	return ss.str();
}

string computeResolvedPublicIp(const string& host, int family = AF_UNSPEC) {
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
			LOGE_CTX(Agent::mLogPrefix) << "getnameinfo error: " << gai_strerror(err) << " for host [" << host << "]";
		}
	} else if ((family == AF_INET && !uri_utils::isIpv4Address(dest.c_str())) ||
	           (family == AF_INET6 && !uri_utils::isIpv6Address(dest.c_str()))) {
		// Silently ignore IP 4/6 mismatch. This is useful to discover whether the same host string is IP4 or IP6 by
		// calling this function twice and keeping the non-empty result
	} else {
		LOGW_CTX(Agent::mLogPrefix) << "getaddrinfo error: " << gai_strerror(err) << " for host [" << host
		                            << "] and family=[" << family << "]";
	}
	return "";
}

/**
 * @brief Get the last time a file used for a TLS connection was modified.
 *
 * @param[in] tlsInfo Structure containing the path to the certificate files.
 * @return The last time any of those file was modified.
 */
filesystem::file_time_type getLastCertUpdate(TlsConfigInfo& tlsInfo) {
	auto lastUpdate = filesystem::last_write_time(tlsInfo.certifFile);
	lastUpdate = max(lastUpdate, filesystem::last_write_time(tlsInfo.certifPrivateKey));
	if (!tlsInfo.certifCaFile.empty()) {
		lastUpdate = max(lastUpdate, filesystem::last_write_time(tlsInfo.certifCaFile));
	}

	return lastUpdate;
}

#if ENABLE_MDNS
void mDnsRegisterCallback(void* data, int error) {
	if (error != 0) LOGE_CTX(Agent::mLogPrefix) << "Error while registering a mDNS service";
}
#endif

string absolutePath(const string& currdir, const string& file) {
	if (file.empty()) return file;
	if (file.at(0) == '/') return file;
	return currdir + "/" + file;
}

/**
 * Make sure that there is no mistyped params in the provided url.
 * @throw BadConfiguration if a non-authorized parameter is present in the url
 */
void verifyAllowedParameters(const url_t* url) {
	Home home{};
	if (!url->url_params) return;

	// Remove all the allowed params and see if something else is remaining at the end.
	char* params = su_strdup(home.home(), url->url_params);
	params = url_strip_param_string(params, "tls-certificates-dir");
	params = url_strip_param_string(params, "tls-certificates-file");
	params = url_strip_param_string(params, "tls-certificates-private-key");
	params = url_strip_param_string(params, "tls-certificates-ca-file");
	params = url_strip_param_string(params, "require-peer-certificate");
	params = url_strip_param_string(params, "maddr");
	params = url_strip_param_string(params, "tls-verify-incoming");
	params = url_strip_param_string(params, "tls-allow-missing-client-certificate");
	params = url_strip_param_string(params, "tls-verify-outgoing");
	params = url_strip_param_string(params, "network");

	if (params && strlen(params) > 0)
		throw BadConfiguration{"bad parameters '"s + params + "' given in transports definition"};
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
		mCountIncomingNotify = global->getStat(key + "notify");
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

	const auto* uniqueIdParam = global->get<ConfigString>("unique-id");
	auto uniqueId = uniqueIdParam->read();
	if (!uniqueId.empty()) {
		if (uniqueId.length() == 16) {
			transform(uniqueId.begin(), uniqueId.end(), uniqueId.begin(), ::tolower);
			if (find_if(uniqueId.begin(), uniqueId.end(), [](char c) -> bool { return !::isxdigit(c); }) ==
			    uniqueId.end()) {
				mUniqueId = uniqueId;
			} else {
				throw BadConfigurationValue{uniqueIdParam, "parameter must hold an hexadecimal number"};
			}
		} else {
			throw BadConfigurationValue{uniqueIdParam, "parameter must have 16 characters"};
		}
	}

	const auto* rtpBindAddressParam = global->get<ConfigStringList>("rtp-bind-address");
	const auto rtpBindAddress = rtpBindAddressParam->read();
	if (rtpBindAddress.size() != 2) {
		throw BadConfigurationValue{
		    rtpBindAddressParam,
		    "config entry [rtp-bind-address] must have 2 and only 2 ip addresses, IPV4 first, IPV6 second"};
	}
	mRtpBindIp = rtpBindAddress.front();
	mRtpBindIp6 = rtpBindAddress.back();
}

void Agent::initializePreferredRoute() {
	// Adding internal transport to transport in "cluster" case
	const auto* cluster = mConfigManager->getRoot()->get<GenericStruct>("cluster");
	if (cluster->get<ConfigBoolean>("enabled")->read()) {
		const auto* internalTransportParam = cluster->get<ConfigString>("internal-transport");
		auto internalTransport = internalTransportParam->read();

		auto pos = internalTransport.find("\%auto");
		if (pos != string::npos) {
			LOGW << "Using '\%auto' token in '" << internalTransportParam->getCompleteName() << "' is deprecated";
			char result[NI_MAXHOST] = {0};
			// Currently only IpV4
			if (bctbx_get_local_ip_for(AF_INET, nullptr, 0, result, sizeof(result)) != 0)
				throw runtime_error{"%%auto couldn't be resolved"};

			internalTransport.replace(pos, sizeof("\%auto") - 1, result);
		}

		try {
			SipUri url{internalTransport};
			mPreferredRouteV4 = url_hdup(&mHome, url.get());
			LOGI << "Agent preferred IP for internal routing find: v4: " << internalTransport;
		} catch (const sofiasip::InvalidUrlError& e) {
			throw runtime_error{"invalid URI in '" + internalTransportParam->getCompleteName() + "': " + e.getReason()};
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

void Agent::startMdns() {
#if ENABLE_MDNS
	/* Get Informations about mDNS register */
	GenericStruct* mdns = mConfigManager->getRoot()->get<GenericStruct>("mdns-register");
	bool mdnsEnabled = mdns->get<ConfigBoolean>("enabled")->read();
	if (mdnsEnabled) {
		if (!belle_sip_mdns_register_available()) throw runtime_error{"Belle-sip does not have mDNS activated!"};

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
			LOGE << "Cannot retrieve machine hostname";
		} else {
			int prio;
			if (mdnsPrioMin == mdnsPrioMax) {
				prio = mdnsPrioMin;
			} else {
				/* Randomize the priority */
				prio = belle_sip_random() % (mdnsPrioMax - mdnsPrioMin + 1) + mdnsPrioMin;
				LOGD << "Multicast DNS services will be started with priority: " << prio;
			}

			LOGD << "Registering multicast DNS services";
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

void Agent::start(const string& transport_override, const string& passphrase) {
	char cCurrDir[FILENAME_MAX];
	if (!getcwd(cCurrDir, sizeof(cCurrDir))) {
		throw BadConfiguration{"could not get current file path"};
	}
	string currDir = cCurrDir;

	auto* global = mConfigManager->getRoot()->get<GenericStruct>("global");
	list<string> transports = global->get<ConfigStringList>("transports")->read();
	string ciphers = global->get<ConfigString>("tls-ciphers")->read();
	// sofia needs a value in milliseconds.
	auto tports_idle_timeout = global->get<ConfigDuration<chrono::seconds>>("idle-timeout")->read().count();
	bool globalVerifyIn = global->get<ConfigBoolean>("require-peer-certificate")->read();
	auto t1x64 = global->get<ConfigDuration<chrono::milliseconds>>("transaction-timeout")->read().count();
	int udpmtu = global->get<ConfigInt>("udp-mtu")->read();
	auto incompleteIncomingMessageTimeout = 600L * 1000L; /*milliseconds*/
	auto keepAliveInterval = global->get<ConfigDuration<chrono::seconds>>("keepalive-interval")->read().count();
	auto queueSize = (unsigned int)global->get<ConfigInt>("tport-message-queue-size")->read();

	mProxyToProxyKeepAliveInterval =
	    global->get<ConfigDuration<chrono::seconds>>("proxy-to-proxy-keepalive-interval")->read().count();

	const auto* natHelperConfig = findModuleByRole("NatHelper")->getConfig();
	const auto& strategy = natHelperConfig->get<ConfigString>("nat-traversal-strategy")->read();
	if (strategy == "contact-correction") {
		const auto& contactCorrectionParameter = natHelperConfig->get<ConfigString>("contact-correction-param")->read();
		mNatTraversalStrategy = make_shared<ContactCorrectionStrategy>(this, contactCorrectionParameter);
	} else if (strategy == "flow-token") {
		const auto forceFlowTokenExpr = natHelperConfig->get<ConfigBooleanExpression>("force-flow-token")->read();
		std::filesystem::path hashKeyPath = natHelperConfig->get<ConfigString>("flow-token-path")->read();
		mNatTraversalStrategy = make_shared<FlowTokenStrategy>(this, forceFlowTokenExpr, hashKeyPath);
	} else {
		throw runtime_error("unknown value for \"nat-traversal-strategy\" (" + strategy + ")");
	}

	mTimer.setForEver([this] { idle(); });

	const auto tcpMaxReadSize = global->get<ConfigInt>("tcp-max-read-size");
	if (tcpMaxReadSize->read() <= 0)
		throw BadConfigurationValue{tcpMaxReadSize, "parameter should be strictly positive"};

	nta_agent_set_params(mAgent, NTATAG_SIP_T1X64(t1x64), NTATAG_RPORT(1), NTATAG_TCP_RPORT(1),
	                     NTATAG_TLS_RPORT(1),    // use rport in vias added to outgoing requests for all protocols
	                     NTATAG_SERVER_RPORT(2), // always add a rport parameter even if the request doesn't have it*/
	                     NTATAG_UDP_MTU(udpmtu), TAG_END());

	const auto mainTlsConfigInfo = getTlsConfigInfo(global);

	if (!transport_override.empty()) {
		transports = ConfigStringList::parse(transport_override);
	}

	for (const auto& uri : transports) {
		int err;
		Url url{uri};
		LOGD << "Enabling transport " << uri;

		const auto networkParameter = getNetworkParameter(url);
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

			verifyAllowedParameters(url.get());
			mPassphrase = passphrase;

			auto uriTlsConfigInfo = url.getTlsConfigInfo();
			auto finalTlsConfigInfo =
			    uriTlsConfigInfo.mode != TlsMode::NONE ? std::move(uriTlsConfigInfo) : mainTlsConfigInfo;
			if (finalTlsConfigInfo.mode == TlsMode::OLD) {
				finalTlsConfigInfo.certifDir = absolutePath(currDir, finalTlsConfigInfo.certifDir);

				err = nta_agent_add_tport(
				    mAgent, reinterpret_cast<const url_string_t*>(url.get()),
				    TPTAG_CERTIFICATE(finalTlsConfigInfo.certifDir.c_str()), TPTAG_TLS_PASSPHRASE(mPassphrase.c_str()),
				    TPTAG_TLS_CIPHERS(ciphers.c_str()), TPTAG_TLS_VERIFY_POLICY(tls_policy),
				    TPTAG_IDLE(tports_idle_timeout), TPTAG_TIMEOUT(incompleteIncomingMessageTimeout),
				    TPTAG_KEEPALIVE(keepAliveInterval), TPTAG_SDWN_ERROR(1), TPTAG_QUEUESIZE(queueSize),
				    TPTAG_NETWORK(networkParameter.c_str()), TAG_END());
			} else {
				finalTlsConfigInfo.certifFile = absolutePath(currDir, finalTlsConfigInfo.certifFile);
				finalTlsConfigInfo.certifPrivateKey = absolutePath(currDir, finalTlsConfigInfo.certifPrivateKey);
				finalTlsConfigInfo.certifCaFile = absolutePath(currDir, finalTlsConfigInfo.certifCaFile);

				err =
				    nta_agent_add_tport(mAgent, reinterpret_cast<const url_string_t*>(url.get()),
				                        TPTAG_CERTIFICATE_FILE(finalTlsConfigInfo.certifFile.c_str()),
				                        TPTAG_CERTIFICATE_PRIVATE_KEY(finalTlsConfigInfo.certifPrivateKey.c_str()),
				                        TPTAG_CERTIFICATE_CA_FILE(finalTlsConfigInfo.certifCaFile.c_str()),
				                        TPTAG_TLS_PASSPHRASE(mPassphrase.c_str()), TPTAG_TLS_CIPHERS(ciphers.c_str()),
				                        TPTAG_TLS_VERIFY_POLICY(tls_policy), TPTAG_IDLE(tports_idle_timeout),
				                        TPTAG_TIMEOUT(incompleteIncomingMessageTimeout),
				                        TPTAG_KEEPALIVE(keepAliveInterval), TPTAG_SDWN_ERROR(1),
				                        TPTAG_QUEUESIZE(queueSize), TPTAG_NETWORK(networkParameter.c_str()), TAG_END());
				if (!err) {
					try {
						auto lastUpdateTime = getLastCertUpdate(finalTlsConfigInfo);
						mTlsTransportsList.emplace_back(url, std::move(finalTlsConfigInfo), ciphers, tls_policy,
						                                lastUpdateTime);
					} catch (exception& e) {
						// This should not happen as the file are already tested while adding a transport.
						LOGE << "Failed to get the last modification time for the certificate files of transport "
						     << url.str() << ", it will not be periodically updated (cause: " << e.what() << ")";
					}
				}
			}
		} else {
			err = nta_agent_add_tport(mAgent, reinterpret_cast<const url_string_t*>(url.get()),
			                          TPTAG_IDLE(tports_idle_timeout), TPTAG_TIMEOUT(incompleteIncomingMessageTimeout),
			                          TPTAG_KEEPALIVE(keepAliveInterval), TPTAG_SDWN_ERROR(1),
			                          TPTAG_QUEUESIZE(queueSize), TPTAG_NETWORK(networkParameter.c_str()), TAG_END());
		}
		if (err == -1) {
			const auto transport = url.getParam("transport");
			if (strcasecmp(transport.c_str(), "tls") == 0) {
				throw BadConfiguration{"specifying a URI with 'transport=tls' is not valid in Flexisip configuration. "
				                       "Use 'sips' uri scheme instead."};
			}
			throw runtime_error("could not enable transport " + uri + ", " + strerror(errno));
		}
	}
	if (!mTlsTransportsList.empty()) {
		auto certUpdatePeriod = mConfigManager->getGlobal()
		                            ->get<ConfigDuration<chrono::minutes>>("tls-certificates-check-interval")
		                            ->read();

		mCertificateUpdateTimer.emplace(mRoot, certUpdatePeriod);
		mCertificateUpdateTimer->setForEver([this] {
			for (auto& transport : mTlsTransportsList) {
				updateTransport(transport);
			}
		});
	}

	// Iterate over all primary transports (enabled through the "global/transports" parameter + implicitly enabled when
	// using "sip:*") to guess information (empiric method):
	//   - mPublicIpV4/mPublicIpV6 is the public IP of the proxy, assuming there is only one.
	//   - mPreferredRouteV4/mPreferredRouteV6 is a private interface of the proxy that can be used for inter flexisip
	//     nodes SIP communication.
	//   - mRtpBindIp/mRtpBindIp6 is a local address to bind rtp ports. It is taken from maddr parameter of the public
	//     transport of the proxy.
	//
	// This algorithm is empiric and aims at satisfying most common needs but cannot satisfy all of them.

	if (mPreferredRouteV4 != nullptr) {
		if (nta_agent_add_tport(mAgent, reinterpret_cast<const url_string_t*>(mPreferredRouteV4),
		                        TPTAG_IDLE(tports_idle_timeout), TPTAG_TIMEOUT(incompleteIncomingMessageTimeout),
		                        TPTAG_IDENT(sInternalTransportIdent), TPTAG_KEEPALIVE(keepAliveInterval),
		                        TPTAG_QUEUESIZE(queueSize), TPTAG_SDWN_ERROR(1), TAG_END()) == -1) {
			char prefRouteV4[266];
			url_e(prefRouteV4, sizeof(prefRouteV4), mPreferredRouteV4);
			throw runtime_error{"could not enable internal transport "s + prefRouteV4 + ", " + strerror(errno)};
		}
		tp_name_t tn{};
		tn.tpn_ident = sInternalTransportIdent;
		mInternalTport = tport_by_name(nta_agent_tports(mAgent), &tn);
		if (!mInternalTport) throw runtime_error{"failed to retrieve internal transport (pointer is empty)"};
	}

	tport_t* primaries = tport_primaries(nta_agent_tports(mAgent));
	if (primaries == nullptr) throw BadConfiguration{"no valid SIP transport found, please verify your configuration"};
	startMdns();

	for (auto* tport = nta_agent_tports(mAgent); tport; tport = tport_next(tport))
		if (tport_is_tcp(tport)) tport_set_max_read_size(tport, tcpMaxReadSize->read());

	LOGI << "Agent primaries are:";
	Home home{};
	const tport_t* publicTransport{};
	for (const auto* tport = primaries; tport != nullptr; tport = tport_next(tport)) {
		// The public IP address and the bound IP address are different. This is the case for transports with
		// "sip:public_address;maddr=binding_address" where "public_address" is the hostname or IP address publicly
		// announced and "binding_address" the real IP address we are listening on. It is useful for scenarios where
		// the sever is behind a router.
		const auto* name = tport_name(tport);
		auto isIpv6 = uri_utils::isIpv6Address(name->tpn_host);
		auto formatedHost = module_toolbox::getHost(name->tpn_canon);
		if (isIpv6 && mPublicIpV6.empty()) mPublicIpV6 = formatedHost;
		else if (!isIpv6 && mPublicIpV4.empty()) mPublicIpV4 = formatedHost;

		// Hypothesis: the first transport with network set to the "0.0.0.0/0" is the public transport.
		if (!publicTransport && tport_has_network(tport) && tport_network_str(home.home(), tport) == "0.0.0.0/0"s)
			publicTransport = tport;

		mTransports.emplace_back(formatedHost, name->tpn_port, name->tpn_proto,
		                         computeResolvedPublicIp(formatedHost, AF_INET),
		                         computeResolvedPublicIp(formatedHost, AF_INET6), name->tpn_host);

		LOGI << "\t" << getPrintableTransport(tport);
	}

	// If no public transport was found, take the first primary transport as public transport.
	if (!publicTransport) publicTransport = primaries;
	mNodeUri = urlFromTportName(&mHome, tport_name(publicTransport));

	LOGI << "The 'public' transport: " << getPrintableTransport(publicTransport);

	const auto* clusterConfig = mConfigManager->getRoot()->get<GenericStruct>("cluster");
	const auto clusterDomain = clusterConfig->get<ConfigString>("cluster-domain")->read();
	if (mNodeUri && !clusterDomain.empty()) {
		auto name = *tport_name(publicTransport);
		name.tpn_canon = clusterDomain.c_str();
		name.tpn_port = nullptr;
		mClusterUri = urlFromTportName(&mHome, &name);
	}

	mDefaultUri = (clusterConfig->get<ConfigBoolean>("enabled")->read() && mClusterUri) ? mClusterUri : mNodeUri;

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
		LOGW << "This flexisip instance has no public IPv6 address detected";
	}

	// Generate the unique ID if it has not been specified in Flexisip's settings
	if (mUniqueId.empty()) {
		su_md5_t ctx;
		su_md5_init(&ctx);
		char digest[(SU_MD5_DIGEST_SIZE * 2) + 1];
		su_md5_hexdigest(&ctx, digest);
		su_md5_deinit(&ctx);
		digest[16] = '\0'; // keep half of the digest, should be enough
		// compute a network wide unique id
		mUniqueId = digest;
		LOGD << "Generated unique ID: " << mUniqueId;
	} else {
		LOGD << "Static unique ID: " << mUniqueId;
	}

	if (mPublicResolvedIpV6.empty() && mPublicResolvedIpV4.empty()) {
		throw runtime_error{"the default public address of the server could not be resolved (" + mPublicIpV4 + " / " +
		                    mPublicIpV6 + ")"};
	}

	LOGI << "Agent public hostname/ip:            v4: " << mPublicIpV4 << "\tv6: " << mPublicIpV6;
	LOGI << "Agent public resolved hostname/ip:   v4: " << mPublicResolvedIpV4 << "\tv6: " << mPublicResolvedIpV6;
	LOGI << "Agent _default_ RTP bind ip address: v4: " << mRtpBindIp << "\tv6: " << mRtpBindIp6;

	mRegistrarDb->setLatestExpirePredicate([weakAg = weak_from_this()](const url_t* url) {
		auto agent = weakAg.lock();
		if (agent == nullptr) return false;
		return agent->isUs(url);
	});

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
		throw BadConfiguration{
		    "if you specified tls-certificates-file you MUST specify tls-certificates-private-key too and vice versa"};
	}
	if (!tlsConfigInfoFromConf.certifFile.empty()) {
		tlsConfigInfoFromConf.mode = TlsMode::NEW;
		LOGI << "Main tls certs file [" << tlsConfigInfoFromConf.certifFile << "], main private key file ["
		     << tlsConfigInfoFromConf.certifPrivateKey << "], main CA file [" << tlsConfigInfoFromConf.certifCaFile
		     << "]";

	} else {
		tlsConfigInfoFromConf.mode = TlsMode::OLD;
		LOGI << "Main tls certs dir: " << tlsConfigInfoFromConf.certifDir
		     << " (be careful you are using a deprecated config tls-certificates-dir)";
	}

	return tlsConfigInfoFromConf;
}

void Agent::addConfigSections(ConfigManager& cfg) {
	// Modules are statically register into the ModuleInfoManager singleton.
	// Ask the ModuleInfoManager to build a valid module info chain, according to module's placement hints.
	list<ModuleInfoBase*> moduleInfoChain = ModuleInfoManager::get()->buildModuleChain();

	// Add modules config section.
	GenericStruct* cr = cfg.getEditableRoot();
	for (ModuleInfoBase* moduleInfo : moduleInfoChain) {
		moduleInfo->declareConfig(*cr);
	}
	createAgentCounters(*cr);
	DomainRegistrationManager::declareConfig(*cr);
}

void Agent::addPluginsConfigSections(ConfigManager& cfg) {
	// Load plugins .so files. They will automatically register into the ModuleInfoManager singleton.
	GenericStruct* cr = cfg.getEditableRoot();
	const GenericStruct* global = cr->get<GenericStruct>("global");
	const string& pluginDir = global->get<ConfigString>("plugins-dir")->read();
	for (const string& pluginName : global->get<ConfigStringList>("plugins")->read()) {
		LOGI << "Loading [" << pluginName << "] plugin...";
		PluginLoader pluginLoader(pluginDir + "/lib" + pluginName + ".so");
		const ModuleInfoBase* moduleInfo = pluginLoader.getModuleInfo();
		if (!moduleInfo) {
			throw runtime_error{"unable to load plugin [" + pluginName + "]: " + pluginLoader.getError()};
		}
		moduleInfo->declareConfig(*cr);
	}
	// Ask the ModuleInfoManager to build a valid module info chain, according to module's placement hints.
	ModuleInfoManager::get()->buildModuleChain();
}

Agent::Agent(const std::shared_ptr<sofiasip::SuRoot>& root,
             const std::shared_ptr<ConfigManager>& cm,
             const std::shared_ptr<AuthDb>& authDb,
             const std::shared_ptr<RegistrarDb>& registrarDb)
    : mRoot{root}, mConfigManager{cm}, mAuthDb{authDb}, mRegistrarDb{registrarDb}, mTimer(mRoot, 5s) {
	LOGD << "New Agent instance: " << this;
	mHttpEngine = nth_engine_create(root->getCPtr(), NTHTAG_ERROR_MSG(0), TAG_END());
	const auto* cr = cm->getRoot();

	EtcHostsResolver::get();

	list<ModuleInfoBase*> moduleInfoChain = ModuleInfoManager::get()->getModuleChain();

	// Instantiate the modules.
	for (ModuleInfoBase* moduleInfo : moduleInfoChain) {
		LOGD << "Creating module instance of [" << moduleInfo->getModuleName() << "]";
		mModules.push_back(moduleInfo->create(this));
	}

	mServerString = "Flexisip/" FLEXISIP_GIT_VERSION " (sofia-sip-nta/" NTA_VERSION ")";

	onDeclare(*cr);

	struct ifaddrs* net_addrs;
	int err = getifaddrs(&net_addrs);
	if (err == 0) {
		struct ifaddrs* ifa = net_addrs;
		while (ifa != nullptr) {
			if (ifa->ifa_netmask != nullptr && ifa->ifa_addr != nullptr) {
				LOGI << "New network: " << Network::print(ifa);
				mNetworks.emplace_front(ifa);
			}
			ifa = ifa->ifa_next;
		}
		freeifaddrs(net_addrs);
	} else {
		LOGE << "Cannot find interface addresses: " << strerror(err);
	}

	mAgent = nta_agent_create(root->getCPtr(), (url_string_t*)-1, &Agent::messageCallback, (nta_agent_magic_t*)this,
	                          TAG_END());
	su_home_init(&mHome);
	mPreferredRouteV4 = nullptr;
	mPreferredRouteV6 = nullptr;
	mDrm = new DomainRegistrationManager(this);
	mProxyToProxyKeepAliveInterval = 0;

	mConfigManager->getGlobal()->get<ConfigStringList>("aliases")->setConfigListener(this);
	mAliases = mConfigManager->getGlobal()->get<ConfigStringList>("aliases")->read();
	LOGI << "List of host aliases:";
	for (const auto& alias : mAliases) {
		LOGI << "\t" << alias;
	}

	initializePreferredRoute();
}

Agent::~Agent() {
	LOGD << "Destroy Agent instance: " << this;
#if ENABLE_MDNS
	for (belle_sip_mdns_register_t* reg : mMdnsRegisterList) {
		belle_sip_mdns_unregister(reg);
	}
#endif

	mTerminating = true;

	// We need to clear modules before calling destroy on sofia agent.
	mModules.clear();

	mTimer.stop();
	if (mCertificateUpdateTimer.has_value()) mCertificateUpdateTimer->stop();
	delete mDrm;
	if (mAgent) nta_agent_destroy(mAgent);
	if (mHttpEngine) nth_engine_destroy(mHttpEngine);
	su_home_deinit(&mHome);
}

string Agent::getPreferredRoute() const {
	if (!mPreferredRouteV4) return string{};

	char prefUrl[266];
	url_e(prefUrl, sizeof(prefUrl), mPreferredRouteV4);
	return string{prefUrl};
}

bool Agent::doOnConfigStateChanged(const ConfigValue& conf, ConfigState state) {
	LOGI << "Configuration of agent changed for key " << conf.getName() << " to " << conf.get();

	if (conf.getName() == "aliases" && state == ConfigState::Committed) {
		mAliases = ((ConfigStringList*)(&conf))->read();
		LOGD << "Global aliases updated";
	}
	return true;
}

void Agent::unloadConfig() {
	for (const auto& module : mModules) {
		module->unload();
	}
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
		LOGE << "getPreferredIp() getaddrinfo() error while resolving '" << dest << "': " << gai_strerror(err);
	}
	isIpv6 = strchr(dest.c_str(), ':') != NULL;
	if (getResolvedPublicIp(true).empty()) {
		// If no IPv6 available, fallback to ipv4 and relay on NAT64.
		return make_pair(getResolvedPublicIp(), getRtpBindIp());
	}
	return isIpv6 ? make_pair(getResolvedPublicIp(true), getRtpBindIp(true))
	              : make_pair(getResolvedPublicIp(), getRtpBindIp());
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

sip_via_t* Agent::getNextVia(sip_t* response) const {
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

shared_ptr<Module> Agent::findModuleByRole(const std::string& moduleRole) const {
	auto it = find_if(mModules.cbegin(), mModules.cend(),
	                  [&moduleRole](const auto& m) { return m->getInfo()->getRole() == moduleRole; });
	// That must never happen, the Agent instanciates a module of each role even if the configuration disables it.
	if (it == mModules.cend()) throw runtime_error("no module with the role \"" + moduleRole + "\" was found");
	return *it;
}

template <typename SipEventT, typename ModuleIter>
unique_ptr<SipEventT>
Agent::processEvent(std::unique_ptr<SipEventT>&& ev, const ModuleIter& begin, const ModuleIter& end) {
	for (auto it = begin; it != end; ++it) {
		ev->mCurrModule = *it;
		ev = (*it)->process(std::move(ev));
		if (!ev) return {};
		if (ev->isTerminated() || ev->isSuspended()) break;
	}
	if (!ev->isTerminated() && !ev->isSuspended()) {
		stringstream error{"Event no handled "};
		error << ev.get();
		throw FlexisipException{error.str()};
	}
	return std::move(ev);
}

void Agent::processRequest(unique_ptr<RequestSipEvent>&& ev) {
	const auto msgSip = ev->getMsgSip();
	SipLogContext ctx(msgSip);
	auto* sip = msgSip->getSip();
	const auto* req = sip->sip_request ? sip->sip_request->rq_method_name : "<unknown>";
	const auto cSeq = sip->sip_cseq ? to_string(sip->sip_cseq->cs_seq) : "<unknown>";
	const auto callId = sip->sip_call_id ? sip->sip_call_id->i_id : "<unknown>";
	const auto* from = sip->sip_from ? url_as_string(ev->getHome(), sip->sip_from->a_url) : "<unknown>";
	const auto* to = sip->sip_to ? url_as_string(ev->getHome(), sip->sip_to->a_url) : "<unknown>";

	LOGI << "Received SIP request [" << ev.get() << "] " << req << " (" << cSeq << " - " << callId << ") from " << from
	     << " to " << to;
	LOGD << "Message:\n" << *msgSip;

	if (const auto* sipRequest = sip->sip_request) {
		switch (sipRequest->rq_method) {
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
			case sip_method_notify:
				++*mCountIncomingNotify;
				break;
			case sip_method_options:
				++*mCountIncomingOptions;
				break;
			default:
				if (strcmp(sipRequest->rq_method_name, "DECLINE") == 0) {
					++*mCountIncomingDecline;
				} else {
					++*mCountIncomingReqUnknown;
				}
				break;
		}
	} else LOGD << "Could not increment counters for the current SIP request: sipRequest pointer is empty";

	processEvent(std::move(ev), mModules.begin(), mModules.end());
}

unique_ptr<ResponseSipEvent> Agent::processResponse(unique_ptr<ResponseSipEvent>&& ev) {
	if (mTerminating) {
		// Avoid throwing a bad weak pointer on GatewayAdapter destruction
		LOGI << "Skipping incoming message on expired agent";
		return {};
	}
	const auto msgSip = ev->getMsgSip();
	SipLogContext ctx(msgSip);

	const auto* sip = msgSip->getSip();
	const auto status = sip->sip_status ? to_string(sip->sip_status->st_status) : "<unknown>";
	const auto* phrase = sip->sip_status ? sip->sip_status->st_phrase : "<unknown>";
	const auto cSeq = sip->sip_cseq ? to_string(sip->sip_cseq->cs_seq) : "<unknown>";
	const auto callId = sip->sip_call_id ? sip->sip_call_id->i_id : "<unknown>";
	const auto* from = sip->sip_from ? url_as_string(ev->getHome(), sip->sip_from->a_url) : "<unknown>";
	const auto* to = sip->sip_to ? url_as_string(ev->getHome(), sip->sip_to->a_url) : "<unknown>";

	LOGI << "Received SIP response [" << ev.get() << "] " << status << " " << phrase << " (" << cSeq << " - " << callId
	     << ") from " << from << " to " << to;
	LOGD << "Message:\n" << *msgSip;

	if (const auto* sipStatus = sip->sip_status) {
		switch (sipStatus->st_status) {
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
	} else LOGD << "Could not increment counters for the current SIP response: sipStatus pointer is empty";

	return processEvent(std::move(ev), mModules.begin(), mModules.end());
}

void Agent::injectRequest(unique_ptr<RequestSipEvent>&& ev) {
	SipLogContext ctx{ev->getMsgSip()};
	auto currModule = ev->mCurrModule.lock(); // Used to be a basic pointer
	LOGI << "Inject SIP request [" << ev.get() << "] after " << currModule->getModuleName();
	LOGD << "Message:\n" << *ev->getMsgSip();
	ev->restartProcessing();
	auto it = find(mModules.cbegin(), mModules.cend(), currModule);
	processEvent(std::move(ev), ++it, mModules.cend());
	printEventTailSeparator();
}

unique_ptr<ResponseSipEvent> Agent::injectResponse(unique_ptr<ResponseSipEvent>&& ev) {
	SipLogContext ctx{ev->getMsgSip()};
	auto currModule = ev->mCurrModule.lock(); // Used to be a basic pointer
	LOGI << "Inject SIP response [" << ev.get() << "] after " << currModule->getModuleName();
	LOGD << "Message:\n" << *ev->getMsgSip();
	ev->restartProcessing();
	auto it = find(mModules.cbegin(), mModules.cend(), currModule);
	ev = processEvent(std::move(ev), ++it, mModules.cend());
	printEventTailSeparator();
	return std::move(ev);
}

/**
 * This is a dangerous function when called at the wrong time.
 * So we prefer an early abort with a stack trace.
 * Indeed, incoming tport is global in sofia and will be overwritten
 */
tport_t* Agent::getIncomingTport(const msg_t* orig) const {
	tport_t* primaries = nta_agent_tports(getSofiaAgent());
	tport_t* tport = tport_delivered_by(primaries, orig);
	if (!tport) {
		/* tport shall never be null for a request, but it may be null for a response, for example
		 * for self-generated 503 responses following a connection refused.
		 */
		const sip_t* sip = (const sip_t*)msg_object(orig);
		if (sip && sip->sip_request != nullptr) {
			throw runtime_error{"tport not found"};
		}
	}
	return tport;
}

int Agent::onIncomingMessage(msg_t* msg, const sip_t* sip) {
	if (mTerminating) {
		// Avoid throwing a bad weak pointer on GatewayAdapter destruction
		LOGI << "Skipping incoming message on expired agent";
		return -1;
	}
	// Assuming sip is derived from msg
	auto ms = make_shared<MsgSip>(ownership::owned(msg));
	if (sip->sip_request) {
		processRequest(make_unique<RequestSipEvent>(shared_from_this(), ms, getIncomingTport(ms->getMsg())));
	} else {
		processResponse(make_unique<ResponseSipEvent>(shared_from_this(), ms, getIncomingTport(msg)));
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

su_timer_t* Agent::createTimer(int milliseconds, TimerCallback cb, void* data, bool repeating) const {
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
			LOGD << "Applying proxy to proxy keepalive interval for tport [" << tp << "]";
			tport_set_params(tp, TPTAG_KEEPALIVE(mProxyToProxyKeepAliveInterval), TAG_END());
		}
	}
}

void Agent::printEventTailSeparator() {
	STREAM_LOG(BCTBX_LOG_DEBUG);
	STREAM_LOG(BCTBX_LOG_MESSAGE) << sEventSeparator;
	STREAM_LOG(BCTBX_LOG_DEBUG);
}

void Agent::sendTrap(const GenericEntry* source, const std::string& msg) const {
	if (auto p = mNotifier.lock()) {
		p->sendNotification(source, msg);
	}
}

void Agent::updateTransport(TlsTransportInfo& tlsTpInfo) {
	filesystem::file_time_type lastModificationTime{};
	try {
		lastModificationTime = getLastCertUpdate(tlsTpInfo.tlsConfigInfo);
	} catch (exception& e) {
		LOGW << "Failed to get last modification date of the certificates for TLS transport " << tlsTpInfo.url.str()
		     << ": " << e.what();
		return;
	}
	if (lastModificationTime > tlsTpInfo.lastModificationTime) {
		LOGI << "Updating TLS certificate for transport: " << tlsTpInfo.url.str();
		if (nta_agent_update_tport_certificates(
		        mAgent, reinterpret_cast<const url_string_t*>(tlsTpInfo.url.get()),
		        TPTAG_CERTIFICATE_FILE(tlsTpInfo.tlsConfigInfo.certifFile.c_str()),
		        TPTAG_CERTIFICATE_PRIVATE_KEY(tlsTpInfo.tlsConfigInfo.certifPrivateKey.c_str()),
		        TPTAG_CERTIFICATE_CA_FILE(tlsTpInfo.tlsConfigInfo.certifCaFile.c_str()),
		        TPTAG_TLS_PASSPHRASE(mPassphrase.c_str()), TPTAG_TLS_CIPHERS(tlsTpInfo.ciphers.c_str()),
		        TPTAG_TLS_VERIFY_POLICY(tlsTpInfo.policy), TAG_END())) {
			LOGE << "Error while updating the TLS transport: " << tlsTpInfo.url.str()
			     << " cert: " << tlsTpInfo.tlsConfigInfo.certifFile
			     << " key: " << tlsTpInfo.tlsConfigInfo.certifPrivateKey
			     << " (See sofia-sip logs for more information.)";
		}

		tlsTpInfo.lastModificationTime = lastModificationTime;
	}
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
		LOGE << "getnameinfo error: " << strerror(errno);
	}
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
		throw runtime_error{"Network::isInNetwork: cannot happen"};
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
		ss << "\tAddress: (Error)";
	} else {
		ss << "\tAddress: " << result;
	}
	err = getnameinfo(ifaddr->ifa_netmask, size, result, IPADDR_SIZE, NULL, 0, NI_NUMERICHOST);
	if (err != 0) {
		ss << "\tMask: (Error)";
	} else {
		ss << "\tMask: " << result;
	}

	return ss.str();
}

} // namespace flexisip