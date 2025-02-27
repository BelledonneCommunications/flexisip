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

#include "transport.hh"

#include <charconv>

#include <flexisip/logmanager.hh>
#include <flexisip/utils/sip-uri.hh>

#include <linphone++/core.hh>
#include <linphone/misc.h>

#include "exceptions/bad-configuration.hh"
#include "utils/string-utils.hh"

using namespace std;

static constexpr string_view kLogPrefix{"ConfigurationUtils::Transport"};

namespace flexisip::configuration_utils {

void configureTransport(const shared_ptr<linphone::Transports>& transports,
                        const ConfigString* parameter,
                        const set<string>& allowedSip,
                        const set<string>& allowedSips) {
	transports->setUdpPort(LC_SIP_TRANSPORT_DONTBIND);
	transports->setTcpPort(LC_SIP_TRANSPORT_DONTBIND);
	transports->setTlsPort(LC_SIP_TRANSPORT_DONTBIND);
	transports->setDtlsPort(LC_SIP_TRANSPORT_DONTBIND);

	const auto& transport = parameter->read();
	if (transport.empty()) return;

	const auto parameterName = parameter->getCompleteName();

	SipUri transportUri{};
	try {
		transportUri = SipUri{transport};
	} catch (const std::exception& exception) {
		throw BadConfiguration{parameterName + " invalid SIP URI ("s + exception.what() + ")"};
	}

	const auto scheme = transportUri.getScheme();
	const auto transportUriParam = string_utils::toLower(transportUri.getParam("transport"));

	const auto portText = transportUri.getPort(true);
	int listeningPort{};
	if (std::from_chars(portText.data(), portText.data() + portText.size(), listeningPort).ec ==
	    std::errc::invalid_argument) {
		throw BadConfiguration{parameterName + " failed to get port from SIP URI (" + transport + ")"};
	}
	if (listeningPort == 0) listeningPort = LC_SIP_TRANSPORT_RANDOM;

	if (scheme == "sip") {
		if (allowedSip.empty())
			throw BadConfiguration{parameterName + " 'sip' scheme is not allowed (" + transport + ")"};

		static map<string, const function<void(linphone::Transports&, int)>> sipSchemeTransports{
		    {"", &linphone::Transports::setUdpPort},
		    {"udp", &linphone::Transports::setUdpPort},
		    {"tcp", &linphone::Transports::setTcpPort},
		    {"tls", &linphone::Transports::setTlsPort},
		};

		if (allowedSip.find(transportUriParam) == allowedSip.end())
			throw BadConfiguration{parameterName + " transport type '" + transportUriParam +
			                       "' is not allowed for 'sip' scheme (" + transport + ")"};

		sipSchemeTransports.at(transportUriParam)(*transports, listeningPort);

	} else if (scheme == "sips") {
		if (allowedSips.empty())
			throw BadConfiguration{parameterName + " 'sips' scheme is not allowed (" + transport + ")"};

		static const map<string, const function<void(linphone::Transports&, int)>> sipsSchemeTransports{
		    {"udp", &linphone::Transports::setDtlsPort},
		    {"", &linphone::Transports::setTlsPort},
		    {"tcp", &linphone::Transports::setTlsPort},
		};

		if (allowedSips.find(transportUriParam) == allowedSips.end())
			throw BadConfiguration{parameterName + " transport type '" + transportUriParam +
			                       "' is not allowed for 'sips' scheme (" + transport + ")"};

		sipsSchemeTransports.at(transportUriParam)(*transports, listeningPort);

	} else {
		throw BadConfiguration{parameterName + " invalid scheme for SIP URI (" + transport + ")"};
	}
}

pair<string, IP_FAMILY> parseInternetAddress(string_view address, string_view service) {
	struct addrinfo* res{nullptr};
	struct addrinfo hints {};
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if (const auto error = bctbx_getaddrinfo(address.data(), service.data(), &hints, &res); error != 0) {
		LOGD_CTX(kLogPrefix) << "Failed to get address information on '" << address << "' with service '" << service
		                     << "': " << gai_strerror(error);
		return {"", AF_UNSPEC};
	}

	for (struct addrinfo* info = res; info != nullptr; info = info->ai_next) {
		int ipFamily = info->ai_family;
		char ipAddress[NI_MAXHOST] = {0};
		if (bctbx_addrinfo_to_ip_address(info, ipAddress, sizeof(ipAddress), nullptr) == 0) {
			bctbx_freeaddrinfo(res);
			return {ipAddress, ipFamily};
		}
	}

	bctbx_freeaddrinfo(res);
	return {"", AF_UNSPEC};
}

void configureNatAddresses(const shared_ptr<linphone::NatPolicy>& policy, const ConfigStringList* parameter) {
	const auto addresses = parameter->read();
	const auto parameterName = parameter->getCompleteName();
	for (const auto& address : addresses) {
		const auto [ipAddress, ipFamily] = parseInternetAddress(address);
		if (ipAddress.empty())
			throw BadConfiguration{parameterName + " failed to configure NAT address (" + address + ")"};

		switch (ipFamily) {
			case AF_INET: {
				if (policy->getNatV4Address().empty()) {
					policy->setNatV4Address(ipAddress);
					LOGI_CTX(kLogPrefix) << "Configured IPv4 NAT address: " << ipAddress;
				} else {
					throw BadConfiguration{parameterName + " only one IPv4 NAT address can be configured"};
				}
			} break;
			case AF_INET6: {
				if (policy->getNatV6Address().empty()) {
					policy->setNatV6Address(ipAddress);
					LOGI_CTX(kLogPrefix) << "Configured IPv6 NAT address: " << ipAddress;
				} else {
					throw BadConfiguration{parameterName + " only one IPv6 NAT address can be configured"};
				}
			} break;
			default:
				throw BadConfiguration{parameterName + " unknown IP family (" + ipAddress + " | " +
				                       to_string(ipFamily) + ")"};
		}
	}
}

} // namespace flexisip::configuration_utils