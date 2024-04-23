/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include "module-auth-trusted-hosts.hh"

#include "agent.hh"

using namespace std;

namespace flexisip {

namespace {
const auto sTrustedHostsInfo = ModuleInfo<ModuleAuthTrustedHosts>(
    "AuthTrustedHosts",
    "The AuthTrustedHosts module identifies SIP requests from trusted hosts.\n"
    "Activating this module requires enabling the Authorization module and disabling the Authentication module.\n",
    {"Authentication"},
    ModuleInfoBase::ModuleOid::TrustedHostsAuthentication,
    [](GenericStruct& moduleConfig) {
	    ConfigItemDescriptor items[] = {
	        {StringList, "trusted-hosts",
	         "List of whitespace-separated IP addresses which will be judged as trustful. Messages coming from these "
	         "addresses won't be challenged.",
	         ""},
	        config_item_end};
	    moduleConfig.addChildrenValues(items);
	    moduleConfig.get<ConfigBoolean>("enabled")->setDefault("false");
    });

bool isEmpty(const char* value) {
	return value == nullptr || value[0] == '\0';
}
} // namespace

ModuleAuthTrustedHosts::ModuleAuthTrustedHosts(Agent* ag, const ModuleInfoBase* moduleInfo) : Module(ag, moduleInfo) {
}

void ModuleAuthTrustedHosts::onLoad(const GenericStruct* mc) {
	if (getAgent()
	        ->getConfigManager()
	        .getRoot()
	        ->get<GenericStruct>("module::Authorization")
	        ->get<ConfigBoolean>("enabled")
	        ->read() == false)
		LOGF("The AuthTrustedHosts module requires the Authorization module to be enabled.");

	loadTrustedHosts(*mc->get<ConfigStringList>("trusted-hosts"));
}

void ModuleAuthTrustedHosts::loadTrustedHosts(const ConfigStringList& trustedHosts) {
	const regex parameterRef{R"re(\$\{([0-9A-Za-z:-]+)/([0-9A-Za-z:-]+)\})re"};
	smatch m{};

	auto hosts = trustedHosts.read();
	for (const auto& host : hosts) {
		if (regex_match(host, m, parameterRef)) {
			auto paramRefValues = getAgent()
			                          ->getConfigManager()
			                          .getRoot()
			                          ->get<GenericStruct>(m.str(1))
			                          ->get<ConfigStringList>(m.str(2))
			                          ->read();
			for (const auto& value : paramRefValues) {
				BinaryIp::emplace(mTrustedHosts, value);
			}
		} else {
			BinaryIp::emplace(mTrustedHosts, host);
		}
	}

	const auto* clusterSection = getAgent()->getConfigManager().getRoot()->get<GenericStruct>("cluster");
	auto clusterEnabled = clusterSection->get<ConfigBoolean>("enabled")->read();
	if (clusterEnabled) {
		auto clusterNodes = clusterSection->get<ConfigStringList>("nodes")->read();
		for (const auto& host : clusterNodes) {
			BinaryIp::emplace(mTrustedHosts, host);
		}
	}

	const auto* presenceSection = getAgent()->getConfigManager().getRoot()->get<GenericStruct>("module::Presence");
	const auto presenceServerEnabled = presenceSection->get<ConfigBoolean>("enabled")->read();
	if (presenceServerEnabled) {
		sofiasip::Home home{};
		auto presenceServer = presenceSection->get<ConfigString>("presence-server")->read();
		const auto* contact = sip_contact_make(home.home(), presenceServer.c_str());
		const auto* url = contact ? contact->m_url : nullptr;
		if (url && url->url_host) {
			BinaryIp::emplace(mTrustedHosts, url->url_host);
			SLOGI << "Added presence server '" << url->url_host << "' to trusted hosts";
		} else {
			SLOGW << "Could not parse presence server URL '" << presenceServer
			      << "', cannot be added to trusted hosts!";
		}
	}
	for (const auto& trustedHost : mTrustedHosts) {
		SLOGI << "IP " << trustedHost << " added to trusted hosts";
	}
}

void ModuleAuthTrustedHosts::onRequest(shared_ptr<RequestSipEvent>& ev) {
	sip_t* sip = ev->getMsgSip()->getSip();
	sip_via_t* via = sip->sip_via;
	const char* printableReceivedHost = !isEmpty(via->v_received) ? via->v_received : via->v_host;
	BinaryIp receivedHost{printableReceivedHost};
	if (mTrustedHosts.find(receivedHost) != mTrustedHosts.end()) ev->setTrustedHost();
}

void ModuleAuthTrustedHosts::onResponse(shared_ptr<ResponseSipEvent>&) {
}

} // namespace flexisip
