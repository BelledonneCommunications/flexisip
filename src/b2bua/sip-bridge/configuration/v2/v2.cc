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

#include "v2.hh"

namespace flexisip::b2bua::bridge::config::v2 {

Root fromV1(v1::Root&& v1) {
	decltype(Root::providers) providers{};
	providers.reserve(v1.size());
	decltype(Root::accountPools) accountPools{};
	accountPools.reserve(v1.size());

	for (auto& provider : v1) {
		auto poolName = "Account pool - " + provider.name;
		providers.push_back(Provider{
		    .name = std::move(provider.name),
		    .accountPool = poolName,
		    .triggerCondition =
		        trigger_cond::MatchRegex{
		            .pattern = std::move(provider.pattern),
		            .source = "${incoming.requestUri}",
		        },
		    .accountToUse = account_selection::Random{},
		    .onAccountNotFound = OnAccountNotFound::Decline,
		    .outgoingInvite =
		        {
		            .to = "sip:{incoming.requestUri.user}@{account.uri.hostport}"
		                  "{incoming.requestUri.uriParameters}",
		            .enableAvpf = provider.enableAvpf,
		            .mediaEncryption = provider.mediaEncryption,
		        },
		});

		auto staticLoader = StaticLoader{};
		staticLoader.reserve(provider.accounts.size());
		for (auto& account : provider.accounts) {
			staticLoader.push_back(Account{{
			    .uri = std::move(account.uri),
			    .userId = std::move(account.userid),
			    .secretType = SecretType::Cleartext,
			    .secret = std::move(account.password),
			}});
		}
		AccountPool accountPool{
		    .registrationRequired = provider.registrationRequired,
		    .maxCallsPerLine = provider.maxCallsPerLine,
		    .loader = std::move(staticLoader),
		    .outboundProxy = std::move(provider.outboundProxy),
		    .mwiServerUri = "",
		};
		accountPools.try_emplace(std::move(poolName), std::move(accountPool));
	}

	return {
	    .schemaVersion = 2,
	    .providers = std::move(providers),
	    .accountPools = std::move(accountPools),
	};
}

} // namespace flexisip::b2bua::bridge::config::v2