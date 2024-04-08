/** Copyright (C) 2010-2024 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
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
			staticLoader.push_back({
			    .uri = std::move(account.uri),
			    .userid = std::move(account.userid),
			    .secretType = SecretType::Cleartext,
			    .secret = std::move(account.password),
			});
		}
		AccountPool accountPool{
		    .outboundProxy = std::move(provider.outboundProxy),
		    .registrationRequired = provider.registrationRequired,
		    .maxCallsPerLine = provider.maxCallsPerLine,
		    .loader = std::move(staticLoader),
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
