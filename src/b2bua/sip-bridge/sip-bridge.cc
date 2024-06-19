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
#include "sip-bridge.hh"

#include <fstream>
#include <iostream>

#include "lib/nlohmann-json-3-11-2/json.hpp"
#include <json/json.h>

#include "linphone++/enums.hh"
#include "linphone/misc.h"

#include "b2bua/sip-bridge/accounts/loaders/sql-account-loader.hh"
#include "b2bua/sip-bridge/accounts/loaders/static-account-loader.hh"
#include "b2bua/sip-bridge/accounts/selection-strategy/find-in-pool.hh"
#include "b2bua/sip-bridge/accounts/selection-strategy/pick-random-in-pool.hh"
#include "utils/variant-utils.hh"

using namespace std;

namespace flexisip::b2bua::bridge {

namespace {
// Name of the corresponding section in the configuration file
constexpr auto configSection = "b2bua-server::sip-bridge";
constexpr auto providersConfigItem = "providers";

// Statically define default configuration items
const auto& defineConfig = ConfigManager::defaultInit().emplace_back([](GenericStruct& root) {
	ConfigItemDescriptor items[] = {
	    {String, providersConfigItem,
	     R"(Path to a file containing the accounts to use for external SIP bridging, organised by provider, in JSON format.
Here is a template of what should be in this file:
{
	"schemaVersion": 2,
	"providers": [
		{
			"name": "<user-friendly provider name for CLI output>",
			"accountPool": "<name of an account pool described below>",
			"triggerCondition": {
				"strategy": "<MatchRegex|Always>"
				"pattern": "<MatchRegexParam: regex>"
			},
			"accountToUse": {
				"strategy": "FindInPool|Random",
				"by": "<FindInPoolParam: alias|uri>",
				"source": "<FindInPoolParam: {from}|{to}|{sip:{incoming.to.user}@{account.sipIdentity.hostport}{incoming.to.uriParameters}}>"
			},
			"onAccountNotFound": "nextProvider|decline",
			"outgoingInvite": {
				"to": "<{account.alias}|sip:{incoming.to.user}@{account.sipIdentity.hostport}{incoming.to.uriParameters}>",
				"from": "<optional: {account.sipIdentity}|{sip:{incoming.from.user}@{account.sipIdentity.hostport}{incoming.from.uriParameters}>",
				"outboundProxy": "<optional: sip:flexisip.example.org;transport=tcp>",
				"enableAvpf": <optional: true|false>,
				"mediaEncryption": "<optional: zrtp|sdes|dtls-srtp|none>"
			}
		}
	],
	"accountPools": {
		"<name of account pool>": {
			"outboundProxy": "<sip:some.provider.example.com;transport=tls>",
			"registrationRequired": <true,false>,
			"registrationThrottlingRateMs": <optional: number>,
			"unregisterOnServerShutdown": <optional: true|false>,
			"maxCallsPerLine": <number>,
			"loader": {
				"dbBackend": "<mysql|sqlite3>",
				"initQuery": "<SQL query>"
				"updateQuery": "<SQL query>",
				"connection": "<db=sip_accounts user='flexisip-b2bua' password='secret' host=db.example.org>"
			}
		},
		"<name of another account pool>": {
			"outboundProxy": "<sip:some.provider.example.com;transport=tls>",
			"registrationRequired": <true,false>,
			"registrationThrottlingRateMs": <optional: number>,
			"unregisterOnServerShutdown": <optional: true|false>,
			"maxCallsPerLine": <number>,
			"loader": [
				{
					"uri": "<sip:account1@some.provider.example.com>",
					"userid": "<optional: (e.g. an API key)>"
					"secretType": "<registrationRequiredParam: ha1|clrtxt>",
					"secret": "<registrationRequiredParam: password or API token>"
					"alias": "<optional: sip:anotherAccount1@some.provider.example.com>
					"outboundProxy": "<optional: sip:another.providerOverridingPreviousOne.example.com;transport=tls>",
				}
			]
		}
	}
})"
	     "\nFull documentation is available here: "
	     "https://wiki.linphone.org/xwiki/wiki/public/view/Flexisip/Configuration/"
	     "Back-to-back%20User%20Agent%20%28b2bua%29/SIP%20Bridge/#sip-bridge\n",
	     "example-path.json"},
	    config_item_end};

	root.addChild(make_unique<GenericStruct>(configSection, "External SIP Provider Bridge parameters.", 0))
	    ->addChildrenValues(items);
});
} // namespace

AccountPoolImplMap SipBridge::getAccountPoolsFromConfig(config::v2::AccountPoolConfigMap& accountPoolConfigMap) {
	auto accountPoolMap = AccountPoolImplMap();
	for (auto& [poolName, pool] : accountPoolConfigMap) {
		if (pool.outboundProxy.empty()) {
			LOGF("Please provide an `outboundProxy` for AccountPool '%s'", poolName.c_str());
		}
		if (pool.maxCallsPerLine == 0) {
			SLOGW << "AccountPool '" << poolName
			      << "' has `maxCallsPerLine` set to 0 and will not be used to bridge calls";
		}

		auto loader = std::unique_ptr<Loader>(nullptr);
		auto redisConf = std::optional<redis::async::RedisParameters>(std::nullopt);
		Match(pool.loader)
		    .against(
		        [&loader, &capPoolName = poolName](config::v2::StaticLoader& staticPool) {
			        if (staticPool.empty()) {
				        SLOGW << "AccountPool '" << capPoolName
				              << "' has no `accounts` and will not be used to bridge calls";
			        }

			        loader = make_unique<StaticAccountLoader>(std::move(staticPool));
		        },
		        [&loader, &redisConf, globalRootConf = mGlobalConfigRoot,
		         &suRoot = mSuRoot](config::v2::SQLLoader& sqlLoaderConf) {
			        loader = make_unique<SQLAccountLoader>(suRoot, sqlLoaderConf);

			        if (globalRootConf) {
				        redisConf.emplace(redis::async::RedisParameters::fromRegistrarConf(
				            globalRootConf->get<GenericStruct>("module::Registrar")));
			        }
		        });

		accountPoolMap.try_emplace(poolName, make_shared<AccountPool>(mSuRoot, mCore, poolName, pool, std::move(loader),
		                                                              redisConf ? &*redisConf : nullptr));
	}

	return accountPoolMap;
}

void SipBridge::initFromRootConfig(config::v2::Root rootConfig) {
	const auto accountPools = getAccountPoolsFromConfig(rootConfig.accountPools);
	providers.reserve(rootConfig.providers.size());
	for (auto& provDesc : rootConfig.providers) {
		if (provDesc.name.empty()) {
			LOGF("One of your external SIP providers has an empty `name`");
		}
		auto triggerStrat =
		    Match(provDesc.triggerCondition)
		        .against(
		            [](config::v2::trigger_cond::Always) -> std::unique_ptr<trigger_strat::TriggerStrategy> {
			            return std::make_unique<trigger_strat::Always>();
		            },
		            [&providerName = provDesc.name](const config::v2::trigger_cond::MatchRegex& matchRegex)
		                -> std::unique_ptr<trigger_strat::TriggerStrategy> {
			            if (matchRegex.pattern.empty()) {
				            LOGF("Please provide a `pattern` for provider '%s'", providerName.c_str());
			            }
			            return std::make_unique<trigger_strat::MatchRegex>(matchRegex);
		            });
		const auto& accountPoolIt = accountPools.find(provDesc.accountPool);
		if (accountPoolIt == accountPools.cend()) {
			LOGF("Please provide an existing `accountPools` for provider '%s'", provDesc.name.c_str());
		}
		auto accountStrat =
		    Match(provDesc.accountToUse)
		        .against(
		            [&pool = accountPoolIt->second](config::v2::account_selection::Random)
		                -> std::unique_ptr<account_strat::AccountSelectionStrategy> {
			            return std::make_unique<account_strat::PickRandomInPool>(pool);
		            },
		            [pool = accountPoolIt->second](const config::v2::account_selection::FindInPool& findInPool)
		                -> std::unique_ptr<account_strat::AccountSelectionStrategy> {
			            return std::make_unique<account_strat::FindInPool>(pool, findInPool);
		            });

		providers.emplace_back(SipProvider{
		    std::move(triggerStrat),
		    std::move(accountStrat),
		    provDesc.onAccountNotFound,
		    InviteTweaker(std::move(provDesc.outgoingInvite), *mCore),
		    std::move(provDesc.name),
		});
	}
}

SipBridge::SipBridge(const std::shared_ptr<sofiasip::SuRoot>& suRoot,
                     const std::shared_ptr<linphone::Core>& core,
                     config::v2::Root&& rootConf,
                     const GenericStruct* globalConfigRoot)
    : mSuRoot{suRoot}, mCore{core}, mGlobalConfigRoot(globalConfigRoot) {
	initFromRootConfig(std::move(rootConf));
}

void SipBridge::init(const shared_ptr<linphone::Core>& core, const flexisip::ConfigManager& cfg) {
	auto filePath = cfg.getRoot()->get<GenericStruct>(configSection)->get<ConfigString>(providersConfigItem)->read();
	if (filePath[0] != '/') {
		// Interpret as relative to config file
		const auto& configFilePath = cfg.getConfigFile();
		const auto configFolderPath = configFilePath.substr(0, configFilePath.find_last_of('/') + 1);
		filePath = configFolderPath + filePath;
	}
	auto fileStream = ifstream(filePath);
	constexpr auto fileDesignation = "external SIP providers JSON configuration file";
	if (!fileStream.is_open()) {
		LOGF("Failed to open %s '%s'", fileDesignation, filePath.c_str());
	}

	// Parse file
	nlohmann::json j;
	fileStream >> j;

	mCore = core;
	mGlobalConfigRoot = cfg.getRoot();

	initFromRootConfig([&j]() {
		if (j.is_array()) {
			return config::v2::fromV1(j.get<config::v1::Root>());
		}
		return j.get<config::v2::Root>();
	}());
}

b2bua::Application::ActionToTake SipBridge::onCallCreate(const linphone::Call& incomingCall,
                                                         linphone::CallParams& outgoingCallParams) {
	for (auto& provider : providers) {
		if (const auto actionToTake = provider.onCallCreate(incomingCall, outgoingCallParams, occupiedSlots)) {
			return *actionToTake;
		}
	}

	SLOGD << "No provider could handle the call to " << incomingCall.getToAddress()->asStringUriOnly();
	return linphone::Reason::NotAcceptable;
}

void SipBridge::onCallEnd(const linphone::Call& call) {
	const auto it = occupiedSlots.find(call.getCallLog()->getCallId());
	if (it == occupiedSlots.end()) return;

	if (const auto account = it->second.lock()) {
		account->releaseASlot();
	}
	occupiedSlots.erase(it);
}

string SipBridge::handleCommand(const string& command, const vector<string>& args) {
	if (command != "SIP_BRIDGE") {
		return "";
	}

	if (args.empty() || args[0] != "INFO") {
		return "Valid subcommands for SIP_BRIDGE:\n"
		       "  INFO  displays information on the current state of the bridge.";
	}

	auto providerArr = Json::Value();
	for (const auto& provider : providers) {
		auto accountsArr = Json::Value();
		for (const auto& [_, bridgeAccount] : provider.mAccountStrat->getAccountPool()) {
			const auto account = bridgeAccount->getLinphoneAccount();
			const auto params = account->getParams();
			const auto registerEnabled = params->registerEnabled();
			const auto status = [registerEnabled, account]() {
				if (!registerEnabled) {
					return string{"OK"};
				}
				const auto state = account->getState();
				switch (state) {
					case linphone::RegistrationState::Ok:
						return string{"OK"};
					case linphone::RegistrationState::None:
						return string{"Should register"};
					case linphone::RegistrationState::Progress:
						return string{"Registration in progress"};
					case linphone::RegistrationState::Failed:
						return string{"Registration failed: "} +
						       linphone_reason_to_string(static_cast<LinphoneReason>(account->getError()));
					default:
						return string{"Unexpected state: "} +
						       linphone_registration_state_to_string(static_cast<LinphoneRegistrationState>(state));
				}
			}();

			auto accountObj = Json::Value();
			accountObj["address"] = params->getIdentityAddress()->asString();
			accountObj["status"] = status;

			if (status == "OK") {
				accountObj["registerEnabled"] = registerEnabled;
				accountObj["freeSlots"] = bridgeAccount->getFreeSlotsCount();
			}

			accountsArr.append(accountObj);
		}
		auto providerObj = Json::Value();
		providerObj["name"] = provider.name;
		providerObj["accounts"] = accountsArr;
		providerArr.append(providerObj);
	}

	auto infoObj = Json::Value();
	infoObj["providers"] = providerArr;
	auto builder = Json::StreamWriterBuilder();
	return Json::writeString(builder, infoObj);
}

} // namespace flexisip::b2bua::bridge
