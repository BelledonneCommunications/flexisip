/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022  Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
/*
    Tools to bridge calls to other SIP providers via the Back-to-Back User Agent
    E.g. for placing PSTN calls

    NOT thread safe
*/

#pragma once

#include "b2bua-server.hh"
#include "cli.hh"
#include "linphone++/linphone.hh"
#include <regex>
#include <unordered_map>

namespace flexisip {
namespace b2bua {
namespace bridge {

class Account {
	friend class AccountManager;

	std::shared_ptr<linphone::Account> account;
	uint16_t freeSlots;

	Account(std::shared_ptr<linphone::Account>&& account, uint16_t&& freeSlots);

	bool isAvailable() const;

	// Disable copy semantics
	Account(const Account&) = delete;
	Account& operator=(const Account&) = delete;

public:
	// Move constructor
	Account(Account&& other) = default;
};

class ExternalSipProvider {
	friend class AccountManager;

	std::regex pattern;
	std::vector<Account> accounts;
	std::string name;

	ExternalSipProvider(std::string&& pattern, std::vector<Account>&& accounts, std::string&& name);

	// Disable copy semantics
	ExternalSipProvider(const ExternalSipProvider&) = delete;
	ExternalSipProvider& operator=(const ExternalSipProvider&) = delete;

public:
	// Move constructor
	ExternalSipProvider(ExternalSipProvider&& other) = default;
};

struct AccountDesc {
	std::string uri;
	std::string userid;
	std::string password;
};

struct ProviderDesc {
	std::string name;
	std::string pattern;
	std::string outboundProxy;
	bool registrationRequired;
	uint32_t maxCallsPerLine;
	std::vector<AccountDesc> accounts;
};

class AccountManager : public BridgedCallApplication, public CliHandler {
	std::vector<ExternalSipProvider> providers;
	std::unordered_map<std::string, Account*> occupiedSlots;

	void initFromDescs(linphone::Core& core, std::vector<ProviderDesc>&& provDescs);
	Account* findAccountToCall(const std::string& destinationUri);

public:
	AccountManager() {
	}

	AccountManager(linphone::Core& core, std::vector<ProviderDesc>&& provDescs);

	void init(const std::shared_ptr<linphone::Core>& core, const flexisip::GenericStruct& config) override;
	std::tuple<linphone::Reason, std::shared_ptr<const linphone::Address>>
	onCallCreate(const linphone::Call& incomingCall, linphone::CallParams& outgoingCallParams) override;
	void onCallEnd(const linphone::Call& call) override;

	std::string handleCommand(const std::string& command, const std::vector<std::string>& args) override;
};

} // namespace bridge
} // namespace b2bua
} // namespace flexisip
