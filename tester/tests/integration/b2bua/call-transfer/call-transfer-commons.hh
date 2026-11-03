/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2026 Belledonne Communications SARL, All rights reserved.

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

#pragma once

#include <string>
#include <utility>

#include "flexisip/utils/sip-uri.hh"
#include "tests/integration/b2bua/utils.hh"
#include "utils/string-formatter.hh"

namespace flexisip::tester {

struct Settings {
	StringFormatter providersConfig;
	std::string b2buaFilter{"true"};
};

// Name of the given domain, as used in SIP URIs.
[[nodiscard]] inline const std::string& domainName(Domain domain) {
	return domain == Domain::Flexisip ? kFlexisipDomain : kExternalDomain;
}

/*
 * Account used by a call transfer test.
 */
class CallTransferAccount {
public:
	/**
	 * Constructor for a call transfer account.
	 * No need to provide the domain, as it is always Flexisip for this constructor (only Flexisip/B2bua-managed
	 * accounts can have a different username on the external domain).
	 *
	 * @param usernameOnFlexisip The username of the account on the Flexisip domain.
	 * @param usernameOnExternal The username of the account on the External domain.
	 */
	CallTransferAccount(std::string usernameOnFlexisip, std::string usernameOnExternal)
	    : mDomain(Domain::Flexisip), mUsernameOnFlexisip(std::move(usernameOnFlexisip)),
	      mUsernameOnExternal(std::move(usernameOnExternal)) {}

	/**
	 * Constructor for a call transfer account with the same username on both domains.
	 *
	 * @param username The username of the account on both the Flexisip and external domains.
	 * @param domain The domain on which the account is registered.
	 */
	CallTransferAccount(std::string username, Domain domain)
	    : mDomain(domain), mUsernameOnFlexisip(username), mUsernameOnExternal(std::move(username)) {}

	/*
	 * SIP identity of the given account on the given domain.
	 * Accounts registered on Flexisip are bridged: their identity on the external domain is their bridge account uri.
	 * Accounts registered on the external domain have no bridge account: they keep their username on the Flexisip side.
	 */
	[[nodiscard]] SipUri uriOn(Domain domain) const {
		const auto& username =
		    (domain == Domain::Flexisip and mDomain == Domain::Flexisip) ? mUsernameOnFlexisip : mUsernameOnExternal;
		return SipUri{std::string{"sip:"} + username + "@" + domainName(domain)};
	}

	// SIP identity the account registers with.
	[[nodiscard]] SipUri uri() const {
		return uriOn(mDomain);
	}

	[[nodiscard]] const std::string& domain() const {
		return domainName(mDomain);
	}

	const Domain mDomain;
	const std::string mUsernameOnFlexisip;
	const std::string mUsernameOnExternal;
};

namespace blind {

void successful(const Settings&, const CallTransferAccount&, const CallTransferAccount&, const CallTransferAccount&);
void declined(const Settings&, const CallTransferAccount&, const CallTransferAccount&, const CallTransferAccount&);

} // namespace blind

namespace attended {

void successful(const Settings&, const CallTransferAccount&, const CallTransferAccount&, const CallTransferAccount&);
void declined(const Settings&, const CallTransferAccount&, const CallTransferAccount&, const CallTransferAccount&);

} // namespace attended

namespace test {

using Function = std::function<void(
    const Settings&, const CallTransferAccount&, const CallTransferAccount&, const CallTransferAccount&)>;

/**
 * Internal-Internal-Internal call scenario.
 */
inline void III(const Function& test,
                const Settings& settings,
                const CallTransferAccount& transfereeInt,
                const CallTransferAccount& transferorInt,
                const CallTransferAccount& transferTargetInt) {
	test(settings, transfereeInt, transferorInt, transferTargetInt);
}

/**
 * Internal-Internal-External call scenario.
 */
inline void IIE(const Function& test,
                const Settings& settings,
                const CallTransferAccount& transfereeInt,
                const CallTransferAccount& transferorInt,
                const CallTransferAccount& transferTargetExt) {
	test(settings, transfereeInt, transferorInt, transferTargetExt);
}

/**
 * Internal-External-Internal call scenario.
 */
inline void IEI(const Function& test,
                const Settings& settings,
                const CallTransferAccount& transfereeInt,
                const CallTransferAccount& transferorExt,
                const CallTransferAccount& transferTargetInt) {
	test(settings, transfereeInt, transferorExt, transferTargetInt);
}

/**
 * Internal-External-External call scenario.
 */
inline void IEE(const Function& test,
                const Settings& settings,
                const CallTransferAccount& transfereeInt,
                const CallTransferAccount& transferorExt,
                const CallTransferAccount& transferTargetExt) {
	test(settings, transfereeInt, transferorExt, transferTargetExt);
}

/**
 * External-External-Internal call scenario.
 */
inline void EEI(const Function& test,
                const Settings& settings,
                const CallTransferAccount& transfereeExt,
                const CallTransferAccount& transferorExt,
                const CallTransferAccount& transferTargetInt) {
	test(settings, transfereeExt, transferorExt, transferTargetInt);
}

/**
 * External-Internal-External call scenario.
 */
inline void EIE(const Function& test,
                const Settings& settings,
                const CallTransferAccount& transfereeExt,
                const CallTransferAccount& transferorInt,
                const CallTransferAccount& transferTargetExt) {
	test(settings, transfereeExt, transferorInt, transferTargetExt);
}

/**
 * External-Internal-Internal call scenario.
 */
inline void EII(const Function& test,
                const Settings& settings,
                const CallTransferAccount& transfereeExt,
                const CallTransferAccount& transferorInt,
                const CallTransferAccount& transferTargetInt) {
	test(settings, transfereeExt, transferorInt, transferTargetInt);
}

// No need to test External-External-External call scenario as it does not involve any interaction with the Flexisip
// domain.

} // namespace test

/*
 * Set of users involved in call transfer scenarios.
 * The 'D' stands for "distinct" usernames, used to differentiate between Flexisip and external domain accounts.
 */

// User: "Transferee"
inline const CallTransferAccount kTransfereeIntern{"transferee", Domain::Flexisip};
inline const CallTransferAccount kTransfereeExtern{"transferee", Domain::External};
inline const CallTransferAccount kTransfereeExternD{"++eerefsnart", Domain::External};
inline const CallTransferAccount kTransfereeInternD{"transferee", "++eerefsnart"};
// User: "Transferor"
inline const CallTransferAccount kTransferorIntern{"transferor", Domain::Flexisip};
inline const CallTransferAccount kTransferorExtern{"transferor", Domain::External};
inline const CallTransferAccount kTransferorExternD{"++rorefsnart", Domain::External};
inline const CallTransferAccount kTransferorInternD{"transferor", "++rorefsnart"};
// User: "TransferTarget"
inline const CallTransferAccount kTransferTargetIntern{"transferTarget", Domain::Flexisip};
inline const CallTransferAccount kTransferTargetExtern{"transferTarget", Domain::External};
inline const CallTransferAccount kTransferTargetExternD{"++tegraTrefsnart", Domain::External};
inline const CallTransferAccount kTransferTargetInternD{"transferTarget", "++tegraTrefsnart"};

/**
 * @brief Configuration to use for call transfer tests.
 *
 * Strings to replace:
 * - flexisipPort
 * - flexisipDomain
 * - externalPort
 * - externalDomain
 * - b2buaAccounts
 */
inline const StringFormatter kCallTransferProvidersConfiguration{
    R"json({
        "schemaVersion": 2,
        "providers": [
            {
                "name": "Flexisip -> External (Outbound)",
                "triggerCondition": {
                    "strategy": "Always"
                },
                "accountPool": "Accounts",
                "accountToUse": {
                    "strategy": "FindInPool",
                    "source": "sip:{from.user}@{from.hostport}",
                    "by": "{alias}"
                },
                "onAccountNotFound": "nextProvider",
                "outgoingInvite": {
                    "to": "sip:{incoming.to.user}@{account.uri.hostport}{incoming.to.uriParameters}",
                    "from": "{account.uri}"
                }
            },
            {
                "name": "External -> Flexisip (Inbound)",
                "triggerCondition": {
                    "strategy": "Always"
                },
				"accountPool": "Accounts",
                "accountToUse": {
                    "strategy": "FindInPool",
                    "source": "sip:{to.user}@{to.hostport}",
                    "by": "{uri}"
                },
                "onAccountNotFound": "nextProvider",
                "outgoingInvite": {
                    "to": "{account.alias}",
                    "from": "sip:{incoming.from.user}@{account.alias.hostport}{incoming.from.uriParameters}",
                    "outboundProxy": "<sip:127.0.0.1:#flexisipPort#;transport=tcp>"
                }
            }
        ],
        "accountPools": {
            "Accounts": {
                "outboundProxy": "<sip:127.0.0.1:#externalPort#;transport=tcp>",
                "registrationRequired": true,
                "maxCallsPerLine": 10,
                "loader": [#b2buaAccounts#]
            }
        }
    })json",
    '#',
    '#',
};

inline const StringFormatter kB2buaProviderAccountConfiguration{
    R"json(
{
    "uri": "sip:#userNameOnExternal#@#externalDomain#",
    "alias": "sip:#userNameOnFlexisip#@#internalDomain#"
})json",
    '#',
    '#',
};

/**
 * Settings for scenarios in which all calls are routed to the B2BUA.
 */
inline const Settings kAllCallsRoutedToB2bua{
    kCallTransferProvidersConfiguration,
};

/*
 * Settings for scenarios in which internal calls are not routed to the B2BUA: the module::B2bua entry filter only
 * routes the requests whose called user is a username of the external domain, i.e. a username starting with "++".
 */
inline const Settings kInternalDirectSettings{
    kCallTransferProvidersConfiguration,
    "request.uri.user regex '\\+\\+.*'",
};

} // namespace flexisip::tester