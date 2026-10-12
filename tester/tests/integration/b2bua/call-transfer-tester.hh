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

#include <string>
#include <utility>

#include "flexisip/utils/sip-uri.hh"
#include "utils/string-formatter.hh"

namespace flexisip::tester {
namespace {

// Domain on which a client is registered.
enum class Domain { Flexisip, External };

const std::string kFlexisipDomain = "flexisip.example.org";
const std::string kExternalDomain = "external.example.org";

// Name of the given domain, as used in SIP URIs.
[[nodiscard]] const std::string& domainName(Domain domain) {
	return domain == Domain::Flexisip ? kFlexisipDomain : kExternalDomain;
}

/*
 * Whether clients registered on the Flexisip domain dial their callee with its username on the external domain, as
 * customers do.
 */
enum class ExternalUsernameDialing { Disabled, Enabled };

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

	/*
	 * URI that the given caller dials to reach the given callee.
	 * When the external username dialing is enabled and the caller is registered on Flexisip, the INVITE it emits uses
	 * the username of the callee account on the external domain.
	 */
	[[nodiscard]] SipUri dialUri(const CallTransferAccount& caller, ExternalUsernameDialing dialing) const {
		if (dialing == ExternalUsernameDialing::Enabled) {
			return SipUri{std::string{"sip:"} + mUsernameOnExternal + "@" + domainName(caller.mDomain)};
		}
		return uriOn(caller.mDomain);
	}

	/*
	 * SIP identity of the current account as seen from the given domain, once the call has been bridged.
	 * When the external username dialing is enabled, the username seen on the Flexisip side is the one on the external
	 * domain: the bridge account uri supersedes the alias.
	 */
	[[nodiscard]] SipUri seenUriOn(Domain domain, ExternalUsernameDialing dialing) const {
		if (dialing == ExternalUsernameDialing::Enabled) {
			return SipUri{std::string{"sip:"} + mUsernameOnExternal + "@" + domainName(domain)};
		}
		return uriOn(domain);
	}

	[[nodiscard]] const std::string& domain() const {
		return domainName(mDomain);
	}

	const Domain mDomain;
	const std::string mUsernameOnFlexisip;
	const std::string mUsernameOnExternal;
};

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
const StringFormatter kCallTransferProvidersConfiguration{
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

const StringFormatter kB2buaProviderAccountConfiguration{
    R"json(
{
    "uri": "sip:#userNameOnExternal#@#externalDomain#",
    "alias": "sip:#userNameOnFlexisip#@#internalDomain#"
})json",
    '#',
    '#',
};

// User: "Transferee"
const CallTransferAccount kTransfereeIntern{"transferee", Domain::Flexisip};
const CallTransferAccount kTransfereeExtern{"transferee", Domain::External};
const CallTransferAccount kTransfereeInternD{"transferee", "eerefsnart"};
// User: "Transferor"
const CallTransferAccount kTransferorIntern{"transferor", Domain::Flexisip};
const CallTransferAccount kTransferorExtern{"transferor", Domain::External};
const CallTransferAccount kTransferorInternD{"transferor", "rorefsnart"};
// User: "TransferTarget"
const CallTransferAccount kTransferTIntern{"transferTarget", Domain::Flexisip};
const CallTransferAccount kTransferTExtern{"transferTarget", Domain::External};
const CallTransferAccount kTransferTInternD{"transferTarget", "tegraTrefsnart"};

} // namespace
} // namespace flexisip::tester