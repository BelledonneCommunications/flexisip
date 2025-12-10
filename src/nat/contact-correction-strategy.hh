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

#pragma once

#include <memory>
#include <string>

#include "agent.hh"
#include "flexisip/event.hh"
#include "nat-traversal-strategy.hh"

namespace flexisip {

/**
 * Correct the url in the "Contact" header field. This header is corrected using "rport" and "received" information
 * present in the "VIA" header field.
 */
class ContactCorrectionStrategy : public NatTraversalStrategy {
public:
	/**
	 * Utility methods for the strategy.
	 */
	class Helper {
	public:
		Helper() = delete;
		explicit Helper(const std::string& parameter);

		/**
		 * Fix the "Contact" header field present in request response.
		 */
		static void fixContactInResponse(su_home_t* home, msg_t* msg, sip_t* sip);
		/**
		 * Fix the "Contact" header field using "rport" and "received" information from the "VIA" header field.
		 */
		static void fixContactFromVia(su_home_t* home, sip_t* msg, const sip_via_t* via);
		/**
		 * Check whether the "Contact" header field needs to be fixed.
		 */
		bool contactNeedsToBeFixed(const tport_t* internalTport, const SipEvent& ev) const;

		const std::string& getContactCorrectionParameter() const;

	private:
		static constexpr std::string_view mLogPrefix{"ContactCorrectionStrategy::Helper"};

		std::string mContactCorrectionParameter;
	};

	ContactCorrectionStrategy() = delete;
	ContactCorrectionStrategy(Agent* agent, const std::string& contactCorrectionParameter);

	void preProcessOnRequestNatHelper(const RequestSipEvent& ev) const override;
	void addRecordRouteNatHelper(RequestSipEvent& ev) const override;
	void onResponseNatHelper(const ResponseSipEvent& ev) const override;
	url_t*
	getDestinationUrl(MsgSip& msg, const tport_t* incoming, const std::optional<SipUri>& lastRoute) const override;
	void addRecordRouteForwardModule(MsgSip& msg,
	                                 const tport_t* incoming,
	                                 const tport_t* outgoing,
	                                 const std::optional<SipUri>& lastRoute) const override;
	void
	addPathOnRegister(MsgSip& msg, const tport_t* incoming, const tport_t* outgoing, const char* uniq) const override;

private:
	static constexpr std::string_view mLogPrefix{"ContactCorrectionStrategy"};

	Helper mHelper;
};

} // namespace flexisip