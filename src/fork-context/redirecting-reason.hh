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

namespace flexisip {

/**
 * Redirecting Reasons and the SIP status codes bound to them, as defined by RFC 4458 (§ 2.2).
 * The status code of a reason is the value to send in the 'cause' URI parameter when a call is diverted to a voicemail.
 */
enum class RedirectingReason {
	Unknown,
	UserBusy,
	NoReply,
	Unconditional,
	DeflectionDuringAlerting,
	DeflectionImmediateResponse,
	MobileNotReachable,
};

/** SIP status code bound to the given Redirecting Reason (RFC 4458 § 2.2). */
constexpr int toValue(RedirectingReason reason) {
	switch (reason) {
		using enum RedirectingReason;
		case Unknown:
			return 404;
		case UserBusy:
			return 486;
		case NoReply:
			return 408;
		case Unconditional:
			return 302;
		case DeflectionDuringAlerting:
			return 487;
		case DeflectionImmediateResponse:
			return 480;
		case MobileNotReachable:
			return 503;
		default:
			return toValue(Unconditional);
	}
}

inline std::string toString(RedirectingReason reason) {
	switch (reason) {
		using enum RedirectingReason;
		case Unknown:
			return "Unknown/Not available";
		case UserBusy:
			return "User busy";
		case NoReply:
			return "No reply";
		case Unconditional:
			return "Unconditional";
		case DeflectionDuringAlerting:
			return "Deflection during alerting";
		case DeflectionImmediateResponse:
			return "Deflection immediate response";
		case MobileNotReachable:
			return "Mobile subscriber not reachable";
		default:
			return "Invalid RedirectingReason";
	}
}

/**
 * Translate a SIP status code received on a branch into the Redirecting Reason it matches.
 * Only some received codes have an explicit mapping: any other code falls back to 'Unconditional', as mandated
 * by RFC 4458 (§ 2.2) for values with no appropriate mapping. As a consequence, the reasons that are not bound
 * to a mapped code (Unknown, Unconditional, the Deflection reasons, MobileNotReachable) have no producer here.
 */
constexpr RedirectingReason codeToRedirectingReason(int code) {
	switch (code) {
		case 408:
		case 480:
			return RedirectingReason::NoReply;
		case 486:
		case 603:
			return RedirectingReason::UserBusy;
		default:
			return RedirectingReason::Unconditional;
	}
}
} // namespace flexisip
