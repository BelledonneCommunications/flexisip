/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include "flexisip/sofia-wrapper/home.hh"
#include "sofia-sip/sip.h"

namespace flexisip {

class SipEventLog {
public:
	explicit SipEventLog(const sip_t&);
	SipEventLog(SipEventLog&&) = default;
	virtual ~SipEventLog() = default;

	const sip_from_t* getFrom() const {
		return mFrom;
	}
	const sip_to_t* getTo() const {
		return mTo;
	}

protected:
	sofiasip::Home mHome{};

private:
	const sip_from_t* const mFrom;
	const sip_to_t* const mTo;
};

} // namespace flexisip
