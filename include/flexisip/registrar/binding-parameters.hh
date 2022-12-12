/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <cstdint>
#include <functional>
#include <string>

#include <sofia-sip/url.h>

namespace flexisip {

struct BindingParameters {
	bool alias = false; /* < Indicates whether the Contact supplied is an alias, which means it has to be recursed
	           during fetch() operations. */
	bool withGruu = false;
	int globalExpire = 0;
	int version = 0;
	int32_t cSeq = -1; // Negative means no CSeq
	std::string callId = "";
	std::string path = "";
	std::string userAgent = "";
	/* when supplied, the isAliasFunction() overrides the "alias" setting on a per-contact basis.*/
	std::function<bool(const url_t*)> isAliasFunction;
};

} // namespace flexisip
