/*
 * Flexisip, a flexible SIP proxy server with media capabilities.
 * Copyright (C) 2021 Belledonne Communications SARL, All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include <sofia-sip/sip_extra.h>

#include <flexisip/logmanager.hh>

#include "from-domain-authentifier.hh"

using namespace std;

namespace flexisip {

void FromDomainAuthentifier::verify(const std::shared_ptr<AuthStatus>& as) {
	auto sip = as->mEvent->getSip();
	auto fromDomain = sip->sip_from->a_url[0].url_host;
	if (fromDomain && strcmp(fromDomain, "anonymous.invalid") == 0) {
		auto ppi = sip_p_preferred_identity(sip);
		if (ppi) fromDomain = ppi->ppid_url->url_host;
		else {
			LOGD("There is no p-preferred-identity");
		}
	}

	if (!checkDomain(fromDomain)) {
		SLOGI << "Registration failure, domain is forbidden: " << fromDomain;
		as->as_status = 403;
		as->as_phrase = "Domain forbidden";
		notify(as, Authentifier::Status::Reject);
	} else {
		continue_(as);
	}
}

bool FromDomainAuthentifier::checkDomain(const std::string& domain) const noexcept {
	if (find_if(mTrustedDomains.cbegin(), mTrustedDomains.cend(),
				[&domain](const auto &d) { return d == domain || d == "*"; }) != mTrustedDomains.cend()) {
		return true;
	}

	for (const auto &authDomain : mTrustedDomains) {
		auto wildcardPosition = authDomain.find('*');
		// if domain has a wildcard in it, try to match
		if (wildcardPosition != string::npos) {
			auto beforeWildcard = domain.find(authDomain.substr(0, wildcardPosition));
			auto afterWildcard = domain.rfind(authDomain.substr(wildcardPosition + 1));
			if (beforeWildcard == 0 && afterWildcard > wildcardPosition) { return true; }
		}
	}

	return false;
}

}
