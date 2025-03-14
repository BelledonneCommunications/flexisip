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

#include "eventlogs/events/event-id.hh"

#include <algorithm>
#include <functional>
#include <string>

#include "utils/digest.hh"

namespace flexisip {

using namespace std;

EventId::EventId(const sip_t& sip)
    : mHash([&sip] {
	      const auto toUrl = sip.sip_to->a_url;
	      const auto fromUrl = sip.sip_from->a_url;
	      const auto toIdentity{toUrl->url_user ? toUrl->url_user : "" + "@"s + toUrl->url_host};
	      const auto fromIdentity{fromUrl->url_user ? fromUrl->url_user : "" + "@"s + fromUrl->url_host};

	      const auto sortedIdentities = minmax(toIdentity, fromIdentity);

	      return Sha256{}.compute<string>(sip.sip_call_id->i_id + sortedIdentities.first + sortedIdentities.second);
      }()) {
}

EventId::EventId(std::string_view id) : mHash(id) {
}

} // namespace flexisip