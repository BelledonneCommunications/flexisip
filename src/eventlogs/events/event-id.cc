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

#include <string>

#include "utils/digest.hh"

namespace flexisip {

using namespace std;

EventId::EventId(const sip_t& sip)
    : mHash([&sip] {
	      const auto* fromUrl = sip.sip_from->a_url;
	      auto first = string(fromUrl->url_user);
	      first.append(fromUrl->url_host);

	      const auto* toUrl = sip.sip_to->a_url;
	      auto second = string(toUrl->url_user);
	      second.append(toUrl->url_host);

	      if (second < first) first.swap(second);

	      first.append(second);
	      first.append(sip.sip_call_id->i_id);

	      return Sha256{}.compute<string>(first);
      }()) {
}

EventId::EventId(std::string_view id) : mHash(id) {
}

} // namespace flexisip