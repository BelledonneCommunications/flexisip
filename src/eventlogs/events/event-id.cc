/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "eventlogs/events/event-id.hh"

#include <functional>
#include <sstream>
#include <string>

namespace flexisip {
using namespace std;

EventId::EventId(const sip_t& sip)
    : mHash([&sip] {
	      ostringstream concatenated{};
	      concatenated << sip.sip_call_id->i_id;
	      const auto fromUrl = sip.sip_from->a_url;
	      concatenated << fromUrl->url_user << fromUrl->url_host;
	      const auto toUrl = sip.sip_to->a_url;
	      concatenated << toUrl->url_user << toUrl->url_host;
	      return std::hash<string>{}(concatenated.str());
      }()) {
}

EventId::EventId(const std::string& id) : mHash(std::stoull(id)) {
}

} // namespace flexisip
