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

#include "account-json.hh"

namespace flexisip::flexiapi {

void ResolvedUri::JsonDeserializer::fromJson(const nlohmann::json& j, ResolvedUri& r) {
	r.type = j.at("type").get<UriType>();

	if (r.type == UriType::Account) {
		r.mAccount = j.at("payload").get<Account>();
	} else if (r.type == UriType::Group) {
		r.mGroup = j.at("payload").get<Group>();
	}
}

void from_json(const nlohmann::json& j, Account& a) {
	a.id = j.at("id").get<int>();
	a.call_forwardings = j.at("call_forwardings").get<std::vector<CallForwarding>>();
	try {
		a.sip_uri = j.at("sip_uri").get<SipUri>();
	} catch (const sofiasip::InvalidUrlError& e) {
		throw nlohmann::json::parse_error::create(101, 0, "Invalid SIP URI format in JSON: " + std::string(e.what()),
		                                          &j);
	}
}

void to_json(nlohmann::json& nlohmann_json_j, const Account& nlohmann_json_t) {
	nlohmann_json_j["id"] = nlohmann_json_t.id;
}

void from_json(const nlohmann::json& j, CallForwarding& c) {
	c.type = j.at("type").get<CallForwarding::Type>();
	c.forward_to = j.at("forward_to").get<CallForwarding::ForwardType>();
	c.enabled = j.at("enabled").get<bool>();

	try {
		switch (c.forward_to) {
			using enum CallForwarding::ForwardType;
			case Contact:
				c.sip_uri = j.at("contact_sip_uri").get<flexisip::SipUri>();
				break;
			case SipUri:
				c.sip_uri = j.at("sip_uri").get<flexisip::SipUri>();
				break;
			case Voicemail:
				break;
		}
	} catch (const sofiasip::InvalidUrlError& e) {
		throw nlohmann::json::parse_error::create(101, 0, "Invalid SIP URI format in JSON: " + std::string(e.what()),
		                                          &j);
	}
}

} // namespace flexisip::flexiapi