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

#include "message-kind.hh"

#include "flexisip/logmanager.hh"
#include "utils/uri-utils.hh"

using namespace std::string_view_literals;

namespace flexisip {

MessageKind::MessageKind(const ::sip_t& event, sofiasip::MsgSipPriority priority)
    : mKind(Kind::Message), mCardinality(Cardinality::Direct), mPriority(priority) {
	if (event.sip_request->rq_method == sip_method_refer) mKind = Kind::Refer;

	constexpr auto tryExtractConferenceIdFrom = [](const auto& recipient) {
		return UriUtils::getConferenceId(*recipient.a_url);
	};

	mConferenceId = tryExtractConferenceIdFrom(*event.sip_from);
	if (mConferenceId) {
		mCardinality = Cardinality::FromConferenceServer;
		return;
	}

	mConferenceId = tryExtractConferenceIdFrom(*event.sip_to);
	if (mConferenceId) {
		mCardinality = Cardinality::ToConferenceServer;
	}
}

} // namespace flexisip