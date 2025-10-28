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

#include "utils/uri-utils.hh"

namespace flexisip {

MessageKind::MessageKind(const ::sip_t& event, sofiasip::MsgSipPriority priority)
    : mCardinality(Cardinality::Direct), mPriority(priority) {
	mConferenceId = uri_utils::getConferenceId(*event.sip_from->a_url);
	if (mConferenceId) {
		mCardinality = Cardinality::FromConferenceServer;
		return;
	}
	mConferenceId = uri_utils::getConferenceId(*event.sip_to->a_url);
	if (mConferenceId) {
		mCardinality = Cardinality::ToConferenceServer;
	}
}

MessageKind::Cardinality MessageKind::getCardinality() const {
	return mCardinality;
}

sofiasip::MsgSipPriority MessageKind::getPriority() const {
	return mPriority;
}

const std::optional<std::string>& MessageKind::getConferenceId() const {
	return mConferenceId;
}

} // namespace flexisip