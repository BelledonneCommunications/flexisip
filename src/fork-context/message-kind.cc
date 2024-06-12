/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
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
