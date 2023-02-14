/*
 Flexisip, a flexible SIP proxy server with media capabilities.
 Copyright (C) 2012  Belledonne Communications SARL.

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU Affero General Public License as
 published by the Free Software Foundation, either version 3 of the
 License, or (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU Affero General Public License for more details.

 You should have received a copy of the GNU Affero General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "telephone-event-filter.hh"
#include <ortp/rtp.h>

using namespace flexisip;

TelephoneEventFilter::TelephoneEventFilter(int telephone_event_pt) : mTelephoneEventPt(telephone_event_pt) {
}

bool TelephoneEventFilter::onIncomingTransfer(uint8_t *data, size_t size, [[maybe_unused]] const struct sockaddr *sockaddr,
											 [[maybe_unused]] socklen_t addrlen) {
	rtp_header_t *h = (rtp_header_t *)data;
	if (size < sizeof(rtp_header_t))
		return true;
	if (h->paytype == mTelephoneEventPt) {
		LOGD("Detected telephone event in stream, dropping.");
		return false;
	}
	return true;
}

bool TelephoneEventFilter::onOutgoingTransfer([[maybe_unused]] uint8_t *data, [[maybe_unused]] size_t size, [[maybe_unused]] const struct sockaddr *sockaddr,
											  [[maybe_unused]] socklen_t addrlen) {
	return true;
}
