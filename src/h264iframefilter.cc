/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2010-2015  Belledonne Communications SARL, All rights reserved.

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

#include <stdint.h>
#include <bctoolbox/defs.h>
#include "h264iframefilter.hh"

#define TYPE_IDR 5
#define TYPE_SPS 7
#define TYPE_PPS 8
#define TYPE_FU_A 28   /*fragmented unit 0x1C*/
#define TYPE_STAP_A 24 /*single time aggregation packet  0x18*/

static inline uint8_t nal_header_get_type(const uint8_t *h) {
	return (*h) & ((1 << 5) - 1);
}

using namespace flexisip;

H264IFrameFilter::H264IFrameFilter(int skipcount) : mSkipCount(skipcount), mLastIframeTimestamp(0), mIframeCount(0) {
}

bool H264IFrameFilter::onOutgoingTransfer(uint8_t *data, size_t size, [[maybe_unused]] const sockaddr *addr, [[maybe_unused]] socklen_t addrlen) {
	const uint8_t *p = data;
	bool ret = false;
	bool isIFrame = false;
	if (size < 16)
		return true; // not a RTP h264 packet probably
	uint32_t ts = ntohl(((uint32_t *)p)[1]);
	p += 12;
	uint8_t ptype = nal_header_get_type(p);
	switch (ptype) {
		case TYPE_IDR:
			isIFrame = true;
			BCTBX_NO_BREAK;
		case TYPE_PPS:
		case TYPE_SPS:
			ret = true;
			break;
		case TYPE_FU_A: {
			// need to go deeper in the packet
			p++;
			switch (nal_header_get_type(p)) {
				case TYPE_IDR:
					isIFrame = true;
					BCTBX_NO_BREAK;
				case TYPE_PPS:
				case TYPE_SPS:
					ret = true;
					break;
				default:
					break;
			}
		} break;
		case TYPE_STAP_A:
			LOGW("H264 STAP-A packets not properly handled.");
			ret = true; // anyway these are usually small NALs
			break;
		default:
			break;
	}
	if (isIFrame) {
		if (mLastIframeTimestamp != ts || mIframeCount == 0) {
			LOGD("Seeing a new I-frame");
			mLastIframeTimestamp = ts;
			mIframeCount++;
		}
		if ((mIframeCount - 1) % mSkipCount != 0)
			ret = false;
	}

	return ret;
}

bool H264IFrameFilter::onIncomingTransfer([[maybe_unused]] uint8_t *data, [[maybe_unused]] size_t size, [[maybe_unused]] const sockaddr *addr, [[maybe_unused]] socklen_t addrlen) {
	return true;
}
