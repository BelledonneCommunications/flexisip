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


#ifndef h264filter_hh
#define h264filter_hh

#include "mediarelay.hh"

class H264IFrameFilter : public MediaFilter{
public:
	H264IFrameFilter(int skipcount);
	///Should return false if the incoming packet must not be transfered.
	bool onIncomingTransfer(uint8_t *data, size_t size, const sockaddr *addr, socklen_t addrlen);
	///Should return false if the packet output must not be sent.
	bool onOutgoingTransfer(uint8_t *data, size_t size, const sockaddr *addr, socklen_t addrlen);
private:
	int mSkipCount;
	uint32_t mLastIframeTimestamp;
	int mIframeCount;
	
};



#endif

