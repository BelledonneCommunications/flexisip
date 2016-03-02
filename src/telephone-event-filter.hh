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

#ifndef tevfilter_hh
#define tevfilter_hh

#include "mediarelay.hh"

class TelephoneEventFilter : public MediaFilter {
  public:
	TelephoneEventFilter(int telephone_event_pt);
	virtual bool onIncomingTransfer(uint8_t *data, size_t size, const struct sockaddr *sockaddr, socklen_t addrlen);
	virtual bool onOutgoingTransfer(uint8_t *data, size_t size, const struct sockaddr *sockaddr, socklen_t addrlen);

  private:
	int mTelephoneEventPt;
};

#endif
