/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023  Belledonne Communications SARL, All rights reserved.

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

#pragma once

#include <utility>

#include <sofia-sip/msg_header.h>

#include "flexisip/sofia-wrapper/home.hh"

namespace sofiasip {

/**
 * Base class for all SIP header classes.
 * It is actually a wrapper for the SofiaSip msg_header_t type.
 * Every header are copy-constructable and move-constructable.
 */
class SipHeader {
protected:
	friend class MsgSip;

	SipHeader() = default;
	SipHeader(const SipHeader& src) {
		mNativePtr = msg_header_dup(mHome.home(), src.mNativePtr);
	}
	SipHeader(SipHeader&& src) {
		mHome = std::move(src.mHome);
		mNativePtr = src.mNativePtr;
		src.mNativePtr = nullptr;
	}
	virtual ~SipHeader() = default;

	template <typename HeaderT>
	void setNativePtr(HeaderT* header) {
		mNativePtr = reinterpret_cast<msg_header_t*>(header);
	}

	Home mHome{};
	msg_header_t* mNativePtr{nullptr};
};

} // namespace sofiasip
