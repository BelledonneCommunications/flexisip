/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include <iostream>
#include <string>
#include <string_view>
#include <utility>

#include <sofia-sip/msg_header.h>

#include "flexisip/flexisip-exception.hh"
#include "flexisip/sofia-wrapper/home.hh"

namespace sofiasip {

/**
 * Base class for all SIP header classes.
 * It is actually a wrapper for the SofiaSip msg_header_t type.
 * Every header are copy-constructable and move-constructable.
 */
class SipHeader {
public:
	const msg_header_t* getNativePtr() const {
		return mNativePtr;
	}

protected:
	friend class MsgSip;

	SipHeader() = default;
	SipHeader(const SipHeader& src) {
		mNativePtr = msg_header_dup(mHome.home(), src.mNativePtr);
	}
	SipHeader(SipHeader&& src) noexcept {
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

/**
 * Represent a sofiasip @ref msg_param_t.
 */
class SipMsgParam {
public:
	SipMsgParam() = delete;
	/**
	 * Automatically parses the given parameter.
	 * The parameter should be formatted as "key=value".
	 *
	 * @throw flexisip::FlexisipException if the parameter is ill-formatted.
	 */
	explicit SipMsgParam(std::string_view param) : mParam(param) {
		const auto delimiterPosition = mParam.find('=');
		if (delimiterPosition == std::string::npos) {
			throw flexisip::FlexisipException{R"(parameter is ill-formatted, missing "=" character ")" +
			                                  std::string{mParam} + "\""};
		}

		mKey = mParam.substr(0, delimiterPosition);
		mValue = mParam.substr(delimiterPosition + 1, mParam.size());
	}
	SipMsgParam(const SipMsgParam& other) = default;
	SipMsgParam(SipMsgParam&& other) = default;

	/*
	 * Get raw parameter value.
	 */
	std::string_view getParam() const {
		return mParam;
	}
	std::string_view getKey() const {
		return mKey;
	}
	std::string_view getValue() const {
		return mValue;
	}

	const char* str() const {
		return mParam.data();
	}

	bool operator==(const SipMsgParam& other) const {
		return mParam == other.mParam;
	}

private:
	std::string_view mParam;
	std::string_view mKey;
	std::string_view mValue;
};

} // namespace sofiasip