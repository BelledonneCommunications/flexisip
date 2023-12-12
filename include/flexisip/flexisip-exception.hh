/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023 Belledonne Communications SARL, All rights reserved.

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

#pragma once

#include <stdexcept>
#include <string>
#include <string_view>

#include "sofia-sip/sip_status.h"

#include <bctoolbox/exception.hh>

namespace flexisip {

/**
 * @brief This exception inherits \ref BctoolboxException.
 *
 *
 */
class FlexisipException : public BctbxException {
public:
	FlexisipException() = default;
	FlexisipException(const std::string& message) : BctbxException(message) {
	}
	FlexisipException(const char* message) : BctbxException(message) {
	}
	virtual ~FlexisipException() throw() {
	}
	FlexisipException(const FlexisipException& other) : BctbxException(other) {
	}

	template <typename T2>
	FlexisipException& operator<<(const T2& val) {
		BctbxException::operator<<(val);
		return *this;
	}
};

#define FLEXISIP_EXCEPTION FlexisipException() << " " << __FILE__ << ":" << __LINE__ << " "

/**
 * @brief Sip response class.
 *
 */
class SipStatus {
public:
	SipStatus(int code, std::string_view phrase) : mCode(code), mReason(phrase) {
	}
	int getCode() const {
		return mCode;
	}
	const char* getReason() const {
		return mReason.c_str();
	}

private:
	int mCode;
	std::string mReason;
};

/**
 * @brief This exception reports all sip errors.
 *
 */
class GenericSipException : public std::runtime_error {
public:
	GenericSipException(int statusCode, std::string_view statusPhrase)
	    : GenericSipException(statusCode, statusPhrase, "") {
	}
	GenericSipException(int statusCode, std::string_view statusPhrase, std::string_view additionalMsg)
	    : std::runtime_error(statusPhrase.data()), mSipStatus(statusCode, statusPhrase), mMsg(statusPhrase) {
		if (!additionalMsg.empty()) mMsg += std::string(": ") + additionalMsg.data();
	}
	virtual ~GenericSipException() = default;
	void addLocation(const char* file, int line) {
		mMsg = std::string("Exception in ") + file + ":" + std::to_string(line) + " " + mMsg;
	}
	virtual const SipStatus& getSipStatus() const noexcept {
		return mSipStatus;
	};
	virtual const char* what() const noexcept override {
		return mMsg.data();
	};

private:
	const SipStatus mSipStatus;
	std::string mMsg;
};

/**
 * @brief This exception inherits \ref GenericSipException and reports client errors on request.
 *
 */
class InvalidRequestError : public GenericSipException {
public:
	InvalidRequestError() : InvalidRequestError("") {
	}
	InvalidRequestError(std::string_view additionalMsg) : GenericSipException(SIP_400_BAD_REQUEST, additionalMsg) {
	}
	InvalidRequestError(std::string_view reasonSuffix, std::string_view additionalMsg)
	    : GenericSipException(400, std::string(sip_status_phrase(400)) + " - " + reasonSuffix.data(), additionalMsg) {
	}
	virtual ~InvalidRequestError() = default;
};

/**
 * @brief This exception inherits \ref GenericSipException and reports server errors.
 *
 */
class InternalError : public GenericSipException {
public:
	InternalError() : InternalError("") {
	}
	InternalError(std::string_view additionalMsg) : GenericSipException(SIP_500_INTERNAL_SERVER_ERROR, additionalMsg) {
	}
	InternalError(std::string_view reasonSuffix, std::string_view additionalMsg)
	    : GenericSipException(500, std::string(sip_status_phrase(500)) + " - " + reasonSuffix.data(), additionalMsg) {
	}
	virtual ~InternalError() = default;
};

#define THROW_LINE(myException, ...)                                                                                   \
	do {                                                                                                               \
		auto e = myException(__VA_ARGS__);                                                                             \
		e.addLocation(__FILE__, __LINE__);                                                                             \
		throw e;                                                                                                       \
	} while (false)

} // namespace flexisip
