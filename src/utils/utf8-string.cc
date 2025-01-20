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

#include "utf8-string.hh"

#include <cassert>
#include <sstream>
#include <string>

#include <iconv.h>
#include <vector>

namespace {

// Thin wrapper around iconv* functions
class IConv {
public:
	IConv(const char* toCode, const char* fromCode) : mDescriptor(iconv_open(toCode, fromCode)) {
	}
	~IConv() {
		iconv_close(mDescriptor);
	}

	IConv(const IConv&) = delete;
	IConv(IConv&&) = delete;
	IConv& operator=(const IConv&) = delete;
	IConv& operator=(IConv&&) = delete;

	size_t operator()(char** inBuf, size_t* inBytesLeft, char** outBuf, size_t* outBytesLeft) {
		return iconv(mDescriptor, inBuf, inBytesLeft, outBuf, outBytesLeft);
	}

private:
	iconv_t mDescriptor;
};

} // namespace

namespace flexisip {

namespace utils {

Utf8String::Utf8String(const std::string& source) : mData(source) {
	size_t inBytesLeft = mData.size();
	if (inBytesLeft == 0) {
		// The empty string is already valid, nothing to do.
		return;
	}

	IConv converter("UTF-8", "UTF-8");
	size_t outBytesLeft = inBytesLeft;
	char* pInBuf = &mData.front();
	assert(outBytesLeft != 0); // Trying to allocate 0-lengthed dynamically-sized array
	std::vector<char> outBuf(outBytesLeft);
	char* pOutBuf = outBuf.data();
	if (converter(&pInBuf, &inBytesLeft, &pOutBuf, &outBytesLeft) != -1UL) {
		// The whole string is valid, we're good to go.
		return;
	}

	std::ostringstream sanitized{};
	while (0 < inBytesLeft) {
		pOutBuf[0] = '\0';
		sanitized << outBuf.data() << "�";
		pOutBuf = outBuf.data();
		++pInBuf;
		--inBytesLeft;
		converter(&pInBuf, &inBytesLeft, &pOutBuf, &outBytesLeft);
	}
	pOutBuf[0] = '\0';
	sanitized << outBuf.data();

	mData = sanitized.str();
}

} // namespace utils

} // namespace flexisip