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

#pragma once

#include <string>
#include <utility>

#include "utils/rand.hh"
#include "utils/string-utils.hh"

namespace flexisip {

// String wrapper. If initialized with an empty string, will take a randomly generated placeholder value instead.
class ContactKey {
public:
	static constexpr const char kAutoGenTag[] = "fs-gen-";
	// Append this flag to the end of a contact key string to signal that it should not be interpreted as placeholder,
	// even if it starts with `kAutoGenTag`
	static constexpr const char kNotAPlaceholderFlag[] = "NOT_A_PLACEHOLDER";
	// base64url alphabet as defined in RFC 4648 §5
	static constexpr std::string_view kPlaceholderAlphabet{
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"};

	static Random sRandom;
	static Random::StringGenerator sStringGenerator;

	template <class... Args>
	ContactKey(Args&&... args) : mValue(std::forward<Args>(args)...) {
		if (const auto startOfTag = mValue.rfind(kNotAPlaceholderFlag); startOfTag != std::string::npos) {
			mIsPlaceholder = false;
			mValue.resize(startOfTag);
			return;
		}

		if (mValue.empty()) mValue = placeholder();
		mIsPlaceholder = StringUtils::startsWith(mValue, kAutoGenTag);
	}

	bool isPlaceholder() const;

	std::string& str() {
		return mValue;
	}
	const std::string& str() const {
		return mValue;
	}

	operator std::string&() {
		return mValue;
	}
	operator const std::string&() const {
		return mValue;
	}

	bool operator==(const std::string& other) const {
		return mValue == other;
	}

	static std::string generateUniqueId();

private:
	// The probability of collisions for v4 UUIDs is considered negligible for most use cases.
	// That's a collision space of 2¹²² possibilities; Which gives us an upper bound since we don't need to be
	// "universally" unique.
	static constexpr auto requiredCharCountForUniqueness() {
		auto charCount = kPlaceholderAlphabet.size();
		auto approximatePowerOf2 = 0;
		while (charCount >>= 1) {
			approximatePowerOf2 += 1;
		}
		return 122 / approximatePowerOf2;
	}

	// Generate a random unique identifier for internal use in the Registrar
	static std::string placeholder() {
		return std::string{kAutoGenTag} + generateUniqueId();
	}

	std::string mValue;
	bool mIsPlaceholder = false;
};

} // namespace flexisip