/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
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
	static RandomStringGenerator sRsg;

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
		auto charCount = sRsg.kCharCount;
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
