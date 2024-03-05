/** Copyright (C) 2010-2024 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "contact-key.hh"

namespace flexisip {

RandomStringGenerator ContactKey::sRsg{}; // String generator is automatically seeded here
constexpr const char ContactKey::kAutoGenTag[];

std::string ContactKey::generateUniqueId() {
	constexpr auto size = requiredCharCountForUniqueness();
	return sRsg(size);
}

bool ContactKey::isPlaceholder() const {
	return mIsPlaceholder;
}

} // namespace flexisip
