/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <stdexcept>
#include <utility>

namespace flexisip {
namespace pushnotification {

// Base class for PN-related errors
class PushNotificationError : public std::invalid_argument {
public:
	template <typename... Args>
	PushNotificationError(Args... args) : std::invalid_argument(std::forward<Args>(args)...) {
	}
};

} // namespace pushnotification
} // namespace flexisip
