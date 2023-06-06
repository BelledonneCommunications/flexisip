/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <chrono>

namespace flexisip {

using Timestamp = std::chrono::time_point<std::chrono::system_clock>;

class Timestamped {
public:
	const Timestamp& getTimestamp() const {
		return mTimestamp;
	}

private:
	const Timestamp mTimestamp = std::chrono::system_clock::now();
};

} // namespace flexisip
