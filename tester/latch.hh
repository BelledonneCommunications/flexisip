/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2010-2021  Belledonne Communications SARL, All rights reserved.

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

#include <condition_variable>
#include <mutex>

namespace flexisip {

/**
 * This class provides a thread-coordination mechanism that allows at most an expected number of (Latch::mCount)
 * threads to block until the expected number of threads arrive at the barrier. There is no possibility to increase or
 * reset the counter, which makes the latch a single-use barrier.
 */
class Latch {
  public:
	explicit Latch(std::size_t count) : mCount{count} {
	}
	/**
	 * Decrements the counter and blocks until it reaches zero.
	 */
	void wait();

  private:
	std::condition_variable mCv;
	std::mutex              mMutex;
	std::size_t             mCount;
};

} /* namespace flexisip */
