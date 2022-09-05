/*
 * Flexisip, a flexible SIP proxy server with media capabilities.
 * Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include <cstdlib>
#include <ctime>
#include <memory>
#include <random>

#include <flexisip/logmanager.hh>

namespace flexisip {

/**
 * @brief An utility class to generate pseudo-random numbers
 */
class Rand {
public:
	/**
	 * @brief Generate a pseudo-random number in a given interval.
	 *
	 * This method is implemented by rand() system function. The seed
	 * is initialised from the current wallclock timestamp on the first
	 * call of this method and is never reset.
	 *
	 * @param min Lower boundary.
	 * @param max Upper boundary.
	 * @return An integer in the given boundary.
	 */
	static int generate(int min = 0, int max = RAND_MAX) noexcept;

private:
	/**
	 * @brief Initialize the seed if it has never been done.
	 */
	static void makeSeed() noexcept;

	static bool sSeeded; /**< True if the seed has been intialized, False otherwise. */
};

/* Generates random strings of given lengths with uniform probability accross .kAlphabet. If no seed is given at
 * construction, seeds itself from the system's random source. */
class RandomStringGenerator {
public:
	// base64url alphabet as defined in RFC 4648 §5
	static constexpr const char kAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
	static constexpr const auto kCharCount = sizeof(kAlphabet) - 1; // Null-terminated string

	std::default_random_engine mEngine;
	std::uniform_int_distribution<size_t> mDist;

	explicit RandomStringGenerator(uint_fast32_t seed = std::random_device()())
	    : mEngine(seed), mDist(0, kCharCount - 1 /* Array indexing starts at 0 and dist() is inclusive */) {
	}

	std::string operator()(std::size_t length) {
		std::string result(length, '\0');

		for (char& c : result) {
			c = kAlphabet[mDist(mEngine)];
		}

		return result;
	}
};

} // namespace flexisip
