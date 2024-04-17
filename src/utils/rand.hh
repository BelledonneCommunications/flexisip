/*
 * Flexisip, a flexible SIP proxy server with media capabilities.
 * Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.
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
#include <set>
#include <string>
#include <vector>

#include "flexisip/logmanager.hh"

namespace flexisip {

/**
 * A class that represents a set of characters which can be used
 * as candidate characters while randomly generating strings.
 */
class CharClass {
public:
	using Size = std::string::size_type;

	/**
	 * Make an empty class.
	 */
	CharClass() = default;
	/**
	 * Make a class from a sequence of characters.
	 * Characters that are present several time in the given sequence are
	 * inserted only once in the resulting character class.
	 * @param aCList The characters to add in the class.
	 */
	template <typename CharSequenceT>
	CharClass(const CharSequenceT& aCList) noexcept {
		const std::set<char> charSet{aCList.cbegin(), aCList.cend()};
		mCharList.assign(charSet.cbegin(), charSet.cend());
	}
	/**
	 * Make a class from a list of characters intervals.
	 * @param aClass A list of characters intervals. Each interval
	 * are represented by a pair of characters which are respectively
	 * the first and the last character of the interval. In each
	 * pair, the ASCII code of the last character must be higher or
	 * equal to the code of the first one. The interval will be taken
	 * as a single character if the two value are equal.
	 * @throw std::invalid_argument if one pair has its first character
	 * strictly greater than the second one.
	 */
	CharClass(const std::vector<std::pair<char, char>>& aClass);

	/**
	 * Return a character of the class by its index.
	 */
	const char& getChar(Size i) const noexcept {
		return mCharList[i % mCharList.size()];
	}
	/**
	 * Return the number of characters in the class.
	 */
	Size getSize() const noexcept {
		return mCharList.size();
	}

private:
	std::string mCharList{};
};

/**
 * @brief An utility class to generate pseudo-random numbers
 */
class Rand {
public:
	/**
	 * @brief Generate a pseudo-random number in a given interval.
	 *
	 * This method is implemented by rand() system function. The seed
	 * is initialized from the current wall clock timestamp on the first
	 * call of this method and is never reset.
	 *
	 * @param min Lower boundary.
	 * @param max Upper boundary.
	 * @return An integer in the given boundary.
	 */
	static int generate(int min = 0, int max = RAND_MAX) noexcept;
	/**
	 * Randomly generate a character from a class of characters.
	 * @param aAllowedChars A class of characters that defines the allowed
	 * characters to return.
	 */
	static char generate(const CharClass& aAllowedChars) noexcept;
	/**
	 * Randomly generate a string.
	 * @param aLength Size of the string to generate.
	 * @param aAllowedChars Character class of allowed characters in the string.
	 */
	static std::string generate(std::size_t aLength, const CharClass& aAllowedChars);

private:
	/**
	 * @brief Initialize the seed if it has never been done.
	 */
	static void makeSeed() noexcept;

	static bool sSeeded; /**< True if the seed has been initialized, False otherwise. */
};

/* Generates random strings of given lengths with uniform probability accross .kAlphabet. If no seed is given at
 * construction, seeds itself from the system's random source. */
class RandomStringGenerator {
public:
	explicit RandomStringGenerator(std::string_view alphabet, uint_fast32_t seed = std::random_device()())
	    : mEngine(seed), mDist(0, alphabet.size() - 1 /* Array indexing starts at 0 and dist() is inclusive */),
	      mAlphabet(alphabet) {
	}

	std::string operator()(std::size_t length) {
		std::string result(length, '\0');

		for (char& c : result) {
			c = mAlphabet[mDist(mEngine)];
		}

		return result;
	}

	std::default_random_engine mEngine;

private:
	std::uniform_int_distribution<size_t> mDist;
	const std::string_view mAlphabet;
};

} // namespace flexisip
