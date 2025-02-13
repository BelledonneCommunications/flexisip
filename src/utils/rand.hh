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

#include <cstdlib>
#include <ctime>
#include <memory>
#include <random>
#include <set>
#include <string>
#include <vector>

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
	[[deprecated("Use Random instead")]] static int generate(int min = 0, int max = RAND_MAX) noexcept;
	/**
	 * Randomly generate a character from a class of characters.
	 * @param aAllowedChars A class of characters that defines the allowed
	 * characters to return.
	 */
	[[deprecated("Use Random instead")]] static char generate(const CharClass& aAllowedChars) noexcept;
	/**
	 * Randomly generate a string.
	 * @param aLength Size of the string to generate.
	 * @param aAllowedChars Character class of allowed characters in the string.
	 */
	[[deprecated("Use Random instead")]] static std::string generate(std::size_t aLength,
	                                                                 const CharClass& aAllowedChars);

private:
	/**
	 * @brief Initialize the seed if it has never been done.
	 */
	static void makeSeed() noexcept;

	static bool sSeeded; /**< True if the seed has been initialized, False otherwise. */
};

/**
 * Tool for creating random generators.
 * @note if no seed is given at construction, seeds itself from the system's random source
 * @warning created generators use the same random engine instance as the 'Random' instance, so their lifetimes are
 * linked
 */
class Random {
public:
	using Engine = std::default_random_engine;

	class StringGenerator;

	/**
	 * Generates random integers in the provided range.
	 */
	template <typename Type>
	class IntGenerator {
	public:
		// Make it more difficult to accidentally outlive the referenced `Random` instance.
		IntGenerator() = delete;
		IntGenerator(IntGenerator&) = delete;

		/**
		 * @param engine reference to a random engine instance
		 * @param min lower bound
		 * @param max upper bound (included)
		 */
		IntGenerator(Engine& engine, Type min, Type max) : mEngine(engine), mDistribution(min, max) {
		}

		Type generate() {
			return mDistribution(mEngine);
		}

	private:
		Engine& mEngine;
		std::uniform_int_distribution<Type> mDistribution;
	};

	/**
	 * Generates random real numbers (floating point numbers) in the provided range.
	 */
	template <typename Type>
	class RealGenerator {
	public:
		// Make it more difficult to accidentally outlive the referenced `Random` instance.
		RealGenerator() = delete;
		RealGenerator(RealGenerator&) = delete;

		/**
		 * @param engine reference to a random engine instance
		 * @param min lower bound
		 * @param max upper bound (excluded)
		 */
		RealGenerator(Engine& engine, Type min, Type max) : mEngine(engine), mDistribution(min, max) {
		}

		Type generate() {
			return mDistribution(mEngine);
		}

	private:
		Engine& mEngine;
		std::uniform_real_distribution<Type> mDistribution;
	};

	/**
	 * Generates random strings of varying lengths with uniform probability across the provided alphabet.
	 */
	class StringGenerator {
	public:
		// Make it more difficult to accidentally outlive the referenced `Random` instance.
		StringGenerator() = delete;
		StringGenerator(StringGenerator&) = delete;

		/**
		 * @param engine reference to a random engine instance
		 * @param alphabet set of characters
		 */
		StringGenerator(Engine& engine, std::string_view alphabet)
		    : mIntGenerator(engine, 0, alphabet.size() - 1 /* array indexing starts at 0 and dist() is inclusive */),
		      mAlphabet(alphabet) {
		}

		/**
		 * @param length length of the generated string
		 */
		std::string generate(std::size_t length) {
			std::string result(length, '\0');

			for (char& c : result)
				c = mAlphabet[mIntGenerator.generate()];

			return result;
		}

	private:
		IntGenerator<size_t> mIntGenerator;
		const std::string_view mAlphabet;
	};

	explicit Random(Engine::result_type seed = std::random_device()());

	/**
	 * @param min lower bound
	 * @param max upper bound (included)
	 * @return integer generator
	 */
	template <class Type>
	IntGenerator<Type> integer(Type min = std::numeric_limits<Type>::min(),
	                           Type max = std::numeric_limits<Type>::max()) & {
		return IntGenerator<Type>{mEngine, min, max};
	}

	/**
	 * Generates timestamps (up to year 2038).
	 */
	using TimestampGenerator = IntGenerator<std::time_t>;

	/**
	 * @param max maximum timestamp (defaults to year 2038 because MySql (TIMESTAMP) does not support dates beyond)
	 * @return timestamp in the provided range
	 */
	TimestampGenerator timestamp(std::time_t min = 0, std::time_t max = (2038 - 1970) * 365 * 24 * 60 * 60) &;

	/**
	 * Generates random boolean values.
	 */
	using BooleanGenerator = IntGenerator<int>;

	BooleanGenerator boolean() &;

	/**
	 * @param min lower bound
	 * @param max upper bound (excluded)
	 * @return real generator
	 */
	template <class Type>
	RealGenerator<Type> real(Type min = std::numeric_limits<Type>::min(),
	                         Type max = std::numeric_limits<Type>::max()) & {
		return RealGenerator<Type>{mEngine, min, max};
	}

	/**
	 * @param alphabet set of characters (default is base64url alphabet as defined in RFC 4648 §5)
	 * @return string generator
	 */
	StringGenerator
	string(std::string_view alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") &;

	std::default_random_engine mEngine;
};

} // namespace flexisip