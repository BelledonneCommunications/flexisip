/*
 * Flexisip, a flexible SIP proxy server with media capabilities.
 * Copyright (C) 2021  Belledonne Communications SARL, All rights reserved.
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

#include <regex>
#include <string>

namespace flexisip {

/**
 * @brief Interface for realm extractors.
 *
 * Realm extractors are objects that allow to deduce the digest-auth realm
 * from a SIP URI, which often come from the From header of the request to
 * authenticate.
 */
class RealmExtractor {
public:
	virtual ~RealmExtractor() = default;
	virtual std::string extract(const std::string &fromUri) noexcept = 0;
};

/**
 * @brief Realm extractor which returns the
 * same realm whatever the From-URI.
 *
 * The static realm is given while object construction.
 */
class StaticRealmExtractor : public RealmExtractor {
public:
	template <typename T>
	StaticRealmExtractor(T &&realm) : mRealm{std::forward<T>(realm)} {}
	StaticRealmExtractor(const StaticRealmExtractor &) = delete;
	StaticRealmExtractor(StaticRealmExtractor &&) = delete;

	std::string extract([[maybe_unused]] const std::string &fromUri) noexcept override {return mRealm;}

private:
	std::string mRealm{};
};

/**
 * @brief Realm extractor that searches for the
 * realm inside the From-URI by using a regular expression.
 */
class RegexRealmExtractor : public RealmExtractor {
public:
	template <typename T>
	RegexRealmExtractor(T &&regex) : mRegexStr{std::forward<T>(regex)}, mRegex{mRegexStr} {}
	RegexRealmExtractor(const RealmExtractor &) = delete;
	RegexRealmExtractor(RealmExtractor &&) = delete;

	std::string extract(const std::string &fromUri) noexcept override {
		std::smatch m{};
		LOGD("searching for realm in '%s' with '%s' as extracting regex", fromUri.c_str(), mRegexStr.c_str());
		if (!std::regex_search(fromUri, m, mRegex)) {
			return "";
		}
		auto index = m.size() == 1 ? 0 : 1;
		return m.str(index);
	}

private:
	std::string mRegexStr{};
	std::regex mRegex{};
};

} // namespace flexisip
