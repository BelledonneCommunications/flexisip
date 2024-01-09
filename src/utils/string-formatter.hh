/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

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

#include <functional>
#include <map>
#include <string>

/**
 * @brief Factor new strings basing on a template.
 *
 * The template is a string that contains substitution variables, which
 * will be replaced on string creation. Each substitution variable is composed
 * by a name surrounded by '{' and '}' brackets e.g. '{example}'. The name of the variable can
 * be composed by any printable ASCII characters, excepted left brace, which mark
 * the end of the variable.
 *
 * While forging the string, each variable is replaced by a string value basing on
 * a given key-value map or a translation function.
 */
// TODO: Replace with PreprocessedInterpolatedString
class StringFormatter {
public:
	/**
	 * @brief Prototype for translation functions.
	 */
	using TranslationFunc = std::function<std::string(const std::string&)>;

	StringFormatter(const std::string& _template = "", char startDelim = '{', char endDelim = '}')
	    : mStartDelim{startDelim}, mEndDelim{endDelim} {
		setTemplate(_template);
	}

	void setTemplate(const std::string& _template);
	const std::string& getTemplate() const {
		return mTemplate;
	}

	/**
	 * @brief Forge a new string from a map.
	 *
	 * @param values A map associating a variable name with the value by which
	 * the variable will be replaced.
	 * @return The new string.
	 *
	 * @throw std::invalid_argument some variable value couldn't be found
	 * in values map.
	 */
	std::string format(const std::map<std::string, std::string>& values) const;

	/**
	 * @brief Forge a new string by using a function.
	 */
	std::string format(TranslationFunc& func) const;

private:
	static std::pair<bool, std::string> checkTemplateSyntax(const std::string& _template);

	std::string mTemplate;
	char mStartDelim;
	char mEndDelim;
};

/**
 * @brief Specialization of StringFormatter that escapes the reserved characters
 * of each value of the map before replacement in order to be valid for an HTTP URI.
 */
class HttpUriFormatter : public StringFormatter {
public:
	std::string format(const std::map<std::string, std::string>& values) const;
	std::string format(TranslationFunc& func) const;

private:
	static std::map<std::string, std::string> escape(const std::map<std::string, std::string>& values);
};
