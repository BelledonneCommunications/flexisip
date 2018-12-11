/*
 Flexisip, a flexible SIP proxy server with media capabilities.
 Copyright (C) 2018  Belledonne Communications SARL, All rights reserved.

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

#include <map>
#include <string>

/**
 * @brief Factor new strings basing on a template and a map of key-value.
 *
 * The template is a string that contains substitution variables, which
 * will be replaced on string creation. Each substitution variable is composed
 * by a '$' character followed by the name of the variable. Only alphanumeric
 * character and '-' are valid in variable names.
 *
 * @warning All the characters after a '$' will be taken as variable name until a character
 * not suitable for name is encountered.
 */
class StringFormater {
public:
	StringFormater(const std::string &_template = "") : mTemplate(_template) {}

	void setTemplate(const std::string &_template) {mTemplate = _template;}
	const std::string &getTemplate() const {return mTemplate;}

	/**
	 * @brief Create a new string.
	 *
	 * @param values A map associating a variable name with the value by which
	 * the variable will be replaced.
	 * @return The new string.
	 *
	 * An std::invalid_argument exception it thrown if a value couldn't be found in
	 * the map for a variable.
	 */
	std::string format(const std::map<std::string, std::string> &values) const;

private:
	static bool isKeywordChar(char c);

	std::string mTemplate;
};


/**
 * @brief Specialization of StringFormater that escapes the reserved characters
 * of each value of the map before replacement in order to be valid for an HTTP URI.
 */
class HttpUriFormater: public StringFormater {
public:
	std::string format(const std::map<std::string, std::string> &values) const;

private:
	static std::map<std::string, std::string> escape(const std::map<std::string, std::string> &values);
};
