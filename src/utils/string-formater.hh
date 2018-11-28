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

class StringFormater {
public:
	StringFormater(const std::string &_template = "") : mTemplate(_template) {}

	void setTemplate(const std::string &_template) {mTemplate = _template;}
	std::string getTemplate() const {return mTemplate;}

	std::string format(const std::map<std::string, std::string> &values) const;

private:
	static bool isKeywordChar(char c);

	std::string mTemplate;
};
