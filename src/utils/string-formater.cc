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

#include <algorithm>
#include <sstream>
#include <stdexcept>

#include "uri-utils.hh"

#include "string-formater.hh"

using namespace std;

//=====================================================================================================================
// StringFormater class
//=====================================================================================================================

void StringFormater::setTemplate(const std::string &_template) {
	pair<bool, string> syntaxCheckResult = checkTemplateSyntax(_template);
	if (!syntaxCheckResult.first) {
		throw invalid_argument("invalid syntax: " + syntaxCheckResult.second);
	}
	mTemplate = _template;
}

std::string StringFormater::format(const std::map<std::string, std::string> &values) const {
	TranslationFunc func = [&values](const std::string &key) {
		try {
			return values.at(key);
		} catch (const out_of_range &){
			throw invalid_argument("invalid substitution variable {" + key + "}");
		}
	};
	return format(func);
}

std::string StringFormater::format(TranslationFunc &func) const {
	string result;
	auto it1 = mTemplate.cbegin();
	do {
		auto it2 = find(it1, mTemplate.cend(), '{');
		result.insert(result.end(), it1, it2);
		it1 = it2;
		if (it1 != mTemplate.cend()) {
			it2 = find(++it1, mTemplate.cend(), '}');
			string key(it1, it2);
			result += func(key);
			it1 = ++it2;
		}
	} while (it1 != mTemplate.cend());
	return result;
}

std::pair<bool, std::string> StringFormater::checkTemplateSyntax(const std::string &_template) {
	pair<bool, string> result(true, "");
	for (auto it = _template.cbegin(); it != _template.cend(); ) {
		it = find(it, _template.cend(), '{');
		if (it != _template.cend()) {
			it = find(it, _template.cend(), '}');
			if (it == _template.cend()) {
				result.first = false;
				result.second = "missing closing bracket";
				break;
			}
		}
	}
	return result;
}

//=====================================================================================================================


//=====================================================================================================================
// HttpUriFormater class
//=====================================================================================================================
std::string HttpUriFormater::format(const std::map<std::string, std::string> &values) const {
	return StringFormater::format(escape(values));
}

std::string HttpUriFormater::format(TranslationFunc &func) const {
	TranslationFunc func2 = [&func](const string &paramName){return UriUtils::escape(func(paramName), UriUtils::httpReserved);};
	return StringFormater::format(func2);
}

std::map<std::string, std::string> HttpUriFormater::escape(const std::map<std::string, std::string> &values) {
	std::map<std::string, std::string> out;
	for(const auto &item : values) {
		out[item.first] = UriUtils::escape(item.second, UriUtils::httpReserved);
	}
	return out;
}
//=====================================================================================================================
