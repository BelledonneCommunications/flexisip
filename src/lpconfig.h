/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023 Belledonne Communications SARL, All rights reserved.

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

#include <algorithm>
#include <functional>
#include <list>
#include <string>

namespace flexisip {
/**
 * The LpConfig object is used to manipulate a configuration file.
 *
 * @ingroup misc
 * The format of the configuration file is a .ini like format:
 * - sections are defined in []
 * - each section contains a sequence of key=value pairs.
 *
 * Example:
 * @code
 * [sound]
 * echocanceler=1
 * playback_dev=ALSA: Default device
 *
 * [video]
 * enabled=1
 * @endcode
 **/
struct LpItem {
	std::string key;
	std::string value;
	int is_read{};
	int lineno{};
};

class LpSection {
public:
	LpSection(const std::string& name);
	void addItem(const std::string& key, const std::string& value, int line);
	LpItem* findItem(const std::string& item_name);
	const std::string& getName() const;
	const std::list<LpItem>& getItems() const;

private:
	std::string mName;
	std::list<LpItem> mItems;
};
class LpConfig {
public:
	int readFile(const std::string& filename);
	const std::list<LpSection>& getSections() const;

	/**
	 * Retrieves a configuration item as a string, given its section, key, and default value.
	 *
	 * @ingroup misc
	 * The default value string is returned if the config item isn't found.
	 **/
	const char* getString(const std::string& section, const std::string& key, const char* default_string);

	void processUnread(
	    const std::function<void(const std::string& section, const std::string& item, int lineno)>& unreadCallback);

private:
	void parseFile(FILE* file);
	LpSection* findSection(const std::string& sec_name);
	LpSection* findOrAddSection(const std::string& sec_name);

	std::list<LpSection> mSections;
};
}; // namespace flexisip
