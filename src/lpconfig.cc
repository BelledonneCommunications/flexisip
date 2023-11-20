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

#include "lpconfig.h"

#include <sys/stat.h>

#include <memory>

#include <ortp/ortp.h>

#include "configparsing-exception.hh"

using namespace std;

namespace flexisip {

namespace {

constexpr int MAX_LEN{2048};

bool_t is_first_char(const char* start, const char* pos) {
	const char* p;
	for (p = start; p < pos; p++) {
		if (*p != ' ') return false;
	}
	return true;
}

int is_a_comment(const char* str) {
	while (*str == ' ') {
		str++;
	}
	if (*str == '#') return 1;
	return 0;
}

const char* skip_initial_blanks(const char* str) {
	while (*str == ' ')
		++str;
	return str;
}
} // namespace

LpSection::LpSection(const string& name) : mName(name) {
}

void LpSection::addItem(const string& key, const string& value, int line) {
	if (findItem(key) != nullptr)
		throw flexisip::ConfigParsingException("key \"" + std::string(key) + "\" has several entrances.");

	LpItem item;
	item.key = key;
	item.value = value;
	item.lineno = line;
	mItems.push_back(std::move(item));
}

LpItem* LpSection::findItem(const std::string& item_name) {
	auto it = find_if(mItems.begin(), mItems.end(),
	                  [&](const LpItem& item) { return strcasecmp(item.key.c_str(), item_name.c_str()) == 0; });

	if (it == mItems.cend()) return nullptr;
	return &(*it);
}

const std::string& LpSection::getName() const {
	return mName;
}

const std::list<LpItem>& LpSection::getItems() const {
	return mItems;
}

const std::list<LpSection>& LpConfig::getSections() const {
	return mSections;
}

LpSection* LpConfig::findOrAddSection(const string& sec_name) {
	auto sec = findSection(sec_name);
	if (sec != nullptr) return sec;
	mSections.emplace_back(sec_name);
	return &mSections.back();
}

LpSection* LpConfig::findSection(const string& sec_name) {
	auto it = find_if(mSections.begin(), mSections.end(),
	                  [&](const LpSection& sec) { return strcasecmp(sec.getName().c_str(), sec_name.c_str()) == 0; });

	return (it != mSections.cend()) ? &(*it) : nullptr;
}

void LpConfig::parseFile(FILE* file) {
	char tmp[MAX_LEN];
	LpSection* cur = NULL;
	int line = 0;

	if (file == NULL) return;

	while (fgets(tmp, MAX_LEN, file) != NULL) {
		char *pos1, *pos2;
		line++;
		if (is_a_comment(tmp)) continue;
		pos1 = strchr(tmp, '[');
		if (pos1 != NULL && is_first_char(tmp, pos1)) {
			pos2 = strchr(pos1, ']');
			if (pos2 != NULL) {
				int nbs;
				char secname[MAX_LEN];
				secname[0] = '\0';
				/* found section */
				*pos2 = '\0';
				nbs = sscanf(pos1 + 1, "%s", secname);
				if (nbs == 1) {
					if (strlen(secname) > 0) {
						cur = findOrAddSection(string(secname));
					}
				} else {
					ortp_warning("parse error!");
				}
			}
		} else {
			pos1 = strchr(tmp, '=');
			if (pos1 != NULL) {
				char key[MAX_LEN];
				key[0] = '\0';

				*pos1 = '\0';
				if (sscanf(tmp, "%s", key) > 0) {

					pos1++;
					pos2 = strchr(pos1, '\n');
					if (pos2 == NULL) pos2 = pos1 + strlen(pos1);
					else {
						*pos2 = '\0'; /*replace the '\n' */
						pos2--;
					}
					/* remove ending white spaces */
					for (; pos2 > pos1 && *pos2 == ' '; pos2--)
						*pos2 = '\0';
					if (pos2 - pos1 >= 0) {
						/* found a pair key,value */
						if (cur != nullptr) {
							cur->addItem(string(key), string(pos1), line);
							/*printf("Found %s %s=%s\n",cur->name,key,pos1);*/
						} else {
							ortp_warning("found key,item but no sections");
						}
					}
				}
			}
		}
	}
}

int LpConfig::readFile(const string& filename) {
	struct file_deleter {
		void operator()(FILE* f) {
			fclose(f);
		}
	};
	unique_ptr<FILE, file_deleter> f{fopen(filename.c_str(), "r")};
	if (f != nullptr) {
		parseFile(f.get());
		return 0;
	}
	ortp_warning("Fail to open file %s", filename.c_str());
	return -1;
}

void LpConfig::processUnread(
    const std::function<void(const std::string& section, const std::string& item, int lineno)>& unreadCallback) {
	for (auto const& elem : mSections) {
		for (auto& item : elem.getItems()) {
			if (item.is_read == false) {
				unreadCallback(elem.getName(), item.key, item.lineno);
			}
		}
	}
}

const char* LpConfig::getString(const string& section, const string& key, const char* default_string) {
	auto sec = findSection(section);
	if (sec != nullptr) {
		auto item = sec->findItem(key);
		if (item != nullptr) {
			item->is_read = true;
			return skip_initial_blanks(item->value.c_str());
		}
	}
	return default_string;
}
} // namespace flexisip
