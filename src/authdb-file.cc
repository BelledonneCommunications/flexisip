/*
 Flexisip, a flexible SIP proxy server with media capabilities.
 Copyright (C) 2010  Belledonne Communications SARL.

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

#define SU_MSG_ARG_T struct auth_splugin_t

#include "authdb.hh"
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>

FileAuthDb::FileAuthDb() {
	ConfigStruct *cr = ConfigManager::get()->getRoot();
	ConfigStruct *ma = cr->get<ConfigStruct>("module::Authentication");

	mFileString = ma->get<ConfigString>("datasource")->read();

	sync();
}

AuthDbResult FileAuthDb::password(su_root_t *root, const url_t *from,
		const char *auth_username, string &foundPassword,
		AuthDbListener *listener) {
	time_t now = time(NULL);

	if (difftime(now, mLastSync) >= mCacheExpire) {
		sync();
	}

	string id(from->url_user);
	string domain(from->url_host);
	string auth(auth_username);

	string key(createPasswordKey(id, domain, auth));
	switch (getCachedPassword(key, domain, foundPassword, now)) {
	case VALID_PASS_FOUND:
		return AuthDbResult::PASSWORD_FOUND;
	case EXPIRED_PASS_FOUND:
		break;
	default:
		break;
	}

	return AuthDbResult::PASSWORD_NOT_FOUND;
}

void FileAuthDb::sync() {
	LOGD("Syncing password file");

	ConfigStruct *cr = ConfigManager::get()->getRoot();
	ConfigStruct *ma = cr->get<ConfigStruct>("module::Authentication");
	list<string> domains = ma->get<ConfigStringList>("auth-domains")->read();

	mLastSync = time(NULL);

	ifstream file;

	stringstream ss;
	ss.exceptions(ifstream::failbit | ifstream::badbit);

	string line;
	string user;
	string domain;
	string password;
	string userid;

	LOGD("Opening file %s", mFileString.c_str());
	file.open(mFileString);
	if (file.is_open()) {
		while (file.good() && getline(file, line).good()) {
			ss.clear();
			ss.str(line);
			user.clear();
			domain.clear();
			password.clear();
			userid.clear();
			try {
				getline(ss, user, '@');
				getline(ss, domain, ' ');
				getline(ss, password, ' ');
				if (!ss.eof()) {
					getline(ss, userid);
				} else {
					userid = user;
				}

				if (std::find(domains.begin(), domains.end(), domain) != domains.end()) {
					string key(createPasswordKey(user, domain, userid));
					cachePassword(key, domain, password, mLastSync);
				} else {
					LOGW("Not handled domain: %s", domain.c_str());
				}
			} catch (const stringstream::failure &e) {
				LOGW("Incorrect line format: %s", line.c_str());
			}
		}
	} else {
		LOGE("Can't open file %s", mFileString.c_str());
	}
	LOGD("Syncing done");
}
