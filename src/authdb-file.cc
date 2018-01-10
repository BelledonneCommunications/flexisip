/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2010-2015  Belledonne Communications SARL, All rights reserved.

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

#define MAX_USERNAME_LENGTH  30
using namespace std;



void FileAuthDb::parsePasswd(string *pass, string user, string domain, passwd_algo_t *password) {
	// parse password and calcul passmd5, passsha256 if there is clrtxt pass.
	int i;
	for (i = 0; i < 3; i++) {
		if (pass[i].substr(0, 7) == "clrtxt:") {
			password->pass = pass[i].substr(7);
		}
	}

	if (password->pass != "") {
		string input;
		input = user + ":" + domain + ":" + password->pass;
		password->passmd5 = syncMd5(input.c_str(), 16);
		password->passsha256 = syncSha256(input.c_str(), 32);
		return;
	}

	for (i = 0; i < 3; i++) {
		if (pass[i].substr(0, 4) == "md5:") {
			password->passmd5 = pass[i].substr(4);
		}
		if (pass[i].substr(0, 7) == "sha256:") {
			password->passsha256 = pass[i].substr(7);
		}
	}
}

FileAuthDb::FileAuthDb() {
	GenericStruct *cr = GenericManager::get()->getRoot();
	GenericStruct *ma = cr->get<GenericStruct>("module::Authentication");

	mLastSync = 0;
	mFileString = ma->get<ConfigString>("datasource")->read();
	sync();
}

void FileAuthDb::getUserWithPhoneFromBackend(const std::string &phone, const std::string &domain, AuthDbListener *listener) {
	AuthDbResult res = AuthDbResult::PASSWORD_NOT_FOUND;
	if (mLastSync == 0) {
		sync();
	}
	std::string user;
	if (getCachedUserWithPhone(phone, domain, user) == VALID_PASS_FOUND) {
		res = AuthDbResult::PASSWORD_FOUND;
	}
	if (listener) listener->onResult(res, user);
}

void FileAuthDb::getPasswordFromBackend(const std::string &id, const std::string &domain,
                                        const std::string &authid, AuthDbListener *listener) {
	AuthDbResult res = AuthDbResult::PASSWORD_NOT_FOUND;
	time_t now = getCurrentTime();

	if (difftime(now, mLastSync) >= mCacheExpire) {
		sync();
	}

	string key(createPasswordKey(id, authid));

	passwd_algo_t passwd;
	if (getCachedPassword(key, domain, passwd) == VALID_PASS_FOUND) {
		res = AuthDbResult::PASSWORD_FOUND;
	}
	if (listener) listener->onResult(res, passwd);
}

void FileAuthDb::sync() {
	LOGD("Syncing password file");
	GenericStruct *cr = GenericManager::get()->getRoot();
	GenericStruct *ma = cr->get<GenericStruct>("module::Authentication");
	list<string> domains = ma->get<ConfigStringList>("auth-domains")->read();

	mLastSync = getCurrentTime();

	ifstream file;

	stringstream ss;
	ss.exceptions(ifstream::failbit | ifstream::badbit);

	string line;
	string user;
	string domain;
	passwd_algo_t password;
	string userid;
	string phone;
	string pass[3];
	string version;
	string passwd_tag;
	int i;
	char user_ref[MAX_USERNAME_LENGTH];

	LOGD("Opening file %s", mFileString.c_str());
	file.open(mFileString);
	if (file.is_open()) {
		while (file.good() && getline(file, line)) {
			if (line.empty()) continue;
			ss.clear();
			ss.str(line);
			version.clear();
			getline(ss, version, ' ');
			if (version.substr(0, 8) == "version:")
				version = version.substr(8);
			else
				LOGA("userdb.conf must start by version:X to be used.");
			break;
		}
		if (version == "1") {
			while (file.good() && getline(file, line)) {
				if (line.empty()) continue;
				ss.clear();
				ss.str(line);
				user.clear();
				domain.clear();
				pass[0].clear();
				pass[1].clear();
				pass[2].clear();
				password.pass.clear();
				password.passmd5.clear();
				password.passsha256.clear();
				userid.clear();
				phone.clear();
				try {
					getline(ss, user, '@');
					getline(ss, domain, ' ');
					for (i = 0; i < 3 && (!ss.eof()); i++) {
						passwd_tag.clear();
						getline(ss, passwd_tag, ' ');
						if (passwd_tag != ";")
							pass[i] = strdup(passwd_tag.c_str());
						else break;
					}
					if (passwd_tag != ";") {
						if (ss.eof())
							LOGA("In userdb.conf, the section of password must end with ';'");
						else {
							passwd_tag.clear();
							getline(ss, passwd_tag, ' ');
							if ((!ss.eof()) && (passwd_tag != ";"))
								LOGA("In userdb.conf, the section of password must end with ';'");
						}
					}

					// if user with space, replace %20 by space
					url_unescape(user_ref, user.c_str());
					if (!ss.eof()) {
						// TODO read userid with space
						getline(ss, userid, ' ');
						if (!ss.eof()) {
							getline(ss, phone);
						} else {
							phone = "";
						}
					} else {
						userid = user_ref;
						phone = "";
					}

					cacheUserWithPhone(phone, domain, user);
					parsePasswd(pass, (string)user_ref, domain, &password);

					if (find(domains.begin(), domains.end(), domain) != domains.end()) {
						string key(createPasswordKey(user, userid));
						cachePassword(key, domain, password, mCacheExpire);
					} else if (find(domains.begin(), domains.end(), "*") != domains.end()) {
						string key(createPasswordKey(user, userid));
						cachePassword(key, domain, password, mCacheExpire);
					} else {
						LOGW("Not handled domain: %s", domain.c_str());
					}
				} catch (const stringstream::failure &e) {
					LOGW("Incorrect line format: %s (error: %s)", line.c_str(), e.what());
				}
			}
		} else {
			LOGE("Version %s is not supported", version.c_str());
		}
	} else {
		LOGE("Can't open file %s", mFileString.c_str());
	}
	LOGD("Syncing done");
}
