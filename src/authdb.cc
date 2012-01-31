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


#include "authdb.hh"

AuthDb *AuthDb::sUnique = NULL;

AuthDb* AuthDb::get() {
	if (sUnique == NULL) {
		ConfigStruct *cr=ConfigManager::get()->getRoot();
		ConfigStruct *ma=cr->get<ConfigStruct>("module::Authentication");
		const string &impl=ma->get<ConfigString>("db-implementation")->read();
		if (impl == "odbc") {
			sUnique = new OdbcAuthDb();
//		} else if (impl == "redis") {
//			sUnique = new RedisAuthDb();
		}
	}

	return sUnique;
}


AuthDb::AuthDb() {
	ConfigStruct *cr=ConfigManager::get()->getRoot();
	ConfigStruct *ma=cr->get<ConfigStruct>("module::Authentication");
	list<string> domains=ma->get<ConfigStringList>("auth-domains")->read();
	list<string>::const_iterator it;
	for (it=domains.begin();it!=domains.end();++it){
		mCachedPasswords.insert(make_pair(*it,new map<string,string>));
	}
	mCacheExpire = ma->get<ConfigInt>("cache-expire")->read();
}

AuthDb::~AuthDb() {
	map<string, map<string,string>*>::iterator it;
	for (it=mCachedPasswords.begin(); it != mCachedPasswords.end(); ++it) {
		delete (*it).second;
	}
}


/* Neither this method nor the class is thread safe */
void AuthDb::password(const url_t *from, const char *auth_username, AuthDbListener *listener) {
	const string &password=fallback(from, auth_username);
	if (!password.empty()) {
		listener->onSynchronousPasswordFound(password.c_str());
	} else {
		listener->onError();
	}
}


string AuthDb::fallback(const url_t *from, const char *auth_username) {
	// assert not null
	map<string,string> *passwords=mCachedPasswords[from->url_host];
	if (passwords) {
		string key(from->url_user);
		key.append("#");
		key.append(auth_username);
		map<string,string>::iterator it=passwords->find(key);
		if (it != passwords->end()) {
			LOGD("Using password from fallback for %s@%s, %s",
					from->url_user,
					from->url_host,
					auth_username
					);
			return (*it).second;
		}
	}
	return "";
}

void AuthDb::cachePassword(const url_t *from, const char *auth_username, string &pass){
	map<string,string> *passwords=mCachedPasswords[from->url_host];
	if (passwords) {
		string key(from->url_user);
		key.append("#");
		key.append(auth_username);
		map<string,string>::iterator it=passwords->find(key);
		if (it != passwords->end()) {
			(*it).second=pass;
		} else {
			passwords->insert(make_pair(key, pass));
		}
	}
}

