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

using namespace ::std;

AuthDb *AuthDb::sUnique = NULL;


class FixedAuthDb : public AuthDb{
public:
        FixedAuthDb(){};
	virtual AuthDbResult password(su_root_t *root, const url_t *from, const char *auth_username, string &foundPassword, const shared_ptr<AuthDbListener> &listener) {
		foundPassword.assign("fixed");
		return AuthDbResult::PASSWORD_FOUND;
	}
};

AuthDb* AuthDb::get() {
	if (sUnique == NULL) {
		GenericStruct *cr=GenericManager::get()->getRoot();
		GenericStruct *ma=cr->get<GenericStruct>("module::Authentication");
		const string &impl=ma->get<ConfigString>("db-implementation")->read();
		if (impl == "fixed") {
			sUnique = new FixedAuthDb();
//		} else if (impl == "redis") {
//			sUnique = new RedisAuthDb();
		} else if (impl == "file") {
                        sUnique = new FileAuthDb();
#if ENABLE_ODBC
		} else if (impl == "odbc") {
			sUnique = new OdbcAuthDb();
#endif
		}
	}

	return sUnique;
}


AuthDb::AuthDb() {
	GenericStruct *cr=GenericManager::get()->getRoot();
	GenericStruct *ma=cr->get<GenericStruct>("module::Authentication");
	list<string> domains=ma->get<ConfigStringList>("auth-domains")->read();
	mCacheExpire = ma->get<ConfigInt>("cache-expire")->read();
}

AuthDb::~AuthDb() {
}

string AuthDb::createPasswordKey(const string &user, const string &host, const string &auth) {
	string key(user);
	return key.append("#").append(auth);
}

AuthDb::CacheResult AuthDb::getCachedPassword(const string &key, const string &domain, string &pass, time_t now) {
	map<string,CachedPassword*> &passwords=mCachedPasswords[domain];
	unique_lock<mutex> lck(mCachedPasswordMutex);
	map<string,CachedPassword*>::iterator it=passwords.find(key);
	if (it != passwords.end()) {
		pass.assign((*it).second->pass);
		if (now < (*it).second->date + mCacheExpire) {
			return VALID_PASS_FOUND;
		} else {
			return EXPIRED_PASS_FOUND;
		}
	}
	return NO_PASS_FOUND;
}

bool AuthDb::cachePassword(const string &key, const string &domain, const string &pass, time_t time){
	map<string,CachedPassword*> &passwords=mCachedPasswords[domain];
	unique_lock<mutex> lck(mCachedPasswordMutex);
	map<string,CachedPassword*>::iterator it=passwords.find(key);
	if (it != passwords.end()) {
		(*it).second->pass=pass;
		(*it).second->date=time;
	} else {
		passwords.insert(make_pair(key, new CachedPassword(pass,time)));
	}

	return true;
}


