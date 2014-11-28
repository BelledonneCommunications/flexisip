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


AuthDbListener::~AuthDbListener(){
}

class FixedAuthDb : public AuthDb{
public:
        FixedAuthDb(){}
	virtual void getPassword(su_root_t *root, const url_t *from, const char *auth_username, AuthDbListener * listener) {
		listener->mPassword.assign("fixed");
		listener->mResult=PASSWORD_FOUND;
		listener->onResult();
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

string AuthDb::createPasswordKey(const string &user, const string &host, const string &auth_username) {
	ostringstream key;
	key<<user;
	if (!auth_username.empty()){
		key<<user<<"#"<<auth_username;
	}
	return key.str();
}

AuthDb::CacheResult AuthDb::getCachedPassword(const string &key, const string &domain, string &pass) {
	time_t now = getCurrentTime();
	auto & passwords=mCachedPasswords[domain];
	unique_lock<mutex> lck(mCachedPasswordMutex);
	auto it=passwords.find(key);
	if (it != passwords.end()) {
		pass.assign((*it).second.pass);
		if (now < (*it).second.expire_date) {
			return VALID_PASS_FOUND;
		} else {
			passwords.erase(it);
			return EXPIRED_PASS_FOUND;
		}
	}
	return NO_PASS_FOUND;
}

void AuthDb::clearCache(){
	mCachedPasswords.clear();
}

bool AuthDb::cachePassword(const string &key, const string &domain, const string &pass, int expires){
	time_t now = getCurrentTime();
	auto & passwords=mCachedPasswords[domain];
	unique_lock<mutex> lck(mCachedPasswordMutex);
	auto it=passwords.find(key);
	if (expires==-1) expires=mCacheExpire;
	if (it != passwords.end()) {
		(*it).second.pass=pass;
		(*it).second.expire_date=now+expires;
	} else {
		passwords.insert(make_pair(key,CachedPassword(pass,now)));
	}
	return true;
}

void AuthDb::createCachedAccount(const url_t *from, const char *auth_username, const char *password, int expires){
	if (from->url_host && from->url_user){
		string key=createPasswordKey(from->url_user,from->url_host,auth_username ? auth_username : "");
		cachePassword(key,from->url_host,password,expires);
	}
}

void AuthDb::createAccount(const url_t *from, const char *auth_username, const char *password, int expires){
	createCachedAccount(from, auth_username, password, expires);
}

