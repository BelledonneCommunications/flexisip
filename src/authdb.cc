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


#include "authdb.hh"

using namespace ::std;

AuthDb *AuthDb::sUnique = NULL;


AuthDbListener::~AuthDbListener(){
}

class FixedAuthDb : public AuthDb{
public:
        FixedAuthDb(){}

	virtual void getPasswordFromBackend(su_root_t *root, const std::string& id, const std::string& domain, const std::string& authid, AuthDbListener *listener)
	{
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
#if ENABLE_SOCI
		} else if( impl == "soci") {
			sUnique = new SociAuthDB();
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
	key<<user<<"#"<<auth_username;
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
	map<string, CachedPassword> &passwords=mCachedPasswords[domain];
	unique_lock<mutex> lck(mCachedPasswordMutex);
	map<string, CachedPassword>::iterator it=passwords.find(key);
	if (expires==-1) expires=mCacheExpire;
	if (it != passwords.end()) {
		(*it).second.pass=pass;
		(*it).second.expire_date=now+expires;
	} else {
		passwords.insert(make_pair(key,CachedPassword(pass,now+expires)));
	}
	return true;
}

void AuthDb::getPassword(su_root_t *root, const url_t *from, const char *auth_username, AuthDbListener *listener){
	// Check for usable cached password
	string id(from->url_user);
	string domain(from->url_host);
	string auth(auth_username);
	string key(createPasswordKey(id, domain, auth));

	switch(getCachedPassword(key, domain, listener->mPassword)) {
		case VALID_PASS_FOUND:
			listener->mResult=AuthDbResult::PASSWORD_FOUND;
			listener->onResult();
			return;
		case EXPIRED_PASS_FOUND:
			// Might check here if connection is failing
			// If it is the case use fallback password and
			//return AuthDbResult::PASSWORD_FOUND;
			break;
		case NO_PASS_FOUND:
			break;
	}

	// if we reach here, password wasn't cached: we have to grab the password from the actual backend
	getPasswordFromBackend(root, id, domain, auth, listener);
}

static void main_thread_async_response_cb(su_root_magic_t *rm, su_msg_r msg,
										  void *u) {
	AuthDbListener **listenerStorage = (AuthDbListener**)su_msg_data(msg);
	AuthDbListener *listener=*listenerStorage;
	listener->onResult();
}

void AuthDb::notifyPasswordRetrieved(su_root_t *root, AuthDbListener *listener, AuthDbResult result, const std::string &password) {
	if (listener) {
		su_msg_r mamc = SU_MSG_R_INIT;
		if (-1 == su_msg_create(mamc,
								su_root_task(root),
								su_root_task(root),
								main_thread_async_response_cb,
								sizeof(AuthDbListener*))) {
			LOGF("Couldn't create auth async message");
		}

		AuthDbListener **listenerStorage = (AuthDbListener **)su_msg_data(mamc);
		*listenerStorage = listener;

		switch (result) {
			case PASSWORD_FOUND:
				listener->mResult=result;
				listener->mPassword=password;
				break;
			case PASSWORD_NOT_FOUND:
				listener->mResult=AuthDbResult::PASSWORD_NOT_FOUND;
				listener->mPassword="";
				break;
			case AUTH_ERROR:
				/*in that case we can fallback to the cached password previously set*/
				break;
			case PENDING:
				LOGF("unhandled case PENDING");
				break;
		}
		if (-1 == su_msg_send(mamc)) {
			LOGF("Couldn't send auth async message to main thread.");
		}
	}
}

void AuthDb::createCachedAccount(const url_t *from, const char *auth_username, const char *password, int expires){
	if (from->url_host && from->url_user){
		string key=createPasswordKey(from->url_user, from->url_host, auth_username ? auth_username : "");
		cachePassword(key,from->url_host,password,expires);
	}
}

void AuthDb::createAccount(const url_t *from, const char *auth_username, const char *password, int expires){
	createCachedAccount(from, auth_username, password, expires);
}

