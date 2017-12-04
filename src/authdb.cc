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
#include "bctoolbox/crypto.h"

using namespace std;

AuthDbBackend *AuthDbBackend::sUnique = NULL;

AuthDbListener::~AuthDbListener(){
}

void AuthDbListener::onResults(list<std::string> &phones, set<std::string> &users) {

}

class FixedAuthDb : public AuthDbBackend {
  public:
	FixedAuthDb() {
	}

	virtual void getUserWithPhoneFromBackend(const std::string & phone, const std::string &domain, AuthDbListener *listener) {
		if (listener) listener->onResult(PASSWORD_FOUND, "user@domain.com");
	}
	virtual void getPasswordFromBackend(const std::string &id, const std::string &domain,
										const std::string &authid, AuthDbListener *listener, AuthDbListener *listener_ref) {
		if (listener) listener->onResult(PASSWORD_FOUND, "fixed");
	}
	static void declareConfig(GenericStruct *mc){};
};

AuthDbBackend *AuthDbBackend::get() {
	if (sUnique == NULL) {
		GenericStruct *cr = GenericManager::get()->getRoot();
		GenericStruct *ma = cr->get<GenericStruct>("module::Authentication");
		const string &impl = ma->get<ConfigString>("db-implementation")->read();
		if (impl == "fixed") {
			sUnique = new FixedAuthDb();
		} else if (impl == "file") {
			sUnique = new FileAuthDb();
#if ENABLE_ODBC
		} else if (impl == "odbc") {
			sUnique = new OdbcAuthDb();
#endif
#if ENABLE_SOCI
		} else if (impl == "soci") {
			sUnique = new SociAuthDB();
#endif
		}
	}

	return sUnique;
}

AuthDbBackend::AuthDbBackend() {
	GenericStruct *cr = GenericManager::get()->getRoot();
	GenericStruct *ma = cr->get<GenericStruct>("module::Authentication");
	list<string> domains = ma->get<ConfigStringList>("auth-domains")->read();
	mCacheExpire = ma->get<ConfigInt>("cache-expire")->read();
}

AuthDbBackend::~AuthDbBackend() {
}

void AuthDbBackend::declareConfig(GenericStruct *mc) {

	FileAuthDb::declareConfig(mc);
#if ENABLE_ODBC
	OdbcAuthDb::declareConfig(mc);
#endif
#if ENABLE_SOCI
	SociAuthDB::declareConfig(mc);
#endif
}

string AuthDbBackend::createPasswordKey(const string &user, const string &auth_username) {
	ostringstream key;
	key << user << "#" << auth_username;
	return key.str();
}

AuthDbBackend::CacheResult AuthDbBackend::getCachedPassword(const string &key, const string &domain, passwd_algo_t &pass) {
    time_t now = getCurrentTime();
    auto &passwords = mCachedPasswords[domain];
    unique_lock<mutex> lck(mCachedPasswordMutex);
    auto it = passwords.find(key);
    if (it != passwords.end()) {
        pass.pass.assign(it->second.pass.pass);
        pass.passmd5.assign(it->second.pass.passmd5);
        pass.passsha256.assign(it->second.pass.passsha256);
        if (now < it->second.expire_date) {
            return VALID_PASS_FOUND;
        } else {
            passwords.erase(it);
            return EXPIRED_PASS_FOUND;
        }
    }
    return NO_PASS_FOUND;
}

void AuthDbBackend::clearCache() {
	mCachedPasswords.clear();
}

bool AuthDbBackend::cachePassword(const string &key, const string &domain, const passwd_algo_t &pass, int expires) {
    time_t now = getCurrentTime();
    map<string, CachedPassword> &passwords = mCachedPasswords[domain];
    unique_lock<mutex> lck(mCachedPasswordMutex);
    map<string, CachedPassword>::iterator it = passwords.find(key);
    if (expires == -1)
        expires = mCacheExpire;
    if (it != passwords.end()) {
        it->second.pass = pass;
        it->second.expire_date = now + expires;
    } else {
        passwords.insert(make_pair(key, CachedPassword(pass, now + expires)));
    }
    return true;
}

bool AuthDbBackend::cacheUserWithPhone(const std::string &phone, const std::string &domain, const std::string &user) {
	unique_lock<mutex> lck(mCachedUserWithPhoneMutex);

	if (!phone.empty()) {
		ostringstream ostr;
		ostr<<phone<< "@"<< domain << ";user=phone";
		mPhone2User[ostr.str()] = user;
	}
	ostringstream ostr;
	ostr << user << "@" << domain;
	mPhone2User[ostr.str()] = user;
	return true;
}

void AuthDbBackend::getPassword(const std::string &user, const std::string &host, const std::string &auth_username,
                                AuthDbListener *listener) {
    // Check for usable cached password
    string key(createPasswordKey(user, auth_username));
    passwd_algo_t pass;
    switch (getCachedPassword(key, host, pass)) {
        case VALID_PASS_FOUND:
            if (listener) listener->onResult(AuthDbResult::PASSWORD_FOUND, pass);
            return;
        case EXPIRED_PASS_FOUND:
            // Might check here if connection is failing
            // If it is the case use fallback password and
            // return AuthDbResult::PASSWORD_FOUND;
            break;
        case NO_PASS_FOUND:
            break;
    }
    
    // if we reach here, password wasn't cached: we have to grab the password from the actual backend
    getPasswordFromBackend(user, host, auth_username, listener, NULL);
}

void AuthDbBackend::getPasswordForAlgo(const std::string &user, const std::string &host, const std::string &auth_username,
										AuthDbListener *listener, AuthDbListener *listener_ref) {
    // Check for usable cached password
    string key(createPasswordKey(user, auth_username));
    passwd_algo_t pass;
    switch (getCachedPassword(key, host, pass)) {
        case VALID_PASS_FOUND:
            if (listener) listener->onResult(AuthDbResult::PASSWORD_FOUND, pass);
			if(listener_ref) listener_ref->finish_verify_algos(pass);
            return;
        case EXPIRED_PASS_FOUND:
            // Might check here if connection is failing
            // If it is the case use fallback password and
            // return AuthDbResult::PASSWORD_FOUND;
            break;
        case NO_PASS_FOUND:
            break;
    }
    
    // if we reach here, password wasn't cached: we have to grab the password from the actual backend
    getPasswordFromBackend(user, host, auth_username, listener, listener_ref);
}
void AuthDbBackend::createCachedAccount(const std::string &user, const std::string &host, const std::string &auth_username, const passwd_algo_t &password,
                                        int expires, const std::string & phone_alias) {
    if (!user.empty() && !host.empty()) {
        string key = createPasswordKey(user, auth_username);
        cachePassword(key, host, password, expires);
        cacheUserWithPhone(phone_alias, host, user);
    }
}

string AuthDbBackend::syncSha256(const char* input,size_t size){
    uint8_t a1buf[size];
    size_t di;
    char out[size*2+1];
    bctbx_sha256((const unsigned char*)input, strlen(input),size, a1buf);
    for (di = 0; di < size; ++di)
        sprintf(out + di * 2, "%02x", a1buf[di]);
    out[size*2]='\0';
    return out;
}

string AuthDbBackend::syncMd5(const char* input,size_t size){
    uint8_t a1buf[size];
    size_t di;
    char out[size*2+1];
    bctbx_md5((const unsigned char*)input, strlen(input), a1buf);
    for (di = 0; di < size; ++di)
        sprintf(out + di * 2, "%02x", a1buf[di]);
    out[size*2]='\0';
    return out;
}

void AuthDbBackend::verifyAlgo(const passwd_algo_t &pass, std::list<std::string> &algorithms){
	for(auto algo = algorithms.begin(); algo != algorithms.end();)
	{
		auto algo_ref=algo++;
		if((!strcmp(algo_ref->c_str(),"MD5")&&(pass.passmd5==""))||(!strcmp(algo_ref->c_str(),"SHA-256")&&(pass.passsha256=="")))
		{
			algorithms.remove(algo_ref->c_str());
		}
	}
}

void AuthDbBackend::createAccount(const std::string & user, const std::string & host, const std::string &auth_username, const std::string &password,
										int expires, const std::string & phone_alias) {
    // Password here is in mod clrtxt. Calcul passmd5 and passsha256 before createCachedAccount.
    passwd_algo_t pass;
    pass.pass = password;
    if(pass.pass!=""){
        string input;
        input = user+":"+host+":"+pass.pass;
        pass.passmd5=syncMd5(input.c_str(), 16);
        pass.passsha256=syncSha256(input.c_str(), 32);
    }
	createCachedAccount(user, host, auth_username, pass, expires, phone_alias);
}

AuthDbBackend::CacheResult AuthDbBackend::getCachedUserWithPhone(const string &phone, const string &domain, string &user) {
	unique_lock<mutex> lck(mCachedUserWithPhoneMutex);
	auto it = mPhone2User.find(phone + "@" + domain);
	if (it == mPhone2User.end()) {
		it = mPhone2User.find(phone + "@" + domain + ";user=phone");
	}
	if (it != mPhone2User.end()) {
		user.assign(it->second);
		return VALID_PASS_FOUND;
	}
	return NO_PASS_FOUND;
}

void AuthDbBackend::getUserWithPhone(const std::string & phone, const std::string & domain, AuthDbListener *listener) {
	// Check for usable cached password
	string user;
	switch (getCachedUserWithPhone(phone, domain, user)) {
		case VALID_PASS_FOUND:
			if (listener) listener->onResult(AuthDbResult::PASSWORD_FOUND, user);
			return;
		case EXPIRED_PASS_FOUND:
		case NO_PASS_FOUND:
			break;
	}

	// if we reach here, password wasn't cached: we have to grab the password from the actual backend
	getUserWithPhoneFromBackend(phone, domain, listener);
}

void AuthDbBackend::getUsersWithPhone(list<tuple<std::string,std::string,AuthDbListener*>> & creds, AuthDbListener *listener) {
	list<tuple<std::string,std::string,AuthDbListener*>> needed_creds;
	for (tuple<std::string,std::string,AuthDbListener*> cred : creds) {
		// Check for usable cached password
		string user;
		string phone = std::get<0>(cred);
		string domain = std::get<1>(cred);
		AuthDbListener* cred_listener = std::get<2>(cred);
		switch (getCachedUserWithPhone(phone, domain, user)) {
			case VALID_PASS_FOUND:
				if (cred_listener) cred_listener->onResult(AuthDbResult::PASSWORD_FOUND, user);
				break;
			case EXPIRED_PASS_FOUND:
			case NO_PASS_FOUND:
				needed_creds.push_back(cred);
				break;
		}
	}
	
	// if we reach here, password wasn't cached: we have to grab the password from the actual backend
	getUsersWithPhonesFromBackend(needed_creds, listener);
}

void AuthDbBackend::getUsersWithPhonesFromBackend(list<tuple<std::string,std::string,AuthDbListener*>> &creds, AuthDbListener *listener) {
	for(tuple<std::string,std::string,AuthDbListener*> cred : creds) {
		string phone = std::get<0>(cred);
		string domain = std::get<1>(cred);
		AuthDbListener* l = std::get<2>(cred);
		getUserWithPhoneFromBackend(phone,domain, l);
	}
}
