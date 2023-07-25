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

#include "authdb.hh"

#include "flexisip/configmanager.hh"
#include "utils/digest.hh"

using namespace std;

namespace flexisip {

void AuthDbBackend::ListenerToFunctionWrapper::onResult([[maybe_unused]] AuthDbResult result,
                                                        [[maybe_unused]] const std::string& passwd) {
	delete this;
}

void AuthDbBackend::ListenerToFunctionWrapper::onResult(AuthDbResult result, const std::vector<passwd_algo_t>& passwd) {
	if (mCb) mCb(result, passwd);
	delete this;
}

unique_ptr<AuthDbBackend> AuthDbBackend::sUnique;

AuthDbListener::~AuthDbListener() {
}

class FixedAuthDb : public AuthDbBackend {
public:
	FixedAuthDb() : AuthDbBackend(*GenericManager::get()->getRoot()) {
	}

	void getUserWithPhoneFromBackend([[maybe_unused]] const string& phone,
	                                 [[maybe_unused]] const string& domain,
	                                 AuthDbListener* listener) override {
		if (listener) listener->onResult(PASSWORD_FOUND, "user@domain.com");
	}
	void getPasswordFromBackend([[maybe_unused]] const string& id,
	                            [[maybe_unused]] const string& domain,
	                            [[maybe_unused]] const string& authid,
	                            AuthDbListener* listener) override {
		if (listener) {
			listener->onResult(PASSWORD_FOUND, {{"fixed", "CLRTXT"}});
		}
	}
	static void declareConfig([[maybe_unused]] GenericStruct* mc){};
};

AuthDbBackend& AuthDbBackend::get() {
	if (sUnique == nullptr) {
		GenericStruct* cr = GenericManager::get()->getRoot();
		GenericStruct* ma = cr->get<GenericStruct>("module::Authentication");
		const string& impl = ma->get<ConfigString>("db-implementation")->read();
		if (impl == "fixed") {
			sUnique.reset(new FixedAuthDb());
		} else if (impl == "file") {
			sUnique.reset(new FileAuthDb());
#if ENABLE_SOCI
		} else if (impl == "soci") {
			sUnique.reset(new SociAuthDB(*cr));
#endif
		}
	}

	return *sUnique;
}

AuthDbBackend::AuthDbBackend(const GenericStruct& root) {
	GenericStruct* ma = root.get<GenericStruct>("module::Authentication");
	list<string> domains = ma->get<ConfigStringList>("auth-domains")->read();
	mCacheExpire = ma->get<ConfigInt>("cache-expire")->read();
}

AuthDbBackend::~AuthDbBackend() {
}

void AuthDbBackend::declareConfig(GenericStruct* mc) {
	FileAuthDb::declareConfig(mc);
#if ENABLE_SOCI
	SociAuthDB::declareConfig(mc);
#endif
}

// c++ style wrapper around sofia-sip 'url_unescape'
// Avoids creating a temporary buffer for the unescaped string
string AuthDbBackend::urlUnescape(const std::string& str) {
	vector<char> unescaped(str.size() + 1);
	url_unescape(unescaped.data(), str.c_str());
	return unescaped.data();
}

string AuthDbBackend::createPasswordKey(const string& user, const string& auth_username) {
	ostringstream key;
	string unescapedUser = urlUnescape(user);
	string unescapedUsername = urlUnescape(auth_username);

	key << unescapedUser << "#" << unescapedUsername;
	return key.str();
}

AuthDbBackend::CacheResult
AuthDbBackend::getCachedPassword(const string& key, const string& domain, vector<passwd_algo_t>& pass) {
	time_t now = getCurrentTime();
	auto& passwords = mCachedPasswords[domain];
	unique_lock<mutex> lck(mCachedPasswordMutex);
	auto it = passwords.find(key);
	if (it != passwords.end()) {
		pass = it->second.pass;
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

bool AuthDbBackend::cachePassword(const string& key,
                                  const string& domain,
                                  const vector<passwd_algo_t>& pass,
                                  int expires) {
	if (pass.empty()) throw invalid_argument("empty password list");
	time_t now = getCurrentTime();
	map<string, CachedPassword>& passwords = mCachedPasswords[domain];
	unique_lock<mutex> lck(mCachedPasswordMutex);
	map<string, CachedPassword>::iterator it = passwords.find(key);
	if (expires == -1) expires = mCacheExpire;
	if (it != passwords.end()) {
		it->second.pass = pass;
		it->second.expire_date = now + expires;
	} else {
		passwords.insert(make_pair(key, CachedPassword(pass, now + expires)));
	}
	return true;
}

bool AuthDbBackend::cacheUserWithPhone(const string& phone, const string& domain, const string& user) {
	unique_lock<mutex> lck(mCachedUserWithPhoneMutex);

	if (!phone.empty()) {
		ostringstream ostr;
		ostr << phone << "@" << domain << ";user=phone";
		mPhone2User[ostr.str()] = user;
	}
	ostringstream ostr;
	ostr << user << "@" << domain;
	mPhone2User[ostr.str()] = user;
	return true;
}

void AuthDbBackend::getPassword(const std::string& user,
                                const std::string& domain,
                                const std::string& auth_username,
                                AuthDbListener* listener) {
	// Check for usable cached password
	string key = createPasswordKey(user, auth_username);
	vector<passwd_algo_t> pass;
	switch (getCachedPassword(key, domain, pass)) {
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
	getPasswordFromBackend(user, domain, auth_username, listener);
}

void AuthDbBackend::getPassword(const std::string& user,
                                const std::string& domain,
                                const std::string& auth_username,
                                const ResultCb& cb) {
	auto* listener = new ListenerToFunctionWrapper(cb);
	getPassword(user, domain, auth_username, listener);
}

void AuthDbBackend::createCachedAccount(const string& user,
                                        const string& host,
                                        const string& auth_username,
                                        const vector<passwd_algo_t>& password,
                                        int expires,
                                        const string& phone_alias) {
	if (!user.empty() && !host.empty()) {
		string key = createPasswordKey(user, auth_username);
		cachePassword(key, host, password, expires);
		cacheUserWithPhone(phone_alias, host, user);
	}
}

void AuthDbBackend::createAccount(const string& user,
                                  const string& host,
                                  const string& auth_username,
                                  const string& password,
                                  int expires,
                                  const string& phone_alias) {
	// Password here is in mod clrtxt. Calcul passmd5 and passsha256 before createCachedAccount.
	vector<passwd_algo_t> pass;
	passwd_algo_t clrtxt, md5, sha256;

	clrtxt.pass = password;
	clrtxt.algo = "CLRTXT";
	pass.push_back(clrtxt);

	string input;
	input = user + ":" + host + ":" + clrtxt.pass;

	md5.pass = Md5().compute<string>(input);
	md5.algo = "MD5";
	pass.push_back(md5);

	sha256.pass = Sha256().compute<string>(input);
	sha256.algo = "SHA-256";
	pass.push_back(sha256);

	createCachedAccount(user, host, auth_username, pass, expires, phone_alias);
}

AuthDbBackend::CacheResult
AuthDbBackend::getCachedUserWithPhone(const string& phone, const string& domain, string& user) {
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

void AuthDbBackend::getUserWithPhone(const string& phone, const string& domain, AuthDbListener* listener) {
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

void AuthDbBackend::getUsersWithPhone(list<tuple<string, string, AuthDbListener*>>& creds) {
	list<tuple<string, string, AuthDbListener*>> needed_creds;
	for (tuple<string, string, AuthDbListener*> cred : creds) {
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
	if (!needed_creds.empty()) {
		// if we reach here, password wasn't cached: we have to grab the password from the actual backend
		getUsersWithPhonesFromBackend(needed_creds);
	}
}

void AuthDbBackend::getUsersWithPhonesFromBackend(list<tuple<string, string, AuthDbListener*>>& creds) {
	for (tuple<string, string, AuthDbListener*> cred : creds) {
		string phone = std::get<0>(cred);
		string domain = std::get<1>(cred);
		AuthDbListener* l = std::get<2>(cred);
		getUserWithPhoneFromBackend(phone, domain, l);
	}
}

void AuthDbBackend::resetAuthDB() {
	SLOGW << "Reseting AuthDbBackend static pointer, you MUST be in a test.";
	sUnique = nullptr;
}

} // namespace flexisip
