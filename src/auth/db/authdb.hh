/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

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

#include <stdio.h>

#include <functional>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "flexisip/configmanager.hh"

namespace belr {
template <typename _parserElementT>
class Parser;
}
namespace flexisip {

enum AuthDbResult { PENDING, PASSWORD_FOUND, PASSWORD_NOT_FOUND, AUTH_ERROR };

struct passwd_algo_t {
	passwd_algo_t() = default;
	template <typename T, typename U>
	passwd_algo_t(T&& pass, U&& algo) : pass{std::forward<T>(pass)}, algo{std::forward<U>(algo)} {};

	std::string pass{};
	std::string algo{};
};

// Fw declaration
struct AuthDbTimings;

class AuthDbListener : public StatFinishListener {
public:
	virtual void onResult(AuthDbResult result, const std::string& passwd) = 0;
	virtual void onResult(AuthDbResult result, const std::vector<passwd_algo_t>& passwd) = 0;
	virtual ~AuthDbListener();
};

class AuthDbBackend {
public:
	using PwList = std::vector<passwd_algo_t>;
	using ResultCb = std::function<void(AuthDbResult, const PwList&)>;

	virtual ~AuthDbBackend();
	// warning: listener may be invoked on authdb backend thread, so listener must be threadsafe somehow!
	void getPassword(const std::string& user,
	                 const std::string& domain,
	                 const std::string& auth_username,
	                 AuthDbListener* listener);
	void getPassword(const std::string& user,
	                 const std::string& domain,
	                 const std::string& auth_username,
	                 const ResultCb& cb);
	void getUserWithPhone(const std::string& phone, const std::string& domain, AuthDbListener* listener);
	void getUsersWithPhone(std::list<std::tuple<std::string, std::string, AuthDbListener*>>& creds);

	virtual void createAccount(const std::string& user,
	                           const std::string& domain,
	                           const std::string& auth_username,
	                           const std::string& password,
	                           int expires,
	                           const std::string& phone_alias = "");

	/* called by module_auth so that backends can declare their configuration to the ConfigurationManager */
	static void declareConfig(GenericStruct* mc);

protected:
	enum CacheResult { VALID_PASS_FOUND, EXPIRED_PASS_FOUND, NO_PASS_FOUND };

	AuthDbBackend(const GenericStruct&);

	virtual void getUserWithPhoneFromBackend(const std::string&, const std::string&, AuthDbListener* listener) = 0;
	virtual void getUsersWithPhonesFromBackend(std::list<std::tuple<std::string, std::string, AuthDbListener*>>& creds);
	virtual void getPasswordFromBackend(const std::string& id,
	                                    const std::string& domain,
	                                    const std::string& authid,
	                                    AuthDbListener* listener) = 0;

	std::string createPasswordKey(const std::string& user, const std::string& auth);
	bool cachePassword(const std::string& key,
	                   const std::string& domain,
	                   const std::vector<passwd_algo_t>& pass,
	                   int expires);
	bool cacheUserWithPhone(const std::string& phone, const std::string& domain, const std::string& user);
	CacheResult getCachedPassword(const std::string& key, const std::string& domain, std::vector<passwd_algo_t>& pass);
	CacheResult getCachedUserWithPhone(const std::string& phone, const std::string& domain, std::string& user);
	void createCachedAccount(const std::string& user,
	                         const std::string& domain,
	                         const std::string& auth_username,
	                         const std::vector<passwd_algo_t>& password,
	                         int expires,
	                         const std::string& phone_alias = "");
	void clearCache();

	static std::string urlUnescape(const std::string& str);

	int mCacheExpire;

private:
	struct CachedPassword {
		std::vector<passwd_algo_t> pass;
		time_t expire_date;
		CachedPassword(const std::vector<passwd_algo_t>& ipass, time_t idate) : pass(ipass), expire_date(idate) {
		}
	};

	struct ListenerToFunctionWrapper : public AuthDbListener {
	public:
		ListenerToFunctionWrapper() = default;
		ListenerToFunctionWrapper(const ListenerToFunctionWrapper& src) = default;
		ListenerToFunctionWrapper(const ResultCb& cb) : mCb(cb) {
		}

		void onResult(AuthDbResult result, const std::string& passwd) override;
		void onResult(AuthDbResult result, const std::vector<passwd_algo_t>& passwd) override;

		ResultCb mCb;
	};

	std::map<std::string, std::map<std::string, CachedPassword>> mCachedPasswords;
	std::mutex mCachedPasswordMutex;
	std::mutex mCachedUserWithPhoneMutex;
	std::map<std::string, std::string> mPhone2User;
};

/**
 * Class that owns the authentication database backend.
 * The backend is created during the first "get" call.
 **/
class AuthDb {
public:
	AuthDb(const std::shared_ptr<ConfigManager>& cfg) : mConfigManager{cfg} {
	}
	// Accessor to the database backend
	AuthDbBackend& db() {
		if (!mBackend) createAuthDbBackend();
		return *mBackend;
	}

private:
	void createAuthDbBackend();
	std::unique_ptr<AuthDbBackend> mBackend;
	std::shared_ptr<ConfigManager> mConfigManager;
};

// Base root type needed by belr
class FileAuthDbParserElem {
public:
	virtual ~FileAuthDbParserElem() = default;
};

class FileAuthDbParserPassword : public FileAuthDbParserElem {
public:
	void setAlgo(const std::string& algo) {
		mPass.algo = algo;
	}
	void setPassword(const std::string& pass) {
		mPass.pass = pass;
	}
	const passwd_algo_t& getPassAlgo() const {
		return mPass;
	}

private:
	passwd_algo_t mPass;
};

class FileAuthDbParserUserLine : public FileAuthDbParserElem {
public:
	void setUser(const std::string& user) {
		mUser = user;
	}
	const std::string& getUser() const {
		return mUser;
	}
	void setDomain(const std::string& domain) {
		mDomain = domain;
	}
	const std::string& getDomain() const {
		return mDomain;
	}
	void addPassword(const std::shared_ptr<FileAuthDbParserPassword>& password) {
		mParserPasswords.push_back(password);
	}
	// Automatically transform for convenience from parser format to passwd_algo_t
	const std::vector<passwd_algo_t>& getPasswords() {
		if (mPasswords.empty()) {
			for (const auto& parserPasswd : mParserPasswords) {
				mPasswords.push_back(parserPasswd->getPassAlgo());
			}
		}
		return mPasswords;
	}
	void setUserId(const std::string& userId) {
		mUserId = userId;
	}
	const std::string& getUserId() const {
		return mUserId;
	}
	void setPhone(const std::string& phone) {
		mPhone = phone;
	}
	const std::string& getPhone() const {
		return mPhone;
	}

private:
	std::string mUser;
	std::string mDomain;
	std::vector<std::shared_ptr<FileAuthDbParserPassword>> mParserPasswords;
	std::vector<passwd_algo_t> mPasswords;
	std::string mUserId;
	std::string mPhone;
};

class FileAuthDbParserRoot : public FileAuthDbParserElem {
public:
	void setVersion(const std::string& version) {
		mVersion = version;
	}
	const std::string& getVersion() const {
		return mVersion;
	}

	void addAuthLine(const std::shared_ptr<FileAuthDbParserUserLine>& authLine) {
		mAuthLines.push_back(authLine);
	}

	const std::list<std::shared_ptr<FileAuthDbParserUserLine>>& getAuthLines() const {
		return mAuthLines;
	}

private:
	std::string mVersion;
	std::list<std::shared_ptr<FileAuthDbParserUserLine>> mAuthLines;
};

class FileAuthDb : public AuthDbBackend {
private:
	const GenericStruct& mConfigRoot;
	std::string mFileString;
	time_t mLastSync;
	void parsePasswd(const std::vector<passwd_algo_t>& srcPasswords,
	                 const std::string& user,
	                 const std::string& domain,
	                 std::vector<passwd_algo_t>& destPasswords);
	std::shared_ptr<belr::Parser<std::shared_ptr<FileAuthDbParserElem>>> setupParser();

protected:
	void sync();

public:
	FileAuthDb(const GenericStruct& root);
	void
	getUserWithPhoneFromBackend(const std::string& phone, const std::string& domain, AuthDbListener* listener) override;
	void getPasswordFromBackend(const std::string& id,
	                            const std::string& domain,
	                            const std::string& authid,
	                            AuthDbListener* listener) override;

	static void declareConfig(GenericStruct* mc);
};

} // namespace flexisip

#if ENABLE_SOCI

#include "soci/row.h"
#include "soci/rowset.h"
#include "soci/session.h"
#include "soci/soci.h"

#include "utils/thread/thread-pool.hh"

namespace flexisip {

class SociAuthDB : public AuthDbBackend {
public:
	void getUserWithPhoneFromBackend(const std::string&, const std::string&, AuthDbListener* listener) override;
	void
	getUsersWithPhonesFromBackend(std::list<std::tuple<std::string, std::string, AuthDbListener*>>& creds) override;
	void getPasswordFromBackend(const std::string& id,
	                            const std::string& domain,
	                            const std::string& authid,
	                            AuthDbListener* listener) override;

	static void declareConfig(GenericStruct* mc);

	SociAuthDB(const GenericStruct&);

private:
	void connectDatabase();
	void closeOpenedSessions();

	void getUserWithPhoneWithPool(const std::string& phone, const std::string& domain, AuthDbListener* listener);
	void getUsersWithPhonesWithPool(std::list<std::tuple<std::string, std::string, AuthDbListener*>>& creds);
	void getPasswordWithPool(const std::string& id,
	                         const std::string& domain,
	                         const std::string& authid,
	                         AuthDbListener* listener);

	void notifyAllListeners(std::list<std::tuple<std::string, std::string, AuthDbListener*>>& creds,
	                        const std::set<std::pair<std::string, std::string>>& presences);

	std::size_t poolSize;
	std::unique_ptr<soci::connection_pool> conn_pool;
	std::unique_ptr<ThreadPool> thread_pool;
	std::string connection_string;
	std::string backend;
	std::string get_user_with_phone_request;
	std::string get_users_with_phones_request;
	std::string get_password_algo_request;
	// Get user password with soci using admin-provided query string.
	// Will bind only known parameters detected in the query string
	std::function<soci::rowset<soci::row>(soci::session&, const std::string&, const std::string&, const std::string&)>
	    mGetPassword;
	bool check_domain_in_presence_results = false;
	bool _connected = false;

	friend AuthDbBackend;
};

} // namespace flexisip

#endif /* ENABLE_SOCI */
