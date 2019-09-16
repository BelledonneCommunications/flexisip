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

#pragma once

#include <string>
#include <mutex>

#include <flexisip/common.hh>
#include <flexisip/agent.hh>

#include <vector>
#include <stdio.h>

#if ENABLE_ODBC
#include <sql.h>
#include <sqlext.h>
#endif

#include <map>
#include <set>
#include <thread>

#include "sofia-sip/auth_module.h"
#include "sofia-sip/auth_plugin.h"

#include "belr/grammarbuilder.h"
#include "belr/parser.h"

namespace flexisip {

enum AuthDbResult { PENDING, PASSWORD_FOUND, PASSWORD_NOT_FOUND, AUTH_ERROR };

struct passwd_algo_t {
	std::string pass;
	std::string algo;
};

// Fw declaration
struct AuthDbTimings;

class AuthDbListener : public StatFinishListener {
public:
	virtual void onResult(AuthDbResult result, const std::string &passwd) = 0;
	virtual void onResult(AuthDbResult result, const std::vector<passwd_algo_t> &passwd)=0;
	virtual void finishVerifyAlgos(const std::vector<passwd_algo_t> &pass)=0;
	virtual ~AuthDbListener();
};

class AuthDbBackend {
public:
	virtual ~AuthDbBackend();
	// warning: listener may be invoked on authdb backend thread, so listener must be threadsafe somehow!
	void getPassword(const std::string & user, const std::string & domain, const std::string &auth_username, AuthDbListener *listener);
	void getPasswordForAlgo(const std::string &user, const std::string &host, const std::string &auth_username,
				AuthDbListener *listener, AuthDbListener *listener_ref);
	void getUserWithPhone(const std::string &phone, const std::string &domain, AuthDbListener *listener);
	void getUsersWithPhone(std::list<std::tuple<std::string, std::string, AuthDbListener *>> &creds);

	virtual void createAccount(const std::string &user, const std::string &domain, const std::string &auth_username, const std::string &password, int expires, const std::string &phone_alias = "");

	static AuthDbBackend &get();
	/* called by module_auth so that backends can declare their configuration to the ConfigurationManager */
	static void declareConfig(GenericStruct *mc);

protected:
	enum CacheResult {
		VALID_PASS_FOUND,
		EXPIRED_PASS_FOUND,
		NO_PASS_FOUND
	};

	AuthDbBackend();

	virtual void getUserWithPhoneFromBackend(const std::string &, const std::string &, AuthDbListener *listener) = 0;
	virtual void getUsersWithPhonesFromBackend(std::list<std::tuple<std::string, std::string, AuthDbListener *>> &creds);
	virtual void getPasswordFromBackend(const std::string &id, const std::string &domain,
					    const std::string &authid, AuthDbListener *listener, AuthDbListener *listener_ref) = 0;

	std::string createPasswordKey(const std::string &user, const std::string &auth);
	bool cachePassword(const std::string &key, const std::string &domain, const std::vector<passwd_algo_t> &pass, int expires);
	bool cacheUserWithPhone(const std::string &phone, const std::string &domain, const std::string &user);
	CacheResult getCachedPassword(const std::string &key, const std::string &domain, std::vector<passwd_algo_t> &pass);
	CacheResult getCachedUserWithPhone(const std::string &phone, const std::string &domain, std::string &user);
	void createCachedAccount(const std::string & user, const std::string & domain, const std::string &auth_username, const std::vector<passwd_algo_t> &password, int expires, const std::string & phone_alias = "");
	void clearCache();

	static std::string syncSha256(const char* input,size_t size);
	static std::string syncMd5(const char* input,size_t size);
	static std::string urlUnescape(const std::string &str);

	int mCacheExpire;

private:
	struct CachedPassword {
		std::vector<passwd_algo_t> pass;
		time_t expire_date;
		CachedPassword(const std::vector<passwd_algo_t> &ipass, time_t idate) : pass(ipass), expire_date(idate) {
		}
	};

	static std::unique_ptr<AuthDbBackend> sUnique;

	std::map<std::string, std::map<std::string, CachedPassword>> mCachedPasswords;
	std::mutex mCachedPasswordMutex;
	std::mutex mCachedUserWithPhoneMutex;
	std::map<std::string, std::string> mPhone2User;
};

//Base root type needed by belr
class FileAuthDbParserElem {
public:
	virtual ~FileAuthDbParserElem () = default;
};

class FileAuthDbParserPassword : public FileAuthDbParserElem {
public:
	void setAlgo(const std::string &algo) {
		mPass.algo = algo;
	}
	void setPassword(const std::string &pass) {
		mPass.pass = pass;
	}
	const passwd_algo_t &getPassAlgo() const {
		return mPass;
	}

private:
	passwd_algo_t mPass;
};

class FileAuthDbParserUserLine : public FileAuthDbParserElem {
public:
	void setUser(const std::string &user) {
		mUser = user;
	}
	const std::string & getUser() const {
		return mUser;
	}
	void setDomain(const std::string &domain) {
		mDomain = domain;
	}
	const std::string & getDomain() const {
		return mDomain;
	}
	void addPassword(const std::shared_ptr<FileAuthDbParserPassword> &password) {
		mParserPasswords.push_back(password);
	}
	//Automatically transform for convenience from parser format to passwd_algo_t
	const std::vector<passwd_algo_t> & getPasswords() {
		if (mPasswords.empty()) {
			for (const auto &parserPasswd : mParserPasswords) {
				mPasswords.push_back(parserPasswd->getPassAlgo());
			}
		}
		return mPasswords;
	}
	void setUserId(const std::string &userId) {
		mUserId = userId;
	}
	const std::string & getUserId() const {
		return mUserId;
	}
	void setPhone(const std::string &phone) {
		mPhone = phone;
	}
	const std::string & getPhone() const {
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
	void setVersion(const std::string &version) {
		mVersion = version;
	}
	const std::string & getVersion() const {
		return mVersion;
	}

	void addAuthLine(const std::shared_ptr<FileAuthDbParserUserLine> &authLine) {
		mAuthLines.push_back(authLine);
	}

	const std::list<std::shared_ptr<FileAuthDbParserUserLine>> &getAuthLines() const {
		return mAuthLines;
	}

private:
	std::string mVersion;
	std::list<std::shared_ptr<FileAuthDbParserUserLine>> mAuthLines;
};

class FileAuthDb : public AuthDbBackend {
private:
	std::string mFileString;
	time_t mLastSync;
	void parsePasswd(const std::vector<passwd_algo_t> &srcPasswords, const std::string &user, const std::string &domain, std::vector<passwd_algo_t> &destPasswords);
	std::shared_ptr<belr::Parser<std::shared_ptr<FileAuthDbParserElem>>> setupParser();

protected:
	void sync();

public:
	FileAuthDb();
	virtual void getUserWithPhoneFromBackend(const std::string &phone, const std::string &domain, AuthDbListener *listener);
	virtual void getPasswordFromBackend(const std::string &id, const std::string &domain,
					    const std::string &authid, AuthDbListener *listener, AuthDbListener *listener_ref);

	static void declareConfig(GenericStruct *mc){};
};

}

#if ENABLE_ODBC

namespace flexisip {

class OdbcAuthDb : public AuthDbBackend {
	~OdbcAuthDb();
	const static int fieldLength = 500;
	bool mAsynchronousRetrieving;
	struct ConnectionCtx {
		char idCBuffer[fieldLength + 1];
		char domainCBuffer[fieldLength + 1];
		char authIdCBuffer[fieldLength + 1];
		SQLHANDLE stmt;
		SQLHDBC dbc;
		ConnectionCtx() : stmt(NULL), dbc(NULL) {
		}
		~ConnectionCtx() {
			if (stmt)
				SQLFreeHandle(SQL_HANDLE_STMT, stmt);

			if (dbc) {
				SQLDisconnect(dbc);
				SQLFreeHandle(SQL_HANDLE_DBC, dbc);
			}
		}
	};
	std::string connectionString;
	std::string request;
	int maxPassLength;
	std::vector<std::string> parameters;
	bool asPooling;
	SQLHENV env;
	void dbcError(ConnectionCtx &, const char *doing);
	void stmtError(ConnectionCtx &ctx, const char *doing);
	void envError(const char *doing);
	bool execDirect;
	bool getConnection(const std::string &id, ConnectionCtx &ctx, AuthDbTimings &timings);
	AuthDbResult doRetrievePassword(ConnectionCtx &ctx, const std::string &user, const std::string &domain,
					const std::string &auth, std::string &foundPassword, AuthDbTimings &timings);
	void doAsyncRetrievePassword(std::string id, std::string domain, std::string auth,
				     AuthDbListener *listener);

public:
	virtual void getUserWithPhoneFromBackend(const std::string &phone, const std::string &domain, AuthDbListener *listener);
	virtual void getPasswordFromBackend(const std::string &id, const std::string &domain,
					    const std::string &authid, AuthDbListener *listener);
	std::map<std::string, std::string> cachedPasswords;
	void setExecuteDirect(const bool value);
	bool checkConnection();
	OdbcAuthDb();

	static void declareConfig(GenericStruct *mc);
};

}

#endif /* ENABLE_ODBC */

#if ENABLE_SOCI

#include "soci/soci.h"
#include "utils/threadpool.hh"

namespace flexisip {

class SociAuthDB : public AuthDbBackend {
public:
	void getUserWithPhoneFromBackend(const std::string & , const std::string &, AuthDbListener *listener) override;
	void getUsersWithPhonesFromBackend(std::list<std::tuple<std::string,std::string,AuthDbListener*>> &creds) override;
	void getPasswordFromBackend(const std::string &id, const std::string &domain,
					    const std::string &authid, AuthDbListener *listener, AuthDbListener *listener_ref) override;

	static void declareConfig(GenericStruct *mc);

private:
	SociAuthDB();

	void connectDatabase();
	void closeOpenedSessions();

	void getUserWithPhoneWithPool(const std::string &phone, const std::string &domain, AuthDbListener *listener);
	void getUsersWithPhonesWithPool(std::list<std::tuple<std::string,std::string,AuthDbListener*>> &creds);
	void getPasswordWithPool(const std::string &id, const std::string &domain,
				 const std::string &authid, AuthDbListener *listener, AuthDbListener *listener_ref);

	void notifyAllListeners(std::list<std::tuple<std::string, std::string, AuthDbListener *>> &creds, const std::set<std::pair<std::string, std::string>> &presences);


	std::size_t poolSize;
	std::unique_ptr<soci::connection_pool> conn_pool;
	std::unique_ptr<ThreadPool> thread_pool;
	std::string connection_string;
	std::string backend;
	std::string get_password_request;
	std::string get_user_with_phone_request;
	std::string get_users_with_phones_request;
	std::string get_password_algo_request;
	bool check_domain_in_presence_results = false;
	bool hashed_passwd;
	bool _connected = false;

	friend AuthDbBackend;
};

}

#endif /* ENABLE_SOCI */
