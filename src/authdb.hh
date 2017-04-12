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

#ifndef _AUTHDB_HH_
#define _AUTHDB_HH_

#include <string>
#include <mutex>

#include "common.hh"
#include "agent.hh"

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

enum AuthDbResult { PENDING, PASSWORD_FOUND, PASSWORD_NOT_FOUND, AUTH_ERROR };

// Fw declaration
struct AuthDbTimings;

class AuthDbListener : public StatFinishListener {
  public:
	virtual void onResult(AuthDbResult result, const std::string &passwd) = 0;
	virtual void onResults(list<std::string> &phones, set<std::string> &users);
	virtual ~AuthDbListener();
};

class AuthDbBackend {
	static AuthDbBackend *sUnique;

	struct CachedPassword {
		std::string pass;
		time_t expire_date;
		CachedPassword(const std::string &ipass, time_t idate) : pass(ipass), expire_date(idate) {
		}
	};

	private:
	std::map<std::string, std::map<std::string, CachedPassword>> mCachedPasswords;
	std::mutex mCachedPasswordMutex;
	std::mutex mCachedUserWithPhoneMutex;
	std::map<std::string, std::string> mPhone2User;

  protected:
	AuthDbBackend();
	enum CacheResult { VALID_PASS_FOUND, EXPIRED_PASS_FOUND, NO_PASS_FOUND };
	std::string createPasswordKey(const std::string &user, const std::string &auth);
	bool cachePassword(const std::string &key, const std::string &domain, const std::string &pass, int expires);
	bool cacheUserWithPhone(const std::string &phone, const std::string &domain, const std::string &user);
	CacheResult getCachedPassword(const std::string &key, const std::string &domain, std::string &pass);
	CacheResult getCachedUserWithPhone(const string &phone, const string &domain, string &user);
	void createCachedAccount(const std::string & user, const std::string & domain, const std::string &auth_username, const std::string &password, int expires, const std::string & phone_alias = "");
	void clearCache();
	int mCacheExpire;
  public:
	virtual ~AuthDbBackend();
	// warning: listener may be invoked on authdb backend thread, so listener must be threadsafe somehow!
	void getPassword(const std::string & user, const std::string & domain, const std::string &auth_username, AuthDbListener *listener);
	void getUserWithPhone(const std::string &phone, const std::string &domain, AuthDbListener *listener);
	void getUsersWithPhone(list<tuple<std::string,std::string,AuthDbListener *>> & creds, AuthDbListener *listener);
	virtual void getUserWithPhoneFromBackend(const std::string &, const std::string &, AuthDbListener *listener) = 0;
	virtual void getUsersWithPhonesFromBackend(list<tuple<std::string,std::string,AuthDbListener*>> &creds, AuthDbListener *listener);

	virtual void createAccount(const std::string &user, const std::string & domain, const std::string &auth_username, const std::string &password, int expires, const std::string &phone_alias = "");

	virtual void getPasswordFromBackend(const std::string &id, const std::string &domain,
										const std::string &authid, AuthDbListener *listener) = 0;

	static AuthDbBackend *get();
	/* called by module_auth so that backends can declare their configuration to the ConfigurationManager */
	static void declareConfig(GenericStruct *mc);

};

class FileAuthDb : public AuthDbBackend {
  private:
	std::string mFileString;
	time_t mLastSync;

  protected:
	void sync();

  public:
	FileAuthDb();
	virtual void getUserWithPhoneFromBackend(const std::string &phone, const std::string & domain, AuthDbListener *listener);
	virtual void getPasswordFromBackend(const std::string &id, const std::string &domain,
										const std::string &authid, AuthDbListener *listener);

	static void declareConfig(GenericStruct *mc){};
};

#if ENABLE_ODBC

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

#endif /* ENABLE_ODBC */

#if ENABLE_SOCI

#include "soci.h"
#include "utils/threadpool.hh"

class SociAuthDB : public AuthDbBackend {
	virtual ~SociAuthDB();

  public:
	SociAuthDB();
	void setConnectionParameters(const std::string &domain, const std::string &request);
	virtual void getUserWithPhoneFromBackend(const std::string & , const std::string &, AuthDbListener *listener);
	virtual void getUsersWithPhonesFromBackend(list<tuple<std::string,std::string,AuthDbListener*>> &creds, AuthDbListener *listener);
	virtual void getPasswordFromBackend(const std::string &id, const std::string &domain,
										const std::string &authid, AuthDbListener *listener);

	static void declareConfig(GenericStruct *mc);

  private:
	void getUserWithPhoneWithPool(const std::string &phone, const std::string &domain, AuthDbListener *listener);
	void getUsersWithPhonesWithPool(std::list<std::tuple<std::string,std::string,AuthDbListener*>> &creds, AuthDbListener *listener);
	void getPasswordWithPool(const std::string &id, const std::string &domain,
							 const std::string &authid, AuthDbListener *listener);

	void reconnectSession( soci::session &session );

	size_t poolSize;
	soci::connection_pool *conn_pool;
	ThreadPool *thread_pool;
	std::string connection_string;
	std::string backend;
	std::string get_password_request;
	std::string get_user_with_phone_request;
	std::string get_users_with_phones_request;
};

#endif /* ENABLE_SOCI */

#endif
