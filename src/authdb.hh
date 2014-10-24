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

enum AuthDbResult {PENDING, PASSWORD_FOUND, PASSWORD_NOT_FOUND, AUTH_ERROR};

// Fw declaration
struct AuthDbTimings;

class AuthDbListener : public StatFinishListener {
public:
	virtual void onResult()=0;
	virtual ~AuthDbListener();
	std::string mPassword;
	AuthDbResult mResult;
};

class AuthDb {
	static AuthDb *sUnique;
	struct CachedPassword {
		std::string pass;
		time_t date;
		CachedPassword(const std::string &ipass, time_t idate):pass(ipass),date(idate){}
	};
	std::map<std::string, std::map<std::string,CachedPassword>> mCachedPasswords;
	std::mutex mCachedPasswordMutex;
protected:
	AuthDb();
	enum CacheResult {VALID_PASS_FOUND, EXPIRED_PASS_FOUND, NO_PASS_FOUND};
	std::string createPasswordKey(const std::string &user, const std::string &host, const std::string &auth);
	bool cachePassword(const std::string &key, const std::string &domain, const std::string &pass, time_t time);
	CacheResult getCachedPassword(const std::string &key, const std::string &domain, std::string &pass, time_t now);
	int mCacheExpire;
public:
	virtual ~AuthDb();
	virtual void getPassword(su_root_t *root, const url_t *from, const char *auth_username, AuthDbListener *listener)=0;
	static AuthDb* get();

	AuthDb (const AuthDb &);
	void operator= (const AuthDb &);
};

class FileAuthDb : public AuthDb{
private:
	std::string mFileString;
	time_t mLastSync;

protected:
	void sync();

public:
	FileAuthDb();
	virtual void getPassword(su_root_t *root, const url_t *from, const char *auth_username, AuthDbListener* listener);
};

#if ENABLE_ODBC
class OdbcAuthDb : public AuthDb {
	~OdbcAuthDb();
	const static int fieldLength = 500;
	bool mAsynchronousRetrieving;
	struct ConnectionCtx {
		char idCBuffer[fieldLength +1];
		char domainCBuffer[fieldLength +1];
		char authIdCBuffer[fieldLength +1];
		SQLHANDLE stmt;
		SQLHDBC dbc;
		ConnectionCtx():stmt(NULL),dbc(NULL){}
		~ConnectionCtx(){
			if (stmt) SQLFreeHandle(SQL_HANDLE_STMT, stmt);

			if (dbc) {
				SQLDisconnect(dbc);
				SQLFreeHandle(SQL_HANDLE_DBC, dbc);
			}
		}
	} typedef ConnectionCtx;
	std::string connectionString;
	std::string request;
	int maxPassLength;
	std::vector<std::string> parameters;
	bool asPooling;
	SQLHENV env;
	void dbcError(ConnectionCtx &, const char* doing);
	void stmtError(ConnectionCtx &ctx, const char* doing);
	void envError(const char* doing);
	bool execDirect;
	bool getConnection(const std::string &id, ConnectionCtx &ctx, AuthDbTimings &timings);
	AuthDbResult doRetrievePassword(const std::string &user, const std::string &host, const std::string &auth, std::string &foundPassword, AuthDbTimings &timings);
	void doAsyncRetrievePassword(su_root_t *, std::string id, std::string domain, std::string auth, AuthDbListener *listener);
public:
	virtual void getPassword(su_root_t*, const url_t *from, const char *auth_username, AuthDbListener *listener);
	std::map<std::string,std::string> cachedPasswords;
	void setExecuteDirect(const bool value);
	bool connect(const std::string &dsn, const std::string &request, const std::vector<std::string> &parameters, int maxIdLength, int maxPassLength);
	bool checkConnection();
	OdbcAuthDb();
};
#endif

#endif
