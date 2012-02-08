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
#include <sql.h>
#include <sqlext.h>
#include <map>
#include <set>
#include <thread>

#include "sofia-sip/auth_module.h"
#include "sofia-sip/auth_plugin.h"

using namespace std;

enum AuthDbResult {PENDING, PASSWORD_FOUND, PASSWORD_NOT_FOUND, AUTH_ERROR};

class AuthDbListener {
public:
	~AuthDbListener(){};

	virtual void onAsynchronousPasswordFound(const string &password) = 0;
	virtual void onSynchronousPasswordFound(const string &password) = 0;
	virtual void onError() = 0;
};

class AuthDb {
	static AuthDb *sUnique;
	struct CachedPassword {
		string pass;
		time_t date;
		CachedPassword(const string &pass, time_t date):pass(pass),date(date){};
	} typedef CachedPassword;
	map<string, map<string,CachedPassword*>*> mCachedPasswords;
	std::mutex mCachedPasswordMutex;
protected:
	AuthDb();
	enum CacheResult {VALID_PASS_FOUND, EXPIRED_PASS_FOUND, NO_PASS_FOUND};
	string createPasswordKey(const string &user, const string &host, const string &auth);
	bool cachePassword(const string &key, const string &domain, const string &pass, time_t time);
	CacheResult getCachedPassword(const string &key, const string &domain, string &pass, time_t now);
	int mCacheExpire;
public:
	virtual ~AuthDb();
	virtual AuthDbResult password(const url_t *from, const char *auth_username, string &foundPassword, AuthDbListener *listener)=0;
	static AuthDb* get();

	AuthDb (const AuthDb &);
	void operator= (const AuthDb &);
};

class FileAuthDb : public AuthDb{
private:
        string mFileString;
        time_t mLastSync;
        
protected:
        void sync();
        
public:
        FileAuthDb();
	virtual AuthDbResult password(const url_t *from, const char *auth_username, string &foundPassword, AuthDbListener *listener);
};


class OdbcAuthDb : public AuthDb {
	mutex mCreateHandleMutex;
	const static int fieldLength = 500;
	struct ConnectionCtx {
		char idCBuffer[fieldLength +1];
		char domainCBuffer[fieldLength +1];
		char authIdCBuffer[fieldLength +1];
		SQLHANDLE stmt;
		SQLHDBC dbc;
		ConnectionCtx():stmt(NULL),dbc(NULL){};
		~ConnectionCtx(){
			if (dbc) {
				SQLDisconnect(dbc);
				SQLFreeHandle(SQL_HANDLE_DBC, dbc);
			}
			if (stmt) SQLFreeHandle(SQL_HANDLE_STMT, stmt);
		}
	} typedef ConnectionCtx;
	string connectionString;
	string request;
	int maxPassLength;
	vector<string> parameters;
	bool asPooling;
	SQLHENV env;
	void dbcError(ConnectionCtx &, const char* doing);
	void envError(const char* doing);
	bool execDirect;
	bool getConnection(ConnectionCtx &ctx);
	AuthDbResult doRetrievePassword(const string &user, const string &host, const string &auth, string &foundPassword);
	void doAsyncRetrievePassword(string id, string domain, string auth, AuthDbListener *listener);
public:
	virtual ~OdbcAuthDb();
	virtual AuthDbResult password(const url_t *from, const char *auth_username, string &foundPassword, AuthDbListener *listener);
	map<string,string> cachedPasswords;
	void setExecuteDirect(const bool value);
	bool connect(const string &dsn, const string &request, const vector<string> &parameters, int maxIdLength, int maxPassLength);
	bool checkConnection();
	OdbcAuthDb();
};

#endif
