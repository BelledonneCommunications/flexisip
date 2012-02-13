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

// Fw declaration
struct AuthDbTimings;

class AuthDbListener {
	Agent *mAgent;
	shared_ptr<SipEvent> mEv;
	bool mHashedPass;
	bool mStateFullProxy;
	auth_mod_t *mAm;
	auth_status_t *mAs;
	auth_challenger_t const *mAch;
public:
	auth_response_t mAr;
	AuthDbListener(Agent *, shared_ptr<SipEvent>, bool HashedPass, bool stateFull);
	void setData(auth_mod_t *am, auth_status_t *as, auth_challenger_t const *ach);
	void passwordRetrievingPending();
	~AuthDbListener(){};
	void checkPassword(const char *password);
	void onAsynchronousResponse(AuthDbResult ret, const char *password);
	void onError();
	void sendReplyAndDestroy();
	void sendReply();
	su_root_t *getRoot() {
		return mAgent->getRoot();
	}
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
	virtual AuthDbResult password(su_root_t *root, const url_t *from, const char *auth_username, string &foundPassword, AuthDbListener *listener)=0;
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
	virtual AuthDbResult password(su_root_t *root, const url_t *from, const char *auth_username, string &foundPassword, AuthDbListener *listener);
};


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
		ConnectionCtx():stmt(NULL),dbc(NULL){};
		~ConnectionCtx(){
			if (stmt) SQLFreeHandle(SQL_HANDLE_STMT, stmt);

			if (dbc) {
				SQLDisconnect(dbc);
				SQLFreeHandle(SQL_HANDLE_DBC, dbc);
			}
		}
	} typedef ConnectionCtx;
	string connectionString;
	string request;
	int maxPassLength;
	vector<string> parameters;
	bool asPooling;
	SQLHENV env;
	void dbcError(ConnectionCtx &, const char* doing);
	void stmtError(ConnectionCtx &ctx, const char* doing);
	void envError(const char* doing);
	bool execDirect;
	bool getConnection(ConnectionCtx &ctx, AuthDbTimings &timings);
	AuthDbResult doRetrievePassword(const string &user, const string &host, const string &auth, string &foundPassword, AuthDbTimings &timings);
	void doAsyncRetrievePassword(su_root_t *, string id, string domain, string auth, string fallback, AuthDbListener *listener);
public:
	virtual AuthDbResult password(su_root_t*, const url_t *from, const char *auth_username, string &foundPassword, AuthDbListener *);
	map<string,string> cachedPasswords;
	void setExecuteDirect(const bool value);
	bool connect(const string &dsn, const string &request, const vector<string> &parameters, int maxIdLength, int maxPassLength);
	bool checkConnection();
	OdbcAuthDb();
};

#endif
