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
#include "common.hh"
#include "agent.hh"

#include <vector>
#include <stdio.h>
#include <sql.h>
#include <sqlext.h>
#include <map>

#include "sofia-sip/auth_module.h"
#include "sofia-sip/auth_plugin.h"

using namespace std;

class AuthDbListener {
	Agent *mAgent;
	shared_ptr<SipEvent> mEv;
	bool mHashedPass;
	auth_mod_t *mAm;
	auth_status_t *mAs;
	auth_response_t *mAr;
	auth_challenger_t const *mAch;
	void checkFoundPassword(const string &password);
public:
	AuthDbListener(Agent *, shared_ptr<SipEvent>, bool);
	void setData(auth_mod_t *am, auth_status_t *as, auth_challenger_t const *ach);
	void passwordRetrievingPending();
	void setAr(auth_response_t *ar);
	~AuthDbListener(){};
	void onAsynchronousPasswordFound(const string &password);
	void onSynchronousPasswordFound(const string &password);
	void onError();
	void sendReplyAndDestroy();
	void sendReply();
};

class AuthDb {
	static AuthDb *sUnique;
	map<string, map<string,string>*> mCachedPasswords;
protected:
	AuthDb();
	void cachePassword(const url_t *from, const char *auth, string &pass);
	string fallback(const url_t *from, const char *auth_username);
	int mCacheExpire;
public:
	virtual ~AuthDb();
	virtual void password(const url_t *from, const char *auth_username, AuthDbListener *listener)=0;
	static AuthDb* get();

	AuthDb (const AuthDb &);
	void operator= (const AuthDb &);
};


class OdbcAuthDb : public AuthDb {
	~OdbcAuthDb();
	string connectionString;
	string request;
	int maxPassLength;
	vector<string> parameters;
	char* idCBuffer;
	char *authIdCBuffer;
	char *domainCBuffer;
	bool connected;
	SQLHENV env;
	SQLHDBC dbc;
	SQLHSTMT stmt;
	void dbcError(const char* doing);
	void envError(const char* doing);
	bool execDirect;
	const static int fieldLength = 500;
public:
	virtual void password(const url_t *from, const char *auth_username, AuthDbListener *listener);
	static const int ERROR_PASSWORD_NOT_FOUND = 0;
	static const int ERROR_LINK_FAILURE = 1;
	static const int ERROR = 2;
	static const int ERROR_ID_TOO_LONG = 3;
	static const int ERROR_NOT_CONNECTED = 4;
	map<string,string> cachedPasswords;
	void setExecuteDirect(const bool value);
	bool connect(const string &dsn, const string &request, const vector<string> &parameters, int maxIdLength, int maxPassLength);
	bool reconnect();
	void disconnect();
	bool checkConnection();
	OdbcAuthDb();
};

#endif
