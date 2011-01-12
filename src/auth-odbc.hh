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

#ifndef _REGISTRAR_AUTH_HH_
#define _REGISTRAR_AUTH_HH_

#include <string>
#include "common.hh"


#include <stdio.h>
#include <sql.h>
#include <sqlext.h>

using namespace std;

class OdbcConnector {
private:
	static OdbcConnector *instance;
	OdbcConnector();
	string connectionString;
	string request;
	SQLHENV env;
	SQLHDBC dbc;
	SQLHSTMT stmt;
	void dbcError(const char* doing);
	void envError(const char* doing);

public:
	virtual ~OdbcConnector();
	virtual string password(const string &id) throw (int);
	static OdbcConnector* getInstance();
	static const int ERROR_PASSWORD_NOT_FOUND = 0;
	static const int ERROR_LINK_FAILURE = 1;
	static const int ERROR = 2;
	bool connect(const string &dsn, const string &request);
	void disconnect();
	bool checkConnection();
	OdbcConnector (const OdbcConnector &);
	void operator= (const OdbcConnector &);
};


#endif
