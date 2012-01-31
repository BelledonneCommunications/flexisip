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


#include "authdb.hh"
#include <vector>
#include <set>


static vector<string> parseAndUpdateRequestConfig(string &request) {
	vector<string> found_parameters;
	bool hasIdParameter = false;
	static set<string> recognizedParameters={"id", "authid", "domain"};

	size_t j=0;
	string pattern (":");
	string space (" ");
	string semicol (";");
	while ((j = request.find(pattern, j)) != string::npos)
	{
		string token = request.substr(j + 1, request.length());
		size_t size_token;
		if ((size_token = token.find(space)) != string::npos
				|| (size_token = token.find(semicol)) != string::npos)
			token = token.substr(0, size_token);

		if (recognizedParameters.find(token) == recognizedParameters.end())  {
			LOGF("Unrecognized parameter in SQL request %s", token.c_str());
		}

		found_parameters.push_back(token);
		if (token == "id") {
			hasIdParameter = true;
		}
		request.replace( j, token.length() + 1, "?" );
	}


	if (!hasIdParameter) {
		LOGF("Couldn't find an :id named parameter in provided request");
	}

	return found_parameters;
}

OdbcAuthDb::OdbcAuthDb():idCBuffer(NULL),authIdCBuffer(NULL),domainCBuffer(NULL),connected(false),env(NULL),dbc(NULL),stmt(NULL),execDirect(false) {
	ConfigStruct *cr=ConfigManager::get()->getRoot();
	ConfigStruct *ma=cr->get<ConfigStruct>("module::Authentication");

	string none = "none";
	string dsn = ma->get<ConfigString>("datasource")->read();
	if (dsn == none) LOGF("Authentication is activated but no datasource found");
	LOGD("Datasource found: %s", dsn.c_str());

	string request = ma->get<ConfigString>("request")->read();
	if (request == none) LOGF("Authentication is activated but no request found");
	LOGD("request found: %s", request.c_str());
	vector<string> requestParms = parseAndUpdateRequestConfig(request);
	LOGD("request parsed: %s", request.c_str());


	int maxIdLength = ma->get<ConfigInt>("max-id-length")->read();
	if (maxIdLength == 0) LOGF("Authentication is activated but no max_id_length found");
	LOGD("maxIdLength found: %i", maxIdLength);

	int maxPassLength = ma->get<ConfigInt>("max-password-length")->read();
	if (maxPassLength == 0) LOGF("Authentication is activated but no max_password_length found");
	LOGD("maxPassLength found: %i", maxPassLength);


	if (connect(dsn, request, requestParms, maxIdLength, maxPassLength)) {
		LOGD("Connection OK");
	} else {
		LOGE("Unable to connect to odbc database");
	}
}

void OdbcAuthDb::setExecuteDirect(const bool value) {
	execDirect = value;
}

void showCB(SQLLEN cb)
{
	printf("showing CB : ");
	switch (cb) {
	case SQL_NULL_DATA:
		printf("NULL data\n");
		break;
	case SQL_NO_TOTAL:
		printf("NO total\n");
		break;
	default:
		printf("cb=%ld\n", (long int)cb);
		break;
	}
}

static bool linkFailed(string fn, SQLHANDLE handle, SQLSMALLINT handleType) {
	SQLINTEGER errorNb;
	SQLCHAR sqlState[7];
	SQLCHAR msg[256];
	SQLSMALLINT msgLen;

	SQLRETURN ret = SQLGetDiagRec(handleType, handle, 1, sqlState, &errorNb, msg, sizeof(msg), &msgLen);
	if (SQL_SUCCEEDED(ret) && strcmp((char*)sqlState, "08S01") == 0) {
		LOGE("Odbc link failure while doing %s : (%s) %s",
				fn.c_str(), (unsigned char*) sqlState, (char*) msg);
		return true;
	}

	return false;
}

static void logSqlError(string fn, SQLHANDLE handle, SQLSMALLINT handleType) {
	SQLINTEGER i=0;
	SQLINTEGER errorNb;
	SQLCHAR sqlState[7];
	SQLCHAR msg[256];
	SQLSMALLINT msgLen;
	SQLRETURN ret;

	LOGE("Odbc driver errors while doing %s",	fn.c_str());
	do {
		ret = SQLGetDiagRec(handleType, handle, ++i, sqlState, &errorNb, msg, sizeof(msg), &msgLen);
		if (SQL_SUCCEEDED(ret))
			LOGE("%s:%i:%i:%s", (char*) sqlState, (int) i, (int) errorNb, msg);
	} while(ret == SQL_SUCCESS);
}


OdbcAuthDb::~OdbcAuthDb() {
	// Disconnect from database and close everything
	disconnect();
}

void OdbcAuthDb::envError(const char* doing) {
	logSqlError(doing, env, SQL_HANDLE_ENV);
	disconnect();
}

void OdbcAuthDb::dbcError(const char* doing) {
	logSqlError(doing, dbc, SQL_HANDLE_DBC);
	disconnect();
}

bool OdbcAuthDb::connect(const string &d, const string &r, const vector<string> &parameters, int maxIdLength, int maxPassLength) {
	this->connectionString = d;
	this->request = r;
	this->maxPassLength = maxPassLength;
	this->parameters = parameters;

	return reconnect();
}

void OdbcAuthDb::disconnect() {
	LOGD("disconnecting odbc connector");
	if (idCBuffer != NULL) free(idCBuffer); idCBuffer = NULL;
	if (stmt) SQLFreeHandle(SQL_HANDLE_STMT, stmt);
	if (dbc) {
		SQLDisconnect(dbc);
		SQLFreeHandle(SQL_HANDLE_DBC, dbc);
	}
	if (env) SQLFreeHandle(SQL_HANDLE_ENV, env);
	connected = false;
}

bool OdbcAuthDb::reconnect() {
	if (connected) disconnect();

	LOGD("(re-)connecting odbc connector");
	SQLRETURN retcode = SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &env);

	retcode = SQLSetEnvAttr(env, SQL_ATTR_ODBC_VERSION, (void *) SQL_OV_ODBC3, 0);
	if (!SQL_SUCCEEDED(retcode)) {envError("SQLSetEnvAttr ODBCv3"); return false;}

	retcode = SQLAllocHandle(SQL_HANDLE_DBC, env, &dbc);
	if (!SQL_SUCCEEDED(retcode)) {envError("SQLAllocHandle DBC"); return false;}

	retcode = SQLDriverConnect(dbc, NULL, (SQLCHAR*) connectionString.c_str(), SQL_NTS, NULL, 0, NULL, SQL_DRIVER_COMPLETE);
	if (!SQL_SUCCEEDED(retcode)) {dbcError("SQLDriverConnect");	return false;}

	// Set connection to be read only
	SQLSetConnectAttr(dbc, SQL_ATTR_ACCESS_MODE, (SQLPOINTER)SQL_MODE_READ_ONLY, 0);
	if (!SQL_SUCCEEDED(retcode)) {dbcError("SQLSetConnectAttr"); return false;}
	LOGD("SQLDriverConnect OK");


	retcode = SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt);
	if (!SQL_SUCCEEDED(retcode)) {
		logSqlError("SQLAllocHandle STMT", dbc, SQL_HANDLE_DBC);
		disconnect();
		return connected;
	}

	if (!execDirect) {
		retcode = SQLPrepare(stmt, (SQLCHAR*) request.c_str(), SQL_NTS);
		if (!SQL_SUCCEEDED(retcode)) {
			logSqlError("SQLPrepare request", stmt, SQL_HANDLE_STMT);
			disconnect();
			return connected;
		}

		idCBuffer = (char*) malloc(fieldLength +1);
		authIdCBuffer = (char*) malloc(fieldLength +1);
		domainCBuffer = (char*) malloc(fieldLength +1);
		// Use isql dsn_name then "help table_name" (without ;) to get information on sql types


		for (size_t i=0; i < parameters.size(); i++) {
			char *fieldBuffer;
			if (parameters[i] == "id") {
				fieldBuffer=idCBuffer;
			} else if (parameters[i] == "authid") {
				fieldBuffer=authIdCBuffer;
			} else if (parameters[i] == "domain") {
				fieldBuffer=domainCBuffer;
			} else {
				LOGF("unhandled parameter %s", parameters[i].c_str());
			}
			retcode = SQLBindParameter(stmt,i+1,SQL_PARAM_INPUT, SQL_C_CHAR,
					SQL_CHAR, (SQLULEN) fieldLength, 0,
					fieldBuffer, 0, NULL);
			if (!SQL_SUCCEEDED(retcode)) {
				logSqlError("SQLBindParameter", stmt, SQL_HANDLE_STMT);
				throw ERROR;
			}
		}
		LOGD("SQLBindParameter OK");
	}

	connected = true;
	return true;
}

static void closeCursor(SQLHSTMT &stmt) {
	if (!SQL_SUCCEEDED(SQLCloseCursor(stmt))) {
		logSqlError("SQLCloseCursor", stmt, SQL_HANDLE_STMT);
	}
}

/* Neither this method nor the class is thread safe */
void OdbcAuthDb::password(const url_t *from, const char *auth_username, AuthDbListener *listener){
	if (listener == NULL) return; // caching not handled
	if (!connected) {
		listener->onError();
		return;
	}

	const char *id=from->url_user;
	const char *domain=from->url_host;
	const char *auth=auth_username;

	strncpy(idCBuffer, id, fieldLength);
	strncpy(domainCBuffer, domain, fieldLength);
	strncpy(authIdCBuffer, auth, fieldLength);

	SQLRETURN retcode;
	if (execDirect) {
		// execute direct
		LOGD("Requesting password of user with id='%s'", idCBuffer);
		retcode = SQLExecDirect(stmt, (SQLCHAR*) request.c_str(), SQL_NTS);
		if (!SQL_SUCCEEDED(retcode)) {
			logSqlError("SQLExecDirect", stmt, SQL_HANDLE_STMT);
			if (linkFailed("SQLExecDirect", stmt, SQL_HANDLE_STMT)) throw ERROR_LINK_FAILURE;
			listener->onError();
			return;
		}
		LOGD("SQLExecDirect OK");
	} else {
		// Use prepared statement
		LOGD("Requesting password of user with id='%s'", idCBuffer);
		retcode = SQLExecute(stmt);
		if (!SQL_SUCCEEDED(retcode)) {
			logSqlError("SQLExecute", stmt, SQL_HANDLE_STMT);
			if (linkFailed("SQLExecute", stmt, SQL_HANDLE_STMT)) throw ERROR_LINK_FAILURE;
			listener->onError();
			return;
		}
		LOGD("SQLExecute OK");
	}



	if (retcode != SQL_SUCCESS) {
		LOGE("SQLExecute returned no success");
		closeCursor(stmt);
		listener->onError();
		return;
	}

	retcode = SQLFetch(stmt);
	if (retcode == SQL_ERROR || retcode == SQL_SUCCESS_WITH_INFO) {
		LOGE("Fetch error or success with info");
		logSqlError("SQLFetch", stmt, SQL_HANDLE_STMT);
		closeCursor(stmt);
		listener->onError();
		return;
	}

	if (retcode == SQL_NO_DATA) {
		LOGE("No data fetched");
		closeCursor(stmt);
		listener->onError();
		return;
	}

	SQLLEN cbPass;
	SQLCHAR password[maxPassLength + 1];
	retcode = SQLGetData(stmt, 1, SQL_C_CHAR, password, maxPassLength, &cbPass);
	if (retcode == SQL_ERROR || retcode == SQL_SUCCESS_WITH_INFO) {
		if (retcode == SQL_SUCCESS_WITH_INFO) LOGD("SQLGetData success with info");
		else LOGD("SQLGetData error or success with info - user not found??");
		closeCursor(stmt);
		listener->onError();
		return;
	}

	closeCursor(stmt);

	string cppPassword=string((char*)password);
	cachePassword(from, auth, cppPassword);

	listener->onSynchronousPasswordFound(cppPassword);
}
