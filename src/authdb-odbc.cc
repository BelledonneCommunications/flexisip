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

#define SU_MSG_ARG_T struct auth_splugin_t

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

OdbcAuthDb::OdbcAuthDb():env(NULL),execDirect(false) {
	ConfigStruct *cr=ConfigManager::get()->getRoot();
	ConfigStruct *ma=cr->get<ConfigStruct>("module::Authentication");

	string none = "none";
	connectionString = ma->get<ConfigString>("datasource")->read();
	if (connectionString == none) LOGF("Authentication is activated but no datasource found");
	LOGD("Datasource found: %s", connectionString.c_str());

	request = ma->get<ConfigString>("request")->read();
	if (request == none) LOGF("Authentication is activated but no request found");
	LOGD("request found: %s", request.c_str());
	parameters = parseAndUpdateRequestConfig(request);
	LOGD("request parsed: %s", request.c_str());


	maxPassLength = ma->get<ConfigInt>("max-password-length")->read();
	if (maxPassLength == 0) LOGF("Authentication is activated but no max_password_length found");
	LOGD("maxPassLength found: %i", maxPassLength);

	asPooling=ma->get<ConfigBoolean>("odbc-pooling")->read();

	SQLRETURN retcode;
	if (asPooling) {
		retcode = SQLSetEnvAttr(NULL, SQL_ATTR_CONNECTION_POOLING, (void*)SQL_CP_ONE_PER_HENV, 0);
		if (!SQL_SUCCEEDED(retcode)) {
			envError("SQLSetEnvAttr SQL_ATTR_CONNECTION_POOLING=SQL_CP_ONE_PER_HENV");
			LOGF("odbc error");
		}
	}

	retcode = SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &env);
	retcode = SQLSetEnvAttr(env, SQL_ATTR_ODBC_VERSION, (void *) SQL_OV_ODBC3, 0);
	if (!SQL_SUCCEEDED(retcode)) {
		envError("SQLSetEnvAttr ODBCv3");
		LOGF("odbc error");
	}
}

void OdbcAuthDb::setExecuteDirect(const bool value) {
	execDirect = value;
}

void showCB(SQLLEN cb)
{
	LOGD("showing CB : ");
	switch (cb) {
	case SQL_NULL_DATA:
		LOGD("NULL data");
		break;
	case SQL_NO_TOTAL:
		LOGD("NO total");
		break;
	default:
		LOGD("cb=%ld", (long int)cb);
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

	LOGE("Odbc driver errors while doing %s", fn.c_str());
	do {
		ret = SQLGetDiagRec(handleType, handle, ++i, sqlState, &errorNb, msg, sizeof(msg), &msgLen);
		if (SQL_SUCCEEDED(ret))
			LOGE("%s:%i:%i:%s", (char*) sqlState, (int) i, (int) errorNb, msg);
	} while(ret == SQL_SUCCESS);
}


OdbcAuthDb::~OdbcAuthDb() {
	// Disconnect from database and close everything
	LOGD("disconnecting odbc connector");
	if (env) SQLFreeHandle(SQL_HANDLE_ENV, env);
}

void OdbcAuthDb::envError(const char* doing) {
	logSqlError(doing, env, SQL_HANDLE_ENV);
}

void OdbcAuthDb::dbcError(ConnectionCtx &ctx, const char* doing) {
	logSqlError(doing, ctx.dbc, SQL_HANDLE_DBC);
}




bool OdbcAuthDb::getConnection(ConnectionCtx &ctx) {
	SQLHDBC &dbc=ctx.dbc;
	SQLHSTMT &stmt=ctx.stmt;

	SQLRETURN retcode = SQLAllocHandle(SQL_HANDLE_DBC, env, &dbc);
	if (!SQL_SUCCEEDED(retcode)) {envError("SQLAllocHandle DBC"); return false;}

	retcode = SQLDriverConnect(dbc, NULL, (SQLCHAR*) connectionString.c_str(), SQL_NTS, NULL, 0, NULL, SQL_DRIVER_COMPLETE);
	if (!SQL_SUCCEEDED(retcode)) {dbcError(ctx, "SQLDriverConnect"); return false;}

	// Set connection to be read only
	SQLSetConnectAttr(dbc, SQL_ATTR_ACCESS_MODE, (SQLPOINTER)SQL_MODE_READ_ONLY, 0);
	if (!SQL_SUCCEEDED(retcode)) {dbcError(ctx, "SQLSetConnectAttr"); return false;}
	LOGD("SQLDriverConnect OK");


	retcode = SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt);
	if (!SQL_SUCCEEDED(retcode)) {
		logSqlError("SQLAllocHandle STMT", dbc, SQL_HANDLE_DBC);
		return false;
	}

	if (!execDirect) {
		retcode = SQLPrepare(stmt, (SQLCHAR*) request.c_str(), SQL_NTS);
		if (!SQL_SUCCEEDED(retcode)) {
			logSqlError("SQLPrepare request", stmt, SQL_HANDLE_STMT);
			return false;
		}

		// Use isql dsn_name then "help table_name" (without ;) to get information on sql types

		for (size_t i=0; i < parameters.size(); i++) {
			char *fieldBuffer;
			if (parameters[i] == "id") {
				fieldBuffer=(char*) &ctx.idCBuffer;
			} else if (parameters[i] == "authid") {
				fieldBuffer=(char*) &ctx.authIdCBuffer;
			} else if (parameters[i] == "domain") {
				fieldBuffer=(char*) &ctx.domainCBuffer;
			} else {
				LOGF("unhandled parameter %s", parameters[i].c_str());
			}
			LOGD("SQLBindParameter %u -> %s", (unsigned int) i, parameters[i].c_str());
			retcode = SQLBindParameter(stmt,i+1,SQL_PARAM_INPUT, SQL_C_CHAR,
					SQL_CHAR, (SQLULEN) fieldLength, 0,
					fieldBuffer, 0, NULL);
			if (!SQL_SUCCEEDED(retcode)) {
				logSqlError("SQLBindParameter", stmt, SQL_HANDLE_STMT);
				LOGF("couldn't bind parameter");
			}
		}
		LOGD("SQLBindParameter bind OK [%u]", (unsigned int)parameters.size());
	}

	return true;
}

static void closeCursor(SQLHSTMT &stmt) {
	if (!SQL_SUCCEEDED(SQLCloseCursor(stmt))) {
		logSqlError("SQLCloseCursor", stmt, SQL_HANDLE_STMT);
	}
}




AuthDbResult OdbcAuthDb::password(const url_t *from, const char *auth_username, string &foundPassword, AuthDbListener *listener){
	// Check for usable cached password
	string id(from->url_user);
	string domain(from->url_host);
	string auth(auth_username);

	time_t now=time(NULL);
	string key(createPasswordKey(id, domain, auth));
	switch(getCachedPassword(key, domain, foundPassword, now)) {
	case VALID_PASS_FOUND:
		return AuthDbResult::PASSWORD_FOUND;
	case EXPIRED_PASS_FOUND:
		// Check failing connection
		//return AuthDbResult::PASSWORD_FOUND;
		break;
	case NO_PASS_FOUND:
		break;
	}

	LOGD("YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY");
	// Retrieve password
	thread t(std::bind(&OdbcAuthDb::doAsyncRetrievePassword, this, id, domain, auth, listener));
	t.detach();	// Thread will continue running in detached mode
	return PENDING;
}

struct auth_splugin_t
{
  AuthDbListener *listener;
  char *pass;
  int found;
};

/*
static void main_thread_async_response(su_root_magic_t *rm,
				     su_msg_r msg,
				     auth_splugin_t *u) {
	// Better to get cached password here

	switch (u->found) {
	case PASSWORD_FOUND:
		LOGI("AAAAAAAAAAAAAAAAAAAAA");
		if (u->listener) {
			u->listener->onAsynchronousPasswordFound(u->pass);
			free(u->pass);
		}
		return;
	case PASSWORD_NOT_FOUND:
		LOGI("BBBBBBBBBBBBBBBBBBBB");
		break;
	case AUTH_ERROR:
		LOGI("CCCCCCCCCCCCCCCCCCCCCc");
		break;
	}
	if (u->listener) {
		u->listener->onError();
	}
}
*/
void OdbcAuthDb::doAsyncRetrievePassword(string id, string domain, string auth, AuthDbListener *listener){
	string foundPassword;

	/*
	su_msg_r mamc = SU_MSG_R_INIT;
	if (-1 == su_msg_create(mamc,
			su_root_task(root),
			su_root_task(root),
			main_thread_async_response,
			sizeof(auth_splugin_t))) {
		LOGF("Couldn't create auth async message");
	}


	auth_splugin_t *asp = su_msg_data(mamc);
	asp->listener = listener;
	asp->pass = NULL;
	unique_lock<mutex> lck(mCreateHandleMutex);
	asp->found=doRetrievePassword(id, domain, auth, foundPassword);
	lck.unlock();
	switch (asp->found) {
		case PASSWORD_FOUND:
			LOGI("Found password %s for %s", foundPassword.c_str(), id.c_str());
			asp->pass = strdup(foundPassword.c_str());
			break;
		case PASSWORD_NOT_FOUND:
			LOGI("No password found for %s", id.c_str());
			break;
		case AUTH_ERROR:
			LOGI("Error retrieving password for %s", id.c_str());
			// TODO: use expired one
			break;
		default:
			LOGF("Unhandled case");
	}

	if (-1 == su_msg_send(mamc)) {
		LOGF("Couldn't send auth async message to main thread.");
	}
	*/
}

AuthDbResult OdbcAuthDb::doRetrievePassword(const string &id, const string &domain, const string &auth, string &foundPassword){
	ConnectionCtx ctx;
	if (!getConnection(ctx)) {
		return AUTH_ERROR;
	}
	SQLHANDLE stmt=ctx.stmt;

	strncpy((char*)&ctx.idCBuffer, id.c_str(), fieldLength);
	strncpy((char*)&ctx.domainCBuffer, domain.c_str(), fieldLength);
	strncpy((char*)&ctx.authIdCBuffer, auth.c_str(), fieldLength);

	SQLRETURN retcode;
	if (execDirect) {
		// execute direct
		LOGD("Requesting password of user with id='%s'", (char*)&ctx.idCBuffer);
		retcode = SQLExecDirect(stmt, (SQLCHAR*) request.c_str(), SQL_NTS);
		if (!SQL_SUCCEEDED(retcode)) {
			logSqlError("SQLExecDirect", stmt, SQL_HANDLE_STMT);
			linkFailed("SQLExecDirect", stmt, SQL_HANDLE_STMT);
			return AUTH_ERROR;
		}
		LOGD("SQLExecDirect OK");
	} else {
		// Use prepared statement
		LOGD("Requesting password of user with id='%s'", (char*)&ctx.idCBuffer);
		retcode = SQLExecute(stmt);
		if (!SQL_SUCCEEDED(retcode)) {
			logSqlError("SQLExecute", stmt, SQL_HANDLE_STMT);
			linkFailed("SQLExecute", stmt, SQL_HANDLE_STMT);
			return AUTH_ERROR;
		}
		LOGD("SQLExecute OK");
	}



	if (retcode != SQL_SUCCESS) {
		LOGE("SQLExecute returned no success");
		closeCursor(stmt);
		return AUTH_ERROR;
	}

	retcode = SQLFetch(stmt);
	if (retcode == SQL_ERROR || retcode == SQL_SUCCESS_WITH_INFO) {
		LOGE("Fetch error or success with info");
		logSqlError("SQLFetch", stmt, SQL_HANDLE_STMT);
		closeCursor(stmt);
		return AUTH_ERROR;
	}

	if (retcode == SQL_NO_DATA) {
		LOGE("No data fetched");
		closeCursor(stmt);
		return AUTH_ERROR;
	}

	SQLLEN cbPass;
	SQLCHAR password[maxPassLength + 1];
	retcode = SQLGetData(stmt, 1, SQL_C_CHAR, password, maxPassLength, &cbPass);
	if (retcode == SQL_ERROR || retcode == SQL_SUCCESS_WITH_INFO) {
		if (retcode == SQL_SUCCESS_WITH_INFO) LOGD("SQLGetData success with info");
		else LOGD("SQLGetData error or success with info - user not found??");
		closeCursor(stmt);
		return PASSWORD_NOT_FOUND;
	}

	closeCursor(stmt);

	foundPassword.assign((char*)password);
	string key(createPasswordKey(id, domain, auth));
	cachePassword(key, domain, foundPassword, time(NULL));
	return PASSWORD_FOUND;
}
