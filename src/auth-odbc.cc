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


#include "auth-odbc.hh"

OdbcConnector *OdbcConnector::instance = NULL;

OdbcConnector* OdbcConnector::getInstance() {
	if (instance == NULL) {
		instance = new OdbcConnector();
	}

	return instance;
}

void OdbcConnector::setExecuteDirect(const bool value) {
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


OdbcConnector::OdbcConnector():idCBuffer(NULL),execDirect(false) {}

OdbcConnector::~OdbcConnector() {
	// Disconnect from database and close everything
	disconnect();
}

void OdbcConnector::envError(const char* doing) {
	logSqlError(doing, env, SQL_HANDLE_ENV);
	disconnect();
}

void OdbcConnector::dbcError(const char* doing) {
	logSqlError(doing, dbc, SQL_HANDLE_DBC);
	disconnect();
}

bool OdbcConnector::connect(const string &d, const string &r, const vector<string> &parameters, int maxIdLength, int maxPassLength) {
	this->connectionString = d;
	this->request = r;
	this->maxIdLength = maxIdLength;
	this->maxPassLength = maxPassLength;
	this->parameters = parameters;

	return reconnect();
}

void OdbcConnector::disconnect() {
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

bool OdbcConnector::reconnect() {
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

		idCBuffer = (char*) malloc(maxIdLength +1);
		// Use isql dsn_name then "help table_name" (without ;) to get information on sql types

		for (size_t i=0; i < parameters.size(); i++) {
			if (parameters[i] != "id") {
				LOGF("Unknown request parameter type : %s", parameters[i].c_str());
			}
			retcode = SQLBindParameter(stmt,i+1,SQL_PARAM_INPUT, SQL_C_CHAR,
					SQL_CHAR, (SQLULEN) maxIdLength, 0,
					idCBuffer, 0, NULL);
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
string OdbcConnector::password(const string &id) throw (int) {
	if (!connected) throw ERROR_NOT_CONNECTED;

	if (id.length() > maxIdLength) throw ERROR_ID_TOO_LONG;
	strncpy(idCBuffer, id.c_str(), maxIdLength);

	SQLRETURN retcode;
	if (execDirect) {
		// execute direct
		LOGD("Requesting password of user with id='%s'", idCBuffer);
		retcode = SQLExecDirect(stmt, (SQLCHAR*) request.c_str(), SQL_NTS);
		if (!SQL_SUCCEEDED(retcode)) {
			logSqlError("SQLExecDirect", stmt, SQL_HANDLE_STMT);
			if (linkFailed("SQLExecDirect", stmt, SQL_HANDLE_STMT)) throw ERROR_LINK_FAILURE;
			throw ERROR;
		}
		LOGD("SQLExecDirect OK");
	} else {
		// Use prepared statement
		LOGD("Requesting password of user with id='%s'", idCBuffer);
		retcode = SQLExecute(stmt);
		if (!SQL_SUCCEEDED(retcode)) {
			logSqlError("SQLExecute", stmt, SQL_HANDLE_STMT);
			if (linkFailed("SQLExecute", stmt, SQL_HANDLE_STMT)) throw ERROR_LINK_FAILURE;
			throw ERROR;
		}
		LOGD("SQLExecute OK");
	}



	if (retcode != SQL_SUCCESS) {
		LOGE("SQLExecute returned no success");
		closeCursor(stmt);
		throw ERROR;
	}

	retcode = SQLFetch(stmt);
	if (retcode == SQL_ERROR || retcode == SQL_SUCCESS_WITH_INFO) {
		LOGE("Fetch error or success with info");
		logSqlError("SQLFetch", stmt, SQL_HANDLE_STMT);
		closeCursor(stmt);
		throw ERROR;
	}

	if (retcode == SQL_NO_DATA) {
		LOGE("No data fetched");
		closeCursor(stmt);
		throw ERROR_PASSWORD_NOT_FOUND;
	}

	SQLLEN cbPass;
	SQLCHAR password[maxPassLength + 1];
	retcode = SQLGetData(stmt, 1, SQL_C_CHAR, password, maxPassLength, &cbPass);
	if (retcode == SQL_ERROR || retcode == SQL_SUCCESS_WITH_INFO) {
		if (retcode == SQL_SUCCESS_WITH_INFO) LOGE("SQLGetData success with info");
		else LOGE("SQLGetData error or success with info - user not found??");
		closeCursor(stmt);
		throw ERROR_PASSWORD_NOT_FOUND;
	}

	closeCursor(stmt);

	cachedPasswords[id] = string((char*)password);

//	LOGD((char*)password);

	return (char*) password;
}
