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


#include "registrar-odbc.hh"


OdbcConnector *OdbcConnector::instance = NULL;

OdbcConnector* OdbcConnector::getInstance() {
	if (instance == NULL) {
		instance = new OdbcConnector();
	}

	return instance;
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
		printf("cb=%ld\n", cb);
		break;
	}
}

static bool linkFailed(string fn, SQLHANDLE handle, SQLSMALLINT handleType) {
	SQLINTEGER i=0;
	SQLINTEGER errorNb;
	SQLCHAR sqlState[7];
	SQLCHAR msg[256];
	SQLSMALLINT msgLen;


	SQLRETURN ret = SQLGetDiagRec(handleType, handle, ++i, sqlState, &errorNb, msg, sizeof(msg), &msgLen);
	if (SQL_SUCCEEDED(ret) && sqlState == (SQLCHAR*) "08S01") {
		LOGE("Odbc link failure while doing %s : %s", fn.c_str(), (char*) msg);
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


OdbcConnector::OdbcConnector() {}

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

bool OdbcConnector::connect(const string &d, const string &r) {
	this->connectionString = d;
	this->request = r;

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
		return false;
	}

	retcode = SQLPrepare(stmt, (SQLCHAR*) request.c_str(), SQL_NTS);
	if (!SQL_SUCCEEDED(retcode)) {
		logSqlError("SQLPrepare request", stmt, SQL_HANDLE_STMT);
		disconnect();
		return false;
	}

	return true;
}

void OdbcConnector::disconnect() {
	  if (stmt) SQLFreeHandle(SQL_HANDLE_STMT, stmt);
	  if (dbc) {
		  SQLDisconnect(dbc);
		  SQLFreeHandle(SQL_HANDLE_DBC, dbc);
	  }
	  if (env) SQLFreeHandle(SQL_HANDLE_ENV, env);
}

static void closeCursor(SQLHSTMT &stmt) {
	if (!SQL_SUCCEEDED(SQLCloseCursor(stmt))) {
		logSqlError("SQLCloseCursor", stmt, SQL_HANDLE_STMT);
	}
}

string OdbcConnector::password(string &id) throw (int) {
	SQLCHAR password[50];
	SQLLEN cbPass;

	char* cId = const_cast<char*>(id.c_str());
	SQLRETURN retcode = SQLBindParameter(stmt,1,SQL_PARAM_INPUT, SQL_C_CHAR, SQL_CHAR, (SQLULEN) 50, 0, cId, 0, &cbPass);
	if (!SQL_SUCCEEDED(retcode)) {
		logSqlError("SQLBindParameter", stmt, SQL_HANDLE_STMT);
		throw ERROR;
	}
	LOGD("SQLBindParameter OK");

	LOGD("Requesting password of user with id='%s'", id.c_str());
	retcode = SQLExecute(stmt);
	if (!SQL_SUCCEEDED(retcode)) {
		showCB(cbPass);
		logSqlError("SQLExecute", stmt, SQL_HANDLE_STMT);
		if (linkFailed("SQLExecute", stmt, SQL_HANDLE_STMT)) throw ERROR_LINK_FAILURE;
		throw ERROR;
	}
	LOGD("SQLExecute OK");

	if (retcode != SQL_SUCCESS) {
		LOGE("SQLExecute returned no success");
		closeCursor(stmt);
		throw ERROR;
	}

	retcode = SQLFetch(stmt);
	if (retcode == SQL_ERROR || retcode == SQL_SUCCESS_WITH_INFO) {
		LOGE("Fetch error or success with info");
		closeCursor(stmt);
		throw ERROR;
	}

	retcode = SQLGetData(stmt, 1, SQL_C_CHAR, password, sizeof(password) -1, &cbPass);
	if (retcode == SQL_ERROR || retcode == SQL_SUCCESS_WITH_INFO) {
		LOGE("SQLGetData error or success with info - user not found??");
		closeCursor(stmt);
		throw ERROR_PASSWORD_NOT_FOUND;
	}

	closeCursor(stmt);
	return (char*) password;
}
