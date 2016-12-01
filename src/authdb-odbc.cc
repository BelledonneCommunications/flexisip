/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2010-2015  Belledonne Communications SARL, All rights reserved.

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
#define SU_MSG_ARG_T void

#include "authdb.hh"
#include <vector>
#include <set>
#include <chrono>

using namespace std;
using namespace chrono;

#ifdef USE_MONOTONIC_CLOCK
namespace std {
typedef monotonic_clock steady_clock;
}
#endif

struct AuthDbTimingsAnalyzer;

struct AuthDbTimings {
	static AuthDbTimingsAnalyzer analyzerFull;
	static AuthDbTimingsAnalyzer analyzerRetr;
	bool error;
	AuthDbTimings() : error(false) {
	}

	steady_clock::time_point tStart;
	steady_clock::time_point tGotConnection;
	steady_clock::time_point tGotResult;
	steady_clock::time_point tEnd;

	void done();
};

// To get 3000 authentications per second
// The average duration should be ~300 microseconds per authentication.
struct AuthDbTimingsAnalyzer {
	static const long maxDurationSlow = 14000; // 700 auth/s
	static const long maxDuration = 600;	   // 1500 auth/s
	static const int steps = 14;
	static const long stepSize = maxDuration / steps;
	static const int LineWidth = 50;

	static mutex tMutex;
	static int displayStatsInterval;
	static int displayStatsAfterCount;

	steady_clock::time_point lastDisplay;
	long errorCount;

	long count;
	long slowCount;
	long slowestCount;

	float average;
	float slowAverage;
	float slowestAverage;

	long maxLineWidth;
	float durations[steps + 1];

	void reset() {
		lastDisplay = steady_clock::now();
		count = 0;
		errorCount = 0;
		slowCount = 0;
		slowestCount = 0;
		average = 0;
		slowAverage = 0;
		slowestAverage = 0;
		memset(durations, 0, sizeof(durations));
		maxLineWidth = 0;
	}

	AuthDbTimingsAnalyzer() {
		reset();
	}

	void compute(const char *name, steady_clock::time_point &t1, steady_clock::time_point &t2, bool error) {
		if (error) {
			tMutex.lock();
			++errorCount;
			tMutex.unlock();
			return;
		}

		// microseconds duration = t2-t1;
		long ticks = /*duration*/ (t2 - t1).count();

		tMutex.lock();

		average = (count * average + ticks) / (count + 1);
		++count;
		if (ticks > maxDuration) {
			// LOGI("bigger max: %f", duration);
			if (ticks > maxDurationSlow) {
				slowestAverage = (slowestCount * slowestAverage + ticks) / (slowestCount + 1);
				++slowestCount;
			}
			slowAverage = (slowCount * slowAverage + ticks) / (slowCount + 1);
			++slowCount;
			ticks = maxDuration;
		}
		long index = (long)(ticks / stepSize);
		++(durations[index]);
		if (durations[index] > maxLineWidth)
			++maxLineWidth;

		// Show statistics each 10'000 timings
		if (displayStatsAfterCount && count == 10000) {
			display(name);
			reset();
		}
		// Or every 10 seconds
		if (displayStatsInterval && duration_cast<seconds>(t1 - lastDisplay).count() >= displayStatsInterval) {
			display(name);
			reset();
		}
		tMutex.unlock();
	}

	void display(const char *name) {
		LOGI("%lu [%lu micro] timings (%lu errors) %lu [%lu micro] slow - %lu [%lu millis] slowest", count,
			 (long)average, errorCount, slowCount, (long)slowAverage, slowestCount, ((long)slowestAverage) / 1000);
		double lDiv = ((double)maxLineWidth) / LineWidth;
		LOGI("Displaying %s, %u steps [%lu - %lu] - max %lu - div %f", name, steps, 0l, maxDuration, maxLineWidth,
			 lDiv);
		if (lDiv == 0.f) {
			LOGI("Skipping display with no maxcount");
			return;
		}

		for (int i = 0; i < steps; ++i) {
			char line[LineWidth + 1] = {0};
			int lineWidth = (int)(durations[i] / lDiv);
			memset(line, '#', lineWidth);
			LOGI("[%u-%u] %s", (int)(i * stepSize), (int)((i + 1) * stepSize), line);
		}
	}
};
mutex AuthDbTimingsAnalyzer::tMutex;
int AuthDbTimingsAnalyzer::displayStatsInterval = 0;   // 0 to disable
int AuthDbTimingsAnalyzer::displayStatsAfterCount = 0; // 0 to disable
AuthDbTimingsAnalyzer AuthDbTimings::analyzerFull;
AuthDbTimingsAnalyzer AuthDbTimings::analyzerRetr;

void AuthDbTimings::done() {
	analyzerFull.compute("full", tStart, tEnd, error);
	analyzerRetr.compute("pass retrieving", tGotConnection, tGotResult, error);
}

static vector<string> parseAndUpdateRequestConfig(string &request) {
	vector<string> found_parameters;
	bool hasIdParameter = false;
	static set<string> recognizedParameters = {"id", "authid", "domain"};

	size_t j = 0;
	string pattern(":");
	string space(" ");
	string semicol(";");
	while ((j = request.find(pattern, j)) != string::npos) {
		string token = request.substr(j + 1, request.length());
		size_t size_token;
		if ((size_token = token.find(space)) != string::npos || (size_token = token.find(semicol)) != string::npos)
			token = token.substr(0, size_token);

		if (recognizedParameters.find(token) == recognizedParameters.end()) {
			LOGF("Unrecognized parameter in SQL request %s", token.c_str());
		}

		found_parameters.push_back(token);
		if (token == "id") {
			hasIdParameter = true;
		}
		request.replace(j, token.length() + 1, "?");
	}

	if (!hasIdParameter) {
		LOGF("Couldn't find an :id named parameter in provided request");
	}

	return found_parameters;
}

/**
 * See documentation on ODBC on Microsoft pages:
 * http://msdn.microsoft.com/en-us/library/ms716319%28v=VS.85%29.aspx
 */
OdbcAuthDb::OdbcAuthDb() : mAsynchronousRetrieving(true), env(NULL), execDirect(false) {
	GenericStruct *cr = GenericManager::get()->getRoot();
	GenericStruct *ma = cr->get<GenericStruct>("module::Authentication");

	string none = "none";
	connectionString = ma->get<ConfigString>("datasource")->read();
	if (connectionString == none)
		LOGF("Authentication is activated but no datasource found");
	LOGD("Datasource found: %s", connectionString.c_str());

	request = ma->get<ConfigString>("request")->read();
	if (request == none)
		LOGF("Authentication is activated but no request found");
	LOGD("request found: %s", request.c_str());
	parameters = parseAndUpdateRequestConfig(request);
	LOGD("request parsed: %s", request.c_str());

	maxPassLength = 256;

	AuthDbTimingsAnalyzer::displayStatsInterval = ma->get<ConfigInt>("odbc-display-timings-interval")->read();
	AuthDbTimingsAnalyzer::displayStatsAfterCount = ma->get<ConfigInt>("odbc-display-timings-after-count")->read();

	mAsynchronousRetrieving = true;
	LOGD("%s password retrieving", mAsynchronousRetrieving ? "Asynchronous" : "Synchronous");

	asPooling = ma->get<ConfigBoolean>("odbc-pooling")->read();

	SQLRETURN retcode;
	// 1. Enable or disable connection pooling.
	// It should be done BEFORE allocating the environment.
	// Note: this is useless with the unixODBC implementation:
	// the pooling attribute of env is set during allocation
	// if odbcinst.ini/Pooling=1, and the SQL_ATTR_CONNECTION_POOLING doesn't mean
	// anything to unixODBC. Sob.
	unsigned long poolingPtr = asPooling ? SQL_CP_ONE_PER_DRIVER : SQL_CP_OFF;
	retcode = SQLSetEnvAttr(NULL, SQL_ATTR_CONNECTION_POOLING, (void *)poolingPtr, 0);
	if (!SQL_SUCCEEDED(retcode)) {
		envError("SQLSetEnvAttr SQL_ATTR_CONNECTION_POOLING=SQL_CP_ONE_PER_DRIVER");
		LOGF("odbc error");
	}

	// 2. Allocate environment
	retcode = SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &env);
	if (!SQL_SUCCEEDED(retcode)) {
		LOGF("Error allocating ENV");
	}

	// 3. Use ODBC version 3
	retcode = SQLSetEnvAttr(env, SQL_ATTR_ODBC_VERSION, (void *)SQL_OV_ODBC3, 0);
	if (!SQL_SUCCEEDED(retcode)) {
		envError("SQLSetEnvAttr ODBCv3");
		LOGF("odbc error");
	}
/*SM: this follow code is really a crap because it blocks flexisip entirely at startup if the database is not
 *responding.
 *  However it is required because mysql client lib segfaults like a shit when used from a thread for the first.
 **/
#if 1
	// Make sure the driver library is loaded.
	AuthDbTimings timings;
	ConnectionCtx ctx;
	string init = "init";
	getConnection(init, ctx, timings);
#endif
}

void OdbcAuthDb::declareConfig(GenericStruct *mc) {

	// ODBC-specific configuration keys
	ConfigItemDescriptor items[] = {

		{String, "request", "Odbc SQL request to execute to obtain the password \n. "
							"Named parameters are :id (the user found in the from header), :domain (the authorization "
							"realm) and :authid (the authorization username). "
							"The use of the :id parameter is mandatory.",
		 "select password from accounts where id = :id and domain = :domain and authid=:authid"},

		{Boolean, "odbc-pooling", "Use pooling in ODBC (improves performances). This is not guaranteed to succeed, "
								  "because if you are using unixODBC, it consults the /etc/odbcinst.ini"
								  "file in section [ODBC] to check for Pooling=yes/no option. You should make sure "
								  "that this flag is set before expecting this option to work.",
		 "true"},

		{Integer, "odbc-display-timings-interval", "Display timing statistics after this count of seconds", "0"},

		{Integer, "odbc-display-timings-after-count",
		 "Display timing statistics once the number of samples reach this number.", "0"},

		config_item_end};

	mc->addChildrenValues(items);
}

void OdbcAuthDb::setExecuteDirect(const bool value) {
	execDirect = value;
}

void showCB(SQLLEN cb) {
	switch (cb) {
		case SQL_NULL_DATA:
			LOGD("CB : NULL data");
			break;
		case SQL_NO_TOTAL:
			LOGD("CB : NO total");
			break;
		default:
			LOGD("CB : %ld", (long int)cb);
			break;
	}
}

static bool linkFailed(string fn, SQLHANDLE handle, SQLSMALLINT handleType) {
	SQLINTEGER errorNb;
	SQLCHAR sqlState[7];
	SQLCHAR msg[256];
	SQLSMALLINT msgLen;

	SQLRETURN ret = SQLGetDiagRec(handleType, handle, 1, sqlState, &errorNb, msg, sizeof(msg), &msgLen);
	if (SQL_SUCCEEDED(ret) && strcmp((char *)sqlState, "08S01") == 0) {
		LOGE("Odbc link failure while doing %s : (%s) %s", fn.c_str(), (unsigned char *)sqlState, (char *)msg);
		return true;
	}

	return false;
}

static void logSqlError(string fn, SQLHANDLE handle, SQLSMALLINT handleType) {
	SQLINTEGER i = 0;
	SQLINTEGER errorNb;
	SQLCHAR sqlState[7];
	SQLCHAR msg[256];
	SQLSMALLINT msgLen;
	SQLRETURN ret;

	LOGE("Odbc driver errors while doing %s", fn.c_str());
	do {
		ret = SQLGetDiagRec(handleType, handle, ++i, sqlState, &errorNb, msg, sizeof(msg), &msgLen);
		if (SQL_SUCCEEDED(ret))
			LOGE("%s:%i:%i:%s", (char *)sqlState, (int)i, (int)errorNb, msg);
	} while (ret == SQL_SUCCESS);
}

OdbcAuthDb::~OdbcAuthDb() {
	// Destroy environment
	// All connection should be destroyed already
	LOGD("Disconnecting odbc connector");
	if (env)
		SQLFreeHandle(SQL_HANDLE_ENV, env);
}

void OdbcAuthDb::envError(const char *doing) {
	logSqlError(doing, env, SQL_HANDLE_ENV);
}

void OdbcAuthDb::dbcError(ConnectionCtx &ctx, const char *doing) {
	logSqlError(doing, ctx.dbc, SQL_HANDLE_DBC);
}

void OdbcAuthDb::stmtError(ConnectionCtx &ctx, const char *doing) {
	logSqlError(doing, ctx.stmt, SQL_HANDLE_STMT);
}

bool OdbcAuthDb::getConnection(const string &id, ConnectionCtx &ctx, AuthDbTimings &timings) {
	steady_clock::time_point tp1 = steady_clock::now();

	// Create a 'wrapper' connection attached to nothing
	SQLRETURN retcode = SQLAllocHandle(SQL_HANDLE_DBC, env, &ctx.dbc);
	if (!SQL_SUCCEEDED(retcode)) {
		envError("SQLAllocHandle DBC");
		return false;
	}
	steady_clock::time_point tp2 = steady_clock::now();

	// when debug is not active, the compiler complains about tp1 and tp2 not being used.
	(void)tp1;
	(void)tp2;

	LOGD("SQLAllocHandle: %s : %lu ms", id.c_str(), (unsigned long)duration_cast<milliseconds>(tp2 - tp1).count());

	// Either:
	// - reuse an underlying connection from the pool;
	// - establish an underlying connecion;
	// Attach underlying to wrapper.
	retcode = SQLDriverConnect(ctx.dbc, NULL, (SQLCHAR *)connectionString.c_str(), SQL_NTS, NULL, 0, NULL,
							   SQL_DRIVER_COMPLETE);
	if (!SQL_SUCCEEDED(retcode)) {
		dbcError(ctx, "SQLDriverConnect");
		return false;
	}
	LOGD("SQLDriverConnect %s : %lu ms", id.c_str(),
		 (unsigned long)duration_cast<milliseconds>(steady_clock::now() - tp2).count());

	// Set connection to be read only
	SQLSetConnectAttr(ctx.dbc, SQL_ATTR_ACCESS_MODE, (SQLPOINTER)SQL_MODE_READ_ONLY, 0);
	if (!SQL_SUCCEEDED(retcode)) {
		dbcError(ctx, "SQLSetConnectAttr");
		return false;
	}

	retcode = SQLAllocHandle(SQL_HANDLE_STMT, ctx.dbc, &ctx.stmt);
	if (!SQL_SUCCEEDED(retcode)) {
		dbcError(ctx, "SQLAllocHandle STMT");
		return false;
	}

	if (!execDirect) {
		retcode = SQLPrepare(ctx.stmt, (SQLCHAR *)request.c_str(), SQL_NTS);
		if (!SQL_SUCCEEDED(retcode)) {
			stmtError(ctx, "SQLPrepare request");
			return false;
		}

		// Use isql dsn_name then "help table_name" (without ;) to get information on sql types

		for (size_t i = 0; i < parameters.size(); i++) {
			char *fieldBuffer;
			if (parameters[i] == "id") {
				fieldBuffer = ctx.idCBuffer;
			} else if (parameters[i] == "authid") {
				fieldBuffer = ctx.authIdCBuffer;
			} else if (parameters[i] == "domain") {
				fieldBuffer = ctx.domainCBuffer;
			} else {
				LOGF("unhandled parameter %s", parameters[i].c_str());
			}
			LOGD("SQLBindParameter %u -> %s", (unsigned int)i, parameters[i].c_str());
			retcode = SQLBindParameter(ctx.stmt, i + 1, SQL_PARAM_INPUT, SQL_C_CHAR, SQL_CHAR, (SQLULEN)fieldLength, 0,
									   fieldBuffer, 0, NULL);
			if (!SQL_SUCCEEDED(retcode)) {
				logSqlError("SQLBindParameter", ctx.stmt, SQL_HANDLE_STMT);
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

void OdbcAuthDb::getPasswordFromBackend(const std::string &id, const std::string &domain,
										const std::string &authid, AuthDbListener *listener) {

	if (mAsynchronousRetrieving) {
		// Asynchronously retrieve password in a new thread.
		// Allocate on the stack and detach. It is lawful since:
		// "When detach() returns, *this no longer represents the possibly continuing thread of execution."

		thread t = thread(bind(&OdbcAuthDb::doAsyncRetrievePassword, this, id, domain, authid, listener));
		t.detach(); // Thread will continue running in detached mode
		return;
	} else {
		AuthDbTimings timings;
		string foundPassword;
		timings.tStart = steady_clock::now();
		ConnectionCtx ctx;
		AuthDbResult ret = doRetrievePassword(ctx, id, domain, authid, foundPassword, timings);
		timings.tEnd = steady_clock::now();
		if (ret == AUTH_ERROR) {
			timings.error = true;
		}
		timings.done();
		if (listener) listener->onResult(ret, foundPassword);
	}
}

/*
static unsigned long threadCount=0;
static mutex threadCountMutex;
*/
void OdbcAuthDb::doAsyncRetrievePassword(string id, string domain, string auth,
										 AuthDbListener *listener) {
	/*	unsigned long localThreadCountCopy=0;
		threadCountMutex.lock();
		++threadCount;
		localThreadCountCopy=threadCount;
		threadCountMutex.unlock();*/
	ConnectionCtx ctx;
	string password;
	AuthDbTimings timings;
	timings.tStart = steady_clock::now();
	AuthDbResult ret = doRetrievePassword(ctx, id, domain, auth, password, timings);
	timings.tEnd = steady_clock::now();
	if (ret == AUTH_ERROR) {
		timings.error = true;
	}
	timings.done();

	if (listener) listener->onResult(ret, password);

	/*
	threadCountMutex.lock();
	--threadCount;
	localThreadCountCopy=threadCount;
	threadCountMutex.unlock();
	*/
}

AuthDbResult OdbcAuthDb::doRetrievePassword(ConnectionCtx &ctx, const string &id, const string &domain,
											const string &auth, string &foundPassword, AuthDbTimings &timings) {
	if (!getConnection(id, ctx, timings)) {
		LOGE("ConnectionCtx creation error");
		return AUTH_ERROR;
	}

	timings.tGotConnection = steady_clock::now();
	SQLHANDLE stmt = ctx.stmt;

	strncpy(ctx.idCBuffer, id.c_str(), fieldLength), ctx.idCBuffer[fieldLength] = 0;
	strncpy(ctx.domainCBuffer, domain.c_str(), fieldLength), ctx.domainCBuffer[fieldLength] = 0;
	strncpy(ctx.authIdCBuffer, auth.c_str(), fieldLength), ctx.authIdCBuffer[fieldLength] = 0;

	SQLRETURN retcode;
	if (execDirect) {
		// execute direct
		LOGD("Requesting password of user with id='%s'", ctx.idCBuffer);
		retcode = SQLExecDirect(stmt, (SQLCHAR *)request.c_str(), SQL_NTS);
		if (!SQL_SUCCEEDED(retcode)) {
			stmtError(ctx, "SQLExecDirect");
			linkFailed("SQLExecDirect", stmt, SQL_HANDLE_STMT);
			return AUTH_ERROR;
		}
		LOGD("SQLExecDirect OK");
	} else {
		// Use prepared statement
		LOGD("Requesting password of user with id='%s'", ctx.idCBuffer);
		retcode = SQLExecute(stmt);
		if (!SQL_SUCCEEDED(retcode)) {
			stmtError(ctx, "SQLExecute");
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
		stmtError(ctx, "SQLFetch");
		closeCursor(stmt);
		return AUTH_ERROR;
	}

	if (retcode == SQL_NO_DATA) {
		LOGD("No data fetched");
		// Seems to be valid
		closeCursor(stmt);
		timings.tGotResult = steady_clock::now();
		return PASSWORD_NOT_FOUND;
	}

	SQLLEN cbPass;
	SQLCHAR password[maxPassLength + 1];
	retcode = SQLGetData(stmt, 1, SQL_C_CHAR, password, maxPassLength, &cbPass);
	if (retcode == SQL_ERROR || retcode == SQL_SUCCESS_WITH_INFO) {
		if (retcode == SQL_SUCCESS_WITH_INFO)
			LOGD("SQLGetData success with info");
		else
			LOGD("SQLGetData error or success with info - user not found??");
		closeCursor(stmt);
		timings.tGotResult = steady_clock::now();
		return PASSWORD_NOT_FOUND;
	}

	closeCursor(stmt);

	timings.tGotResult = steady_clock::now();
	foundPassword.assign((char *)password);
	string key(createPasswordKey(id, auth));
	cachePassword(key, domain, foundPassword, -1);
	LOGD("Password found %s for %s", foundPassword.c_str(), id.c_str());
	return PASSWORD_FOUND;
}

void OdbcAuthDb::getUserWithPhoneFromBackend(const std::string & phone, const std::string & domain, AuthDbListener *listener) {
		LOGE("%s not supported with ODBC", __FUNCTION__);
		if (listener) listener->onResult(AuthDbResult::PASSWORD_NOT_FOUND, "");
}
