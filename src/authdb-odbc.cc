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
#include <chrono>

using namespace ::std;

using namespace chrono;

struct AuthDbTimingsAnalyzer;

struct AuthDbTimings {
	static AuthDbTimingsAnalyzer analyzerFull;
	static AuthDbTimingsAnalyzer analyzerRetr;
	bool error;
	AuthDbTimings():error(false){};

	monotonic_clock::time_point tStart;
	monotonic_clock::time_point tGotConnection;
	monotonic_clock::time_point tGotResult;
	monotonic_clock::time_point tEnd;

	void done();
};



// To get 3000 authentications per second
// The average duration should be ~300 microseconds per authentication.
struct AuthDbTimingsAnalyzer {
	static const long maxDurationSlow = 14000; // 700 auth/s
	static const long maxDuration = 600; // 1500 auth/s
	static const int steps = 14;
	static const long stepSize = maxDuration / steps;
	static const int LineWidth = 50;

	static mutex tMutex;
	static int displayStatsInterval;
	static int displayStatsAfterCount;

	monotonic_clock::time_point lastDisplay;
	long errorCount;

	long count;
	long slowCount;
	long slowestCount;

	float average;
	float slowAverage;
	float slowestAverage;

	long maxLineWidth;
	float durations[steps +1];

	void reset() {
		lastDisplay=monotonic_clock::now();
		count=0;
		errorCount=0;
		slowCount=0;
		slowestCount=0;
		average=0;
		slowAverage=0;
		slowestAverage=0;
		memset(durations, 0, sizeof(durations));
		maxLineWidth=0;
	}

	AuthDbTimingsAnalyzer(){
		reset();
	};

	void compute(const char *name, monotonic_clock::time_point &t1, monotonic_clock::time_point &t2, bool error) {
		if (error) {
			tMutex.lock();
			++errorCount;
			tMutex.unlock();
			return;
		}

		microseconds duration = t2-t1;
		long ticks = duration.count();

		tMutex.lock();

		average=(count*average+ticks)/(count+1);
		++count;
		if (ticks > maxDuration) {
			//LOGI("bigger max: %f", duration);
			if (ticks > maxDurationSlow) {
				slowestAverage=(slowestCount*slowestAverage+ticks)/(slowestCount+1);
				++slowestCount;
			}
			slowAverage=(slowCount*slowAverage+ticks)/(slowCount+1);
			++slowCount;
			ticks = maxDuration;
		}
		long index = (long)(ticks/stepSize);
		++(durations[index]);
		if (durations[index] > maxLineWidth) ++maxLineWidth;

		// Show statistics each 10'000 timings
		if (displayStatsAfterCount && count == 10000) {
			display(name);
			reset();
		}
		// Or every 10 seconds
		if (displayStatsInterval && duration_cast<seconds>(t1-lastDisplay).count() >= displayStatsInterval) {
			display(name);
			reset();
		}
		tMutex.unlock();
	}

	void display(const char *name) {
		LOGI("%lu [%lu micro] timings (%lu errors) %lu [%lu micro] slow - %lu [%lu millis] slowest",
				count, (long) average,
				errorCount,
				slowCount, (long) slowAverage,
				slowestCount, ((long) slowestAverage)/1000);
		double lDiv= ((double)maxLineWidth) / LineWidth;
		LOGI("Displaying %s, %u steps [%lu - %lu] - max %lu - div %f", name, steps,
				0l, maxDuration, maxLineWidth, lDiv);
		if (lDiv == 0) {
			LOGI("Skipping display with no maxcount");
			return;
		}

		for (int i=0; i < steps; ++i) {
			char line[LineWidth +1] = {0};
			int lineWidth= (int) (durations[i] / lDiv);
			memset(line, '#', lineWidth);
			LOGI("[%u-%u] %s", (int) (i*stepSize), (int) ((i+1)*stepSize), line);
		}
	}
};
mutex AuthDbTimingsAnalyzer::tMutex;
int AuthDbTimingsAnalyzer::displayStatsInterval = 0; // 0 to disable
int AuthDbTimingsAnalyzer::displayStatsAfterCount = 0; // 0 to disable
AuthDbTimingsAnalyzer AuthDbTimings::analyzerFull;
AuthDbTimingsAnalyzer AuthDbTimings::analyzerRetr;


void AuthDbTimings::done() {
	analyzerFull.compute("full",  tStart, tEnd, error);
	analyzerRetr.compute("pass retrieving", tGotConnection, tGotResult, error);
}

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

/**
 * See documentation on ODBC on Microsoft pages:
 * http://msdn.microsoft.com/en-us/library/ms716319%28v=VS.85%29.aspx
 */
OdbcAuthDb::OdbcAuthDb():mAsynchronousRetrieving(true),env(NULL),execDirect(false) {
	GenericStruct *cr=GenericManager::get()->getRoot();
	GenericStruct *ma=cr->get<GenericStruct>("module::Authentication");

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

	AuthDbTimingsAnalyzer::displayStatsInterval = ma->get<ConfigInt>("odbc-display-timings-interval")->read();
	AuthDbTimingsAnalyzer::displayStatsAfterCount = ma->get<ConfigInt>("odbc-display-timings-after-count")->read();

	mAsynchronousRetrieving	= ma->get<ConfigBoolean>("odbc-asynchronous")->read();
	LOGD("%s password retrieving", mAsynchronousRetrieving ? "Asynchronous" : "Synchronous");

	asPooling=ma->get<ConfigBoolean>("odbc-pooling")->read();

	SQLRETURN retcode;
	// 1. Enable or disable connection pooling.
	// It should be done BEFORE allocating the environment.
	unsigned long poolingPtr = asPooling ? SQL_CP_ONE_PER_DRIVER : SQL_CP_OFF;
	retcode = SQLSetEnvAttr(NULL, SQL_ATTR_CONNECTION_POOLING, (void*)poolingPtr, 0);
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
	retcode = SQLSetEnvAttr(env, SQL_ATTR_ODBC_VERSION, (void *) SQL_OV_ODBC3, 0);
	if (!SQL_SUCCEEDED(retcode)) {
		envError("SQLSetEnvAttr ODBCv3");
		LOGF("odbc error");
	}


	// Make sure the driver library is loaded.
	// Workaround odbc errors while loading .so connector library.
	AuthDbTimings timings;
	ConnectionCtx ctx;
	string init="init";
	getConnection(init, ctx, timings);
}

void OdbcAuthDb::setExecuteDirect(const bool value) {
	execDirect = value;
}

void showCB(SQLLEN cb)
{
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
	// Destroy environment
	// All connection should be destroyed already
	LOGD("Disconnecting odbc connector");
	if (env) SQLFreeHandle(SQL_HANDLE_ENV, env);
}

void OdbcAuthDb::envError(const char* doing) {
	logSqlError(doing, env, SQL_HANDLE_ENV);
}

void OdbcAuthDb::dbcError(ConnectionCtx &ctx, const char* doing) {
	logSqlError(doing, ctx.dbc, SQL_HANDLE_DBC);
}


void OdbcAuthDb::stmtError(ConnectionCtx &ctx, const char* doing) {
	logSqlError(doing, ctx.stmt, SQL_HANDLE_STMT);
}


bool OdbcAuthDb::getConnection(const string &id, ConnectionCtx &ctx, AuthDbTimings &timings) {
	monotonic_clock::time_point tp1=monotonic_clock::now();
	SQLRETURN retcode = SQLAllocHandle(SQL_HANDLE_DBC, env, &ctx.dbc);
	if (!SQL_SUCCEEDED(retcode)) {
		envError("SQLAllocHandle DBC");
		return false;
	}
	monotonic_clock::time_point tp2=monotonic_clock::now();
	LOGD("SQLAllocHandle: %s : %lu ms", id.c_str(), (unsigned long) duration_cast<milliseconds>(tp2-tp1).count());

	retcode = SQLDriverConnect(ctx.dbc, NULL, (SQLCHAR*) connectionString.c_str(), SQL_NTS, NULL, 0, NULL, SQL_DRIVER_COMPLETE);
	if (!SQL_SUCCEEDED(retcode)) {dbcError(ctx, "SQLDriverConnect"); return false;}
	LOGD("SQLDriverConnect %s : %lu ms", id.c_str(), (unsigned long) duration_cast<milliseconds>(monotonic_clock::now()-tp2).count());

	// Set connection to be read only
	SQLSetConnectAttr(ctx.dbc, SQL_ATTR_ACCESS_MODE, (SQLPOINTER)SQL_MODE_READ_ONLY, 0);
	if (!SQL_SUCCEEDED(retcode)) {dbcError(ctx, "SQLSetConnectAttr"); return false;}

	retcode = SQLAllocHandle(SQL_HANDLE_STMT, ctx.dbc, &ctx.stmt);
	if (!SQL_SUCCEEDED(retcode)) {
		dbcError(ctx, "SQLAllocHandle STMT");
		return false;
	}

	if (!execDirect) {
		retcode = SQLPrepare(ctx.stmt, (SQLCHAR*) request.c_str(), SQL_NTS);
		if (!SQL_SUCCEEDED(retcode)) {
			stmtError(ctx, "SQLPrepare request");
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
			retcode = SQLBindParameter(ctx.stmt,i+1,SQL_PARAM_INPUT, SQL_C_CHAR,
					SQL_CHAR, (SQLULEN) fieldLength, 0,
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




AuthDbResult OdbcAuthDb::password(su_root_t *root, const url_t *from, const char *auth_username, string &foundPassword, const shared_ptr<AuthDbListener> &listener){
	// Check for usable cached password
	string id(from->url_user);
	string domain(from->url_host);
	string auth(auth_username);

	time_t now=time(NULL);
	string key(createPasswordKey(id, domain, auth));
	string fallbackPassword;
	switch(getCachedPassword(key, domain, fallbackPassword, now)) {
	case VALID_PASS_FOUND:
		foundPassword.assign(fallbackPassword);
		return AuthDbResult::PASSWORD_FOUND;
	case EXPIRED_PASS_FOUND:
		// Might check here if connection is failing
		// If it is the case use fallback password and
		//return AuthDbResult::PASSWORD_FOUND;
		break;
	case NO_PASS_FOUND:
		break;
	}

	if (mAsynchronousRetrieving) {
		// Asynchronously retrieve password in a new thread.
		// Allocate on the stack and detach. It is lawful since:
		// "When detach() returns, *this no longer represents the possibly continuing thread of execution."
		if (listener) {
			listener->switchToAsynchronousMode();
		}
		thread t=thread(bind(&OdbcAuthDb::doAsyncRetrievePassword, this, root, id, domain, auth, fallbackPassword, listener));
		t.detach();	// Thread will continue running in detached mode
		return PENDING;
	} else {
		AuthDbTimings timings;
		timings.tStart=monotonic_clock::now();
		AuthDbResult ret = doRetrievePassword(id, domain, auth, foundPassword, timings);
		timings.tEnd=monotonic_clock::now();
		if (ret == AUTH_ERROR) {
			timings.error = true;
		}
		timings.done();
		return ret;
	}
}

struct auth_splugin_t
{
  shared_ptr<AuthDbListener>listener;
  AuthDbResult result;
  char *password;
};


static void main_thread_async_response_cb(su_root_magic_t *rm, su_msg_r msg,
				     auth_splugin_t *u) {
	u->listener->onAsynchronousResponse(u->result, u->password);
	if (u->password) free(u->password);
}


/*
static unsigned long threadCount=0;
static mutex threadCountMutex;
*/
void OdbcAuthDb::doAsyncRetrievePassword(su_root_t *root, string id, string domain, string auth, string fallback, const shared_ptr<AuthDbListener> &listener){
/*	unsigned long localThreadCountCopy=0;
	threadCountMutex.lock();
	++threadCount;
	localThreadCountCopy=threadCount;
	threadCountMutex.unlock();*/
	string foundPassword;
	AuthDbTimings timings;
	timings.tStart=monotonic_clock::now();
	AuthDbResult ret = doRetrievePassword(id, domain, auth, foundPassword, timings);
	timings.tEnd=monotonic_clock::now();
	if (ret == AUTH_ERROR) {
		timings.error = true;
	}
	timings.done();

	if (listener) {
		su_msg_r mamc = SU_MSG_R_INIT;
		if (-1 == su_msg_create(mamc,
				su_root_task(root),
				su_root_task(root),
				main_thread_async_response_cb,
				sizeof(auth_splugin_t))) {
			LOGF("Couldn't create auth async message");
		}

		auth_splugin_t *asp = su_msg_data(mamc);
		asp->listener = listener;
		asp->result = ret;
		asp->password = NULL;
		switch (ret) {
		case PASSWORD_FOUND:
			asp->password = strdup(foundPassword.c_str());
			break;
		case PASSWORD_NOT_FOUND:
			//asp->password = NULL;
			break;
		case AUTH_ERROR:
			if (!fallback.empty()) {
				asp->result = PASSWORD_FOUND;
				asp->password = strdup(fallback.c_str());
			}
			break;
		case PENDING:
			LOGF("unhandled case PENDING");
			break;
		}
		if (-1 == su_msg_send(mamc)) {
			LOGF("Couldn't send auth async message to main thread.");
		}
	}

	/*
	threadCountMutex.lock();
	--threadCount;
	localThreadCountCopy=threadCount;
	threadCountMutex.unlock();
	*/
}

AuthDbResult OdbcAuthDb::doRetrievePassword(const string &id, const string &domain, const string &auth, string &foundPassword, AuthDbTimings &timings){
	ConnectionCtx ctx;
	if (!getConnection(id, ctx, timings)) {
		LOGE("ConnectionCtx creation error");
		return AUTH_ERROR;
	}

	timings.tGotConnection=monotonic_clock::now();
	SQLHANDLE stmt=ctx.stmt;

	strncpy((char*)&ctx.idCBuffer, id.c_str(), fieldLength), ctx.idCBuffer[fieldLength]=0;
	strncpy((char*)&ctx.domainCBuffer, domain.c_str(), fieldLength), ctx.domainCBuffer[fieldLength]=0;
	strncpy((char*)&ctx.authIdCBuffer, auth.c_str(), fieldLength), ctx.authIdCBuffer[fieldLength]=0;

	SQLRETURN retcode;
	if (execDirect) {
		// execute direct
		LOGD("Requesting password of user with id='%s'", (char*)&ctx.idCBuffer);
		retcode = SQLExecDirect(stmt, (SQLCHAR*) request.c_str(), SQL_NTS);
		if (!SQL_SUCCEEDED(retcode)) {
			stmtError(ctx, "SQLExecDirect");
			linkFailed("SQLExecDirect", stmt, SQL_HANDLE_STMT);
			return AUTH_ERROR;
		}
		LOGD("SQLExecDirect OK");
	} else {
		// Use prepared statement
		LOGD("Requesting password of user with id='%s'", (char*)&ctx.idCBuffer);
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
		timings.tGotResult=monotonic_clock::now();
		return PASSWORD_NOT_FOUND;
	}

	closeCursor(stmt);

	timings.tGotResult=monotonic_clock::now();
	foundPassword.assign((char*)password);
	string key(createPasswordKey(id, domain, auth));
	cachePassword(key, domain, foundPassword, time(NULL));
	LOGD("Password found %s for %s", foundPassword.c_str(), id.c_str());
	return PASSWORD_FOUND;
}
