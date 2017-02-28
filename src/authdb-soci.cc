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

#include "authdb.hh"
#include "mysql/soci-mysql.h"
#include <thread>

using namespace soci;

// The dreaded chrono::steady_clock which is not supported for gcc < 4.7
#include <chrono>
using namespace std;
using namespace chrono;
#ifdef USE_MONOTONIC_CLOCK
namespace std {
typedef monotonic_clock steady_clock;
}
#endif

void SociAuthDB::declareConfig(GenericStruct *mc) {
	// ODBC-specific configuration keys
	ConfigItemDescriptor items[] = {

		{String, "soci-password-request",
		 "Soci SQL request to execute to obtain the password.\n"
		 "Named parameters are:\n -':id' : the user found in the from header,\n -':domain' : the authorization realm, "
		 "and\n -':authid' : the authorization username.\n"
		 "The use of the :id parameter is mandatory.",
		 "select password from accounts where id = :id and domain = :domain and authid=:authid"},
		{String, "soci-user-with-phone-request",
		 "Soci SQL request to execute to obtain the username associated with a phone alias.\n"
		 "Named parameters are:\n -':phone' : the phone number to search for.\n"
		 "The use of the :phone parameter is mandatory.",
		 "select login from accounts where phone = :phone"},

		{Integer, "soci-poolsize",
		 "Size of the pool of connections that Soci will use. We open a thread for each DB query, and this pool will "
		 "allow each thread to get a connection.\n"
		 "The threads are blocked until a connection is released back to the pool, so increasing the pool size will "
		 "allow more connections to occur simultaneously.\n"
		 "On the other hand, you should not keep too many open connections to your DB at the same time.",
		 "100"},

		{String, "soci-backend", "Choose the type of backend that Soci will use for the connection.\n"
								 "Depending on your Soci package and the modules you installed, this could be 'mysql', "
								 "'oracle', 'postgresql' or something else.",
		 "mysql"},

		{String, "soci-connection-string", "The configuration parameters of the Soci backend.\n"
										   "The basic format is \"key=value key2=value2\". For a mysql backend, this "
										   "is a valid config: \"db=mydb user=user password='pass' host=myhost.com\".\n"
										   "Please refer to the Soci documentation of your backend, for intance: "
										   "http://soci.sourceforge.net/doc/3.2/backends/mysql.html",
		 "db=mydb user=myuser password='mypass' host=myhost.com"},

		{Integer, "soci-max-queue-size",
		 "Amount of queries that will be allowed to be queued before bailing password "
		 "requests.\n This value should be chosen accordingly with 'soci-poolsize', so "
		 "that you have a coherent behavior.\n This limit is here mainly as a safeguard "
		 "against out-of-control growth of the queue in the event of a flood or big "
		 "delays in the database backend.",
		 "1000"},
		config_item_end};

	mc->addChildrenValues(items);
}

SociAuthDB::SociAuthDB() : conn_pool(NULL) {

	GenericStruct *cr = GenericManager::get()->getRoot();
	GenericStruct *ma = cr->get<GenericStruct>("module::Authentication");

	poolSize = ma->get<ConfigInt>("soci-poolsize")->read();
	connection_string = ma->get<ConfigString>("soci-connection-string")->read();
	backend = ma->get<ConfigString>("soci-backend")->read();
	get_password_request = ma->get<ConfigString>("soci-password-request")->read();
	get_user_with_phone_request = ma->get<ConfigString>("soci-user-with-phone-request")->read();
	unsigned int max_queue_size = (unsigned int)ma->get<ConfigInt>("soci-max-queue-size")->read();

	conn_pool = new connection_pool(poolSize);
	thread_pool = new ThreadPool(poolSize, max_queue_size);

	LOGD("[SOCI] Authentication provider for backend %s created. Pooled for %d connections", backend.c_str(),
		 (int)poolSize);

	for (size_t i = 0; i < poolSize; i++) {
		conn_pool->at(i).open(backend, connection_string);
	}
}

SociAuthDB::~SociAuthDB() {
	delete thread_pool; // will automatically shut it down, clearing threads
	delete conn_pool;
}

void SociAuthDB::reconnectSession(soci::session &session) {

	SLOGE << "[SOCI] Trying close/reconnect on " << session.get_backend_name() << " session";
	session.close();
	session.reconnect();

}

#define DURATION_MS(start, stop) (unsigned long) duration_cast<milliseconds>((stop) - (start)).count()

void SociAuthDB::getPasswordWithPool(const std::string &id, const std::string &domain,
									 const std::string &authid, AuthDbListener *listener) {
	steady_clock::time_point start;
	steady_clock::time_point stop;
	std::string pass;
	session *sql = NULL;
	int errorCount = 0;
	bool retry = false;
	
	while (errorCount < 2){
		retry = false;
		try {
			start = steady_clock::now();
			// will grab a connection from the pool. This is thread safe
			sql = new session(*conn_pool); //this may raise a soci_error exception, so keep it in the try block.

			stop = steady_clock::now();

			SLOGD << "[SOCI] Pool acquired in " << DURATION_MS(start, stop) << "ms";
			start = stop;

			*sql << get_password_request, into(pass), use(id, "id"), use(domain, "domain"), use(authid, "authid");
			stop = steady_clock::now();
			SLOGD << "[SOCI] Got pass for " << id << " in " << DURATION_MS(start, stop) << "ms";
			cachePassword(createPasswordKey(id, authid), domain, pass, mCacheExpire);
			if (listener){
				listener->onResult(pass.empty() ? PASSWORD_NOT_FOUND : PASSWORD_FOUND, pass);
			}
			errorCount = 0;
		} catch (mysql_soci_error const &e) {
			errorCount++;
			stop = steady_clock::now();
			SLOGE << "[SOCI] MySQL error after " << DURATION_MS(start, stop) << "ms : " << e.err_num_ << " " << e.what();
			if (sql) reconnectSession(*sql);
			
			if ((e.err_num_ == 2014 || e.err_num_ == 2006) && errorCount == 1){
				/* 2014 is the infamous "Commands out of sync; you can't run this command now" mysql error,
				 * which is retryable.
				 * At this time we don't know if it is a soci or mysql bug, or bug with the sql request being executed.
				 * 
				 * 2006 is "MySQL server has gone away" which is also retryable.
				 */
				SLOGE << "[SOCI] retrying mysql error " << e.err_num_;
				retry = true;
			}
		} catch (exception const &e) {
			errorCount++;
			stop = steady_clock::now();
			SLOGE << "[SOCI] Some other error after " << DURATION_MS(start, stop) << "ms : " << e.what();
			if (sql) reconnectSession(*sql);
		}
		if (sql) delete sql;
		if (!retry){
			if (errorCount){
				if (listener) listener->onResult(AUTH_ERROR, pass);
			}
			break;
		}
	}
}

void SociAuthDB::getUserWithPhoneWithPool(const std::string &phone, const std::string &domain, AuthDbListener *listener) {
	steady_clock::time_point start;
	steady_clock::time_point stop;
	std::string user;
	session *sql = NULL;

	try {
		start = steady_clock::now();
		// will grab a connection from the pool. This is thread safe
		sql = new session(*conn_pool); //this may raise a soci_error exception, so keep it in the try block.

		stop = steady_clock::now();

		SLOGD << "[SOCI] Pool acquired in " << DURATION_MS(start, stop) << "ms";
		start = stop;

		*sql << get_user_with_phone_request, into(user), use(phone, "phone");
		stop = steady_clock::now();
		if (!user.empty())  {
			SLOGD << "[SOCI] Got user for " << phone << " in " << DURATION_MS(start, stop) << "ms";
			cacheUserWithPhone(phone, domain, user);
		}
		if (listener){
			listener->onResult(user.empty() ? PASSWORD_NOT_FOUND : PASSWORD_FOUND, user);
		}
	} catch (mysql_soci_error const &e) {

		stop = steady_clock::now();
		SLOGE << "[SOCI] MySQL error after " << DURATION_MS(start, stop) << "ms : " << e.err_num_ << " " << e.what();
		if (listener) listener->onResult(PASSWORD_NOT_FOUND, user);

		if (sql) reconnectSession(*sql);

	} catch (exception const &e) {

		stop = steady_clock::now();
		SLOGE << "[SOCI] Some other error after " << DURATION_MS(start, stop) << "ms : " << e.what();
		if (listener) listener->onResult(PASSWORD_NOT_FOUND, user);

		if (sql) reconnectSession(*sql);
	}
	if (sql) delete sql;
}

#pragma mark - Inherited virtuals

void SociAuthDB::getPasswordFromBackend(const std::string &id, const std::string &domain,
										const std::string &authid, AuthDbListener *listener) {

	// create a thread to grab a pool connection and use it to retrieve the auth information
	auto func = bind(&SociAuthDB::getPasswordWithPool, this, id, domain, authid, listener);

	bool success = thread_pool->Enqueue(func);
	if (success == FALSE) {
		// Enqueue() can fail when the queue is full, so we have to act on that
		SLOGE << "[SOCI] Auth queue is full, cannot fullfil password request for " << id << " / " << domain << " / "
			  << authid;
		if (listener) listener->onResult(AUTH_ERROR, "");
	}
}

void SociAuthDB::getUserWithPhoneFromBackend(const string &phone, const string &domain, AuthDbListener *listener) {

	// create a thread to grab a pool connection and use it to retrieve the auth information
	auto func = bind(&SociAuthDB::getUserWithPhoneWithPool, this, phone, domain, listener);

	bool success = thread_pool->Enqueue(func);
	if (success == FALSE) {
		// Enqueue() can fail when the queue is full, so we have to act on that
		SLOGE << "[SOCI] Auth queue is full, cannot fullfil user request for " << phone;
		if (listener) listener->onResult(AUTH_ERROR, "");
	}
}
