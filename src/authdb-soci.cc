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
#include "soci/mysql/soci-mysql.h"
#include "soci-helper.hh"
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
using namespace flexisip;

void SociAuthDB::declareConfig(GenericStruct *mc) {
	// ODBC-specific configuration keys
	ConfigItemDescriptor items[] = {

		{String, "soci-password-request",
			"Soci SQL request to execute to obtain the password and algorithm.\n"
			"Named parameters are:\n -':id' : the user found in the from header,\n -':domain' : the authorization realm, "
			"and\n -':authid' : the authorization username.\n"
			"The use of the :id parameter is mandatory.\n"
			"The output of this request MUST contain two columns in this order:\n"
			"\t- the password column\n"
			"\t- the algorithm associated column: it can be a column in the database or an explicitly specified value among these ('CLRTXT', 'MD5', 'SHA-256')\n"
			"Examples: \n"
			" - the password and algorithm are both available in the database\n"
			"\tselect password, algorithm from accounts where login = :id and domain = :domain\n"
			" - all the passwords from the database are MD5\n"
			"\t select password, 'MD5' from accounts where login = :id and domain = :domain",
			"select password, 'MD5' from accounts where login = :id and domain = :domain"},

		{String, "soci-user-with-phone-request",
			"Soci SQL request to execute to obtain the username associated with a phone alias.\n"
			"Named parameters are:\n -':phone' : the phone number to search for.\n"
			"The use of the :phone parameter is mandatory.\n"
			"Example : select login from accounts where phone = :phone ",
			""},

		{String, "soci-users-with-phones-request",
			"Soci SQL request to execute to obtain the usernames associated with phones aliases.\n"
			"Named parameters are:\n -':phones' : the phones to search for.\n"
			"The use of the :phones parameter is mandatory.\n"
			"If you use phone number linked accounts you'll need to select login, domain, phone in your request for flexisip to work."
			"Example : select login, domain, phone from accounts where phone in (:phones)",
			""},

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

SociAuthDB::SociAuthDB() {
	GenericStruct *cr = GenericManager::get()->getRoot();
	GenericStruct *ma = cr->get<GenericStruct>("module::Authentication");
	GenericStruct *mp = cr->get<GenericStruct>("module::Presence");

	poolSize = ma->get<ConfigInt>("soci-poolsize")->read();
	connection_string = ma->get<ConfigString>("soci-connection-string")->read();
	backend = ma->get<ConfigString>("soci-backend")->read();
	get_password_request = ma->get<ConfigString>("soci-password-request")->read();
	get_user_with_phone_request = ma->get<ConfigString>("soci-user-with-phone-request")->read();
	get_users_with_phones_request = ma->get<ConfigString>("soci-users-with-phones-request")->read();
	unsigned int max_queue_size = (unsigned int)ma->get<ConfigInt>("soci-max-queue-size")->read();
	hashed_passwd = ma->get<ConfigBoolean>("hashed-passwords")->read();
	check_domain_in_presence_results = mp->get<ConfigBoolean>("check-domain-in-presence-results")->read();

	conn_pool.reset(new connection_pool(poolSize));
	thread_pool.reset(new ThreadPool(poolSize, max_queue_size));

	LOGD("[SOCI] Authentication provider for backend %s created. Pooled for %zu connections", backend.c_str(), poolSize);
	connectDatabase();
}

void SociAuthDB::connectDatabase() {
	SLOGD << "[SOCI] Connecting to database (" << poolSize << " pooled connections)";
	try {
		for (size_t i = 0; i < poolSize; i++) {
			conn_pool->at(i).open(backend, connection_string);
		}
		_connected = true;
	} catch (const soci::mysql_soci_error &e) {
		SLOGE << "[SOCI] connection pool open MySQL error: " << e.err_num_ << " " << e.what() << endl;
		closeOpenedSessions();
	} catch (const runtime_error &e) { // std::runtime_error includes all soci exceptions
		SLOGE << "[SOCI] connection pool open error: " << e.what() << endl;
		closeOpenedSessions();
	}
}

void SociAuthDB::closeOpenedSessions() {
	for (size_t i = 0; i < poolSize; i++) {
		soci::session &conn = conn_pool->at(i);
		if (conn.get_backend()) { // if the session is open
			conn.close();
		}
	}
	_connected = false;
}

void SociAuthDB::getPasswordWithPool(const string &id, const string &domain,
									const string &authid, AuthDbListener *listener, AuthDbListener *listener_ref) {
	vector<passwd_algo_t> passwd;
	string unescapedIdStr = urlUnescape(id);

	SociHelper sociHelper(*conn_pool);
	
	try{
		sociHelper.execute([&](session &sql){
			rowset<row> results =  (sql.prepare << get_password_request, use(unescapedIdStr, "id"), use(domain, "domain"), use(authid, "authid"));
			for (rowset<row>::const_iterator it = results.begin(); it != results.end(); it++) {
				row const& r = *it;
				passwd_algo_t pass;

				/* If size == 1 then we only have the password so we assume MD5 */
				if (r.size() == 1) {
					pass.algo = "MD5";

					if (hashed_passwd) {
						pass.pass = r.get<string>(0);
					} else {
						string input = unescapedIdStr + ":" + domain + ":" + r.get<string>(0);
						pass.pass = syncMd5(input.c_str(), 16);
					}
				} else if (r.size() > 1) {
					string password = r.get<string>(0);
					string algo = r.get<string>(1);

					if (algo == "CLRTXT") {
						if (passwd.empty()) {
							pass.algo = algo;
							pass.pass = password;
							passwd.push_back(pass);

							string input;
							input = unescapedIdStr + ":" + domain + ":" + password;

							pass.pass = syncMd5(input.c_str(), 16);
							pass.algo = "MD5";
							passwd.push_back(pass);

							pass.pass = syncSha256(input.c_str(), 32);
							pass.algo = "SHA-256";
							passwd.push_back(pass);

							break;
						}
					} else {
						pass.algo = algo;
						pass.pass = password;
					}
				}
				passwd.push_back(pass);
			}
		});

		

		if (listener_ref) listener_ref->finishVerifyAlgos(passwd);
		if (!passwd.empty()) cachePassword(createPasswordKey(id, authid), domain, passwd, mCacheExpire);
		if (listener){
			listener->onResult(passwd.empty() ? PASSWORD_NOT_FOUND : PASSWORD_FOUND, passwd);
		}
	}catch(SociHelper::DatabaseException &e){
		if (listener) listener->onResult(AUTH_ERROR, passwd);
	}
}

void SociAuthDB::getUserWithPhoneWithPool(const string &phone, const string &domain, AuthDbListener *listener) {
	string user;

	try {
		SociHelper sociHelper(*conn_pool);
		
		if(get_user_with_phone_request != "") {
			sociHelper.execute([&](session &sql){
				sql << get_user_with_phone_request, into(user), use(phone, "phone");
			});
		} else {
			string s = get_users_with_phones_request;
			int index = s.find(":phones");
			while(index > -1) {
				s = s.replace(index, 7, phone);
				index = s.find(":phones");
			}
			sociHelper.execute([&](session &sql){
				rowset<row> ret = (sql.prepare << s);
				for (rowset<row>::const_iterator it = ret.begin(); it != ret.end(); ++it) {
					row const& row = *it;
					user = row.get<string>(0);
				}
			});
			
		}
		if (!user.empty())  {
			cacheUserWithPhone(phone, domain, user);
		}
		if (listener){
			listener->onResult(user.empty() ? PASSWORD_NOT_FOUND : PASSWORD_FOUND, user);
		}
	} catch (SociHelper::DatabaseException &e) {
		if (listener) listener->onResult(PASSWORD_NOT_FOUND, user);
	}
}

void SociAuthDB::getUsersWithPhonesWithPool(list<tuple<string, string,AuthDbListener*>> &creds) {
	set<pair<string, string>> presences;
	ostringstream in;
	list<string> phones;
	list<string> domains;
	bool first = true;
	
	for(const auto &cred : creds) {
		const auto &phone = std::get<0>(cred);
		phones.push_back(phone);
		domains.push_back(std::get<1>(cred));
		if(first) {
			first = false;
			in << "'" << phone << "'";
		} else {
			in << ",'" << phone << "'";
		}
	}

	string s = get_users_with_phones_request;
	int index = s.find(":phones");
	while(index > -1) {
		s = s.replace(index, 7, in.str());
		index = s.find(":phones");
	}

	try {
		SociHelper sociHelper(*conn_pool);
		sociHelper.execute([&](session &sql){
			rowset<row> ret = (sql.prepare << s);

			for (rowset<row>::const_iterator it = ret.begin(); it != ret.end(); ++it) {
				row const& row = *it;
				string user = row.get<string>(0);
				string domain = row.get<string>(1);
				string phone = (row.size() > 2) ? row.get<string>(2) : "";

				bool domain_match = false;
				if (check_domain_in_presence_results) {
					domain_match = find(domains.begin(), domains.end(), domain) != domains.end();
				}

				if (!check_domain_in_presence_results || domain_match) {
					if (!phone.empty()) {
						cacheUserWithPhone(phone, domain, user);
						presences.insert(make_pair(user, phone));
					} else {
						presences.insert(make_pair(user, user));
					}
				}
			}
		});
		notifyAllListeners(creds, presences);
	} catch (SociHelper::DatabaseException &e) {
		SLOGE << "[SOCI] MySQL request causing the error was : " << s;
		presences.clear();
		notifyAllListeners(creds, presences);
	}
}

void SociAuthDB::notifyAllListeners(std::list<std::tuple<std::string, std::string, AuthDbListener *>> &creds, const std::set<std::pair<std::string, std::string>> &presences) {
	for(const auto &cred : creds) {
		const string &phone = std::get<0>(cred);
		AuthDbListener *listener = std::get<2>(cred);
		auto presence = find_if(presences.cbegin(), presences.cend(),
							 [&phone](const pair<string, string> &p){return p.second == phone;}
		);
		if (presence != presences.cend()) {
			// 				mDInfo[presence->first] = mDInfo[phone];
			if (listener) listener->onResult(PASSWORD_FOUND, presence->first);
		} else {
			if (listener) listener->onResult(PASSWORD_NOT_FOUND, phone);
		}
	}
}

#ifdef __clang__
#pragma mark - Inherited virtuals
#endif

void SociAuthDB::getPasswordFromBackend(const string &id, const string &domain,
										const string &authid, AuthDbListener *listener, AuthDbListener *listener_ref) {

	if (!_connected) connectDatabase();
	if (!_connected) {
		if (listener) listener->onResult(AUTH_ERROR , "");
		return;
	}

	// create a thread to grab a pool connection and use it to retrieve the auth information
	auto func = bind(&SociAuthDB::getPasswordWithPool, this, id, domain, authid, listener, listener_ref);

	bool success = thread_pool->run(func);
	if (!success) {
		// Enqueue() can fail when the queue is full, so we have to act on that
		SLOGE << "[SOCI] Auth queue is full, cannot fullfil password request for " << id << " / " << domain << " / "
			<< authid;
		if (listener) listener->onResult(AUTH_ERROR, "");
	}
}

void SociAuthDB::getUserWithPhoneFromBackend(const string &phone, const string &domain, AuthDbListener *listener) {
	if (!_connected) connectDatabase();
	if (!_connected) {
		if (listener) listener->onResult(AUTH_ERROR , "");
		return;
	}

	// create a thread to grab a pool connection and use it to retrieve the auth information
	auto func = bind(&SociAuthDB::getUserWithPhoneWithPool, this, phone, domain, listener);

	bool success = thread_pool->run(func);
	if (success == FALSE) {
		// Enqueue() can fail when the queue is full, so we have to act on that
		SLOGE << "[SOCI] Auth queue is full, cannot fullfil user request for " << phone;
		if (listener) listener->onResult(AUTH_ERROR, "");
	}
}

void SociAuthDB::getUsersWithPhonesFromBackend(list<tuple<string, string, AuthDbListener*>> &creds) {
	if (!_connected) connectDatabase();
	if (!_connected) {
		for (const auto &cred : creds) {
			AuthDbListener *listener = std::get<2>(cred);
			if (listener) listener->onResult(AUTH_ERROR, "");
		}
		return;
	}

	// create a thread to grab a pool connection and use it to retrieve the auth information
	auto func = bind(&SociAuthDB::getUsersWithPhonesWithPool, this, creds);

	bool success = thread_pool->run(func);
	if (success == FALSE) {
		// Enqueue() can fail when the queue is full, so we have to act on that
		SLOGE << "[SOCI] Auth queue is full, cannot fullfil user request for " << &creds;
		for (const auto &cred : creds) {
			AuthDbListener *listener = std::get<2>(cred);
			if (listener) listener->onResult(AUTH_ERROR, "");
		}
	}
}
