/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include <bitset>
#include <cstdint>
#include <regex>
#include <string_view>
#include <thread>

#include <soci/mysql/soci-mysql.h>

#include "flexisip/configmanager.hh"
#include "soci-helper.hh"
#include "utils/digest.hh"
#include "utils/string-utils.hh"
#include "utils/thread/auto-thread-pool.hh"

#include "authdb.hh"

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

namespace {

// Parse admin-provided request to build appropriate parameter injection
std::function<soci::rowset<soci::row>(soci::session&, const std::string&, const std::string&, const std::string&)>
buildSociParamInjecter(std::string_view request) {
	std::regex paramsRegex("(:domain|:authid)");
	constexpr std::uint8_t DOMAIN = 0b01;
	constexpr std::uint8_t AUTHID = 0b10;
	std::uint8_t paramsFound = 0b00;
	const std::cregex_iterator paramsEnd{};
	for (std::cregex_iterator match(request.begin(), request.end(), paramsRegex); match != paramsEnd; ++match) {
		const auto& match_str = match->str();
		if (match_str == ":domain") {
			paramsFound |= DOMAIN;
		} else if (match_str == ":authid") {
			paramsFound |= AUTHID;
		}
		if (paramsFound == (DOMAIN | AUTHID)) break;
	}
	switch (paramsFound) {
		case (DOMAIN | AUTHID): {
			return [request](auto& sql, const auto& id, const auto& domain, const auto& authid) {
				return sql.prepare << request, use(id, "id"), use(domain, "domain"), use(authid, "authid");
			};
		} break;
		case DOMAIN: {
			return [request](auto& sql, const auto& id, const auto& domain, const auto&) {
				return sql.prepare << request, use(id, "id"), use(domain, "domain");
			};
		} break;
		case AUTHID: {
			return [request](auto& sql, const auto& id, const auto&, const auto& authid) {
				return sql.prepare << request, use(id, "id"), use(authid, "authid");
			};
		} break;
		default: {
			return [request](auto& sql, const auto& id, const auto&, const auto&) {
				return sql.prepare << request, use(id, "id");
			};
		} break;
	}
}

} // namespace

void SociAuthDB::declareConfig(GenericStruct* mc) {
	// ODBC-specific configuration keys
	ConfigItemDescriptor items[] = {
	    {String, "soci-backend",
	     "Choose the type of backend that Soci will use for the connection.\n"
	     "Depending on your Soci package and the modules you installed, this could be 'mysql', "
	     "'oracle', 'postgresql' or something else.",
	     "mysql"},

	    {String, "soci-connection-string",
	     "The configuration parameters of the Soci backend.\n"
	     "The basic format is \"key=value key2=value2\". For a mysql backend, this "
	     "is a valid config: \"db=mydb user=user password='pass' host=myhost.com\".\n"
	     "Please refer to the Soci documentation of your backend, for intance: "
	     "http://soci.sourceforge.net/doc/release/4.0/backends/mysql/",
	     "db=mydb user=myuser password='mypass' host=myhost.com"},

	    {String, "soci-password-request",
	     "Soci SQL request used to obtain the password of a given user.\n"
	     "Each keywords starting with ':' character will be replaced by strings extracted from "
	     "the SIP request to authenticate.\n"
	     "\n"
	     "Only these keywords are supported:"
	     " - ':id'     : the user found in the from header (mandatory)\n"
	     " - ':domain' : the authorization realm\n"
	     " - ':authid' : the authorization username\n"
	     "\n"
	     "The request MUST returns a two-columns table, which columns are defined as follow:\n"
	     " - 1st column: hashed password of the user or plain password if the associated algorithm is CLRTXT.\n"
	     " - 2nd column: the algorithm used to hash the associated password. Supported values: 'CLRTXT', 'MD5', "
	     "'SHA-256'\n"
	     "\n"
	     "Examples:\n"
	     " - the password and algorithm are both available in the database\n"
	     "\tselect password, algorithm from accounts where login = :id and domain = :domain\n"
	     "\n"
	     " - all the passwords from the database are MD5\n"
	     "\tselect password, 'MD5' from accounts where login = :id and domain = :domain",
	     "select password, 'MD5' from accounts where login = :id and domain = :domain"},

	    {Integer, "soci-max-queue-size",
	     "Amount of queries that will be allowed to be queued before bailing password requests.\n"
	     "This value should be chosen accordingly with 'soci-poolsize', so that you have a coherent behavior.\n"
	     "This limit is here mainly as a safeguard against out-of-control growth of the queue in the event of a "
	     "flood or big delays in the database backend.",
	     "1000"},

	    {Integer, "soci-poolsize",
	     "Size of the pool of connections that Soci will use. A thread is opened for each DB query, and this pool "
	     "will allow each thread to get a connection.\n"
	     "The threads are blocked until a connection is released back to the pool, so increasing the pool size will "
	     "allow more connections to occur simultaneously.\n"
	     "On the other hand, you should not keep too many open connections to your DB at the same time.",
	     "100"},

	    // Deprecated
	    {String, "soci-user-with-phone-request",
	     "WARNING: This parameter is used by the presence server only.\n"
	     "Soci SQL request used to obtain the username associated with a phone alias.\n"
	     "The string MUST contains the ':phone' keyword which will be replaced by the phone number to look for.\n"
	     "The result of the request is a 1x1 table containing the name of the user associated with the phone "
	     "number.\n"
	     "\n"
	     "Example: select login from accounts where phone = :phone ",
	     ""},

	    {String, "soci-users-with-phones-request",
	     "WARNING: This parameter is used by the presence server only.\n"
	     "Same as 'soci-user-with-phone-request' but allows to fetch several users by a unique SQL request.\n"
	     "The string MUST contains the ':phones' keyword which will be replaced by the list of phone numbers to "
	     "look for. Each element of the list is seperated by a comma character and is protected by simple quotes "
	     "(e.g. '0336xxxxxxxx','0337yyyyyyyy','034zzzzzzzzz').\n"
	     "If you use phone number linked accounts you'll need to select login, domain, phone in your request for "
	     "flexisip to work.\n"
	     "Example: select login, domain, phone from accounts where phone in (:phones)",
	     ""},

	    config_item_end};

	mc->addChildrenValues(items);

	auto userWithPhoneReqConf = mc->get<ConfigString>("soci-user-with-phone-request");
	userWithPhoneReqConf->setDeprecated(
	    {"2020-06-18", "2.1.0",
	     "This configuration is moved to [presence-server] section. Please move your configuration."});
	auto usersWithPhonesReqConf = mc->get<ConfigString>("soci-users-with-phones-request");
	usersWithPhonesReqConf->setDeprecated(
	    {"2020-06-18", "2.1.0",
	     "This configuration is moved to [presence-server] section. Please move your configuration."});

	auto* ps = dynamic_cast<GenericStruct*>(mc->getParent())->get<GenericStruct>("presence-server");
	ps->get<ConfigString>("soci-user-with-phone-request")->setFallback(*userWithPhoneReqConf);
	ps->get<ConfigString>("soci-users-with-phones-request")->setFallback(*usersWithPhonesReqConf);
}

SociAuthDB::SociAuthDB(const GenericStruct& cr) : AuthDbBackend(cr) {
	auto* ma = cr.get<GenericStruct>("module::Authentication");
	auto* mp = cr.get<GenericStruct>("module::Presence");
	auto* ps = cr.get<GenericStruct>("presence-server");

	poolSize = ma->get<ConfigInt>("soci-poolsize")->read();
	connection_string = ma->get<ConfigString>("soci-connection-string")->read();
	backend = ma->get<ConfigString>("soci-backend")->read();

	mGetPassword = buildSociParamInjecter(ma->get<ConfigString>("soci-password-request")->read());

	auto max_queue_size = (unsigned int)ma->get<ConfigInt>("soci-max-queue-size")->read();

	get_user_with_phone_request = ps->get<ConfigString>("soci-user-with-phone-request")->read();
	get_users_with_phones_request = ps->get<ConfigString>("soci-users-with-phones-request")->read();
	check_domain_in_presence_results = mp->get<ConfigBoolean>("check-domain-in-presence-results")->read();

	conn_pool.reset(new connection_pool(poolSize));
	thread_pool = make_unique<AutoThreadPool>(poolSize, max_queue_size);

	LOGD("[SOCI] Authentication provider for backend %s created. Pooled for %zu connections", backend.c_str(),
	     poolSize);
	connectDatabase();
}

void SociAuthDB::connectDatabase() {
	SLOGD << "[SOCI] Connecting to database (" << poolSize << " pooled connections)";
	try {
		for (size_t i = 0; i < poolSize; i++) {
			conn_pool->at(i).open(backend, connection_string);
		}
		_connected = true;
	} catch (const soci::mysql_soci_error& e) {
		SLOGE << "[SOCI] connection pool open MySQL error: " << e.err_num_ << " " << e.what() << endl;
		closeOpenedSessions();
	} catch (const runtime_error& e) { // std::runtime_error includes all soci exceptions
		SLOGE << "[SOCI] connection pool open error: " << e.what() << endl;
		closeOpenedSessions();
	}
}

void SociAuthDB::closeOpenedSessions() {
	for (size_t i = 0; i < poolSize; i++) {
		soci::session& conn = conn_pool->at(i);
		if (conn.get_backend()) { // if the session is open
			conn.close();
		}
	}
	_connected = false;
}

void SociAuthDB::getPasswordWithPool(const string& id,
                                     const string& domain,
                                     const string& authid,
                                     AuthDbListener* listener) {
	vector<passwd_algo_t> passwd{};
	auto unescapedIdStr = urlUnescape(id);

	SociHelper sociHelper{*conn_pool};

	try {
		sociHelper.execute([&](session& sql) {
			rowset<row> results = mGetPassword(sql, unescapedIdStr, domain, authid);
			for (const auto& r : results) {
				/* If size == 1 then we only have the password so we assume MD5 */
				auto algo = r.size() > 1 ? r.get<string>(1) : "MD5";
				if (algo == "CLRTXT") {
					const auto& password = r.get<string>(0);
					auto input = unescapedIdStr + ":" + domain + ":" + password;
					passwd.clear();
					passwd.emplace_back(password, algo);
					passwd.emplace_back(Md5{}.compute<string>(input), "MD5");
					passwd.emplace_back(Sha256{}.compute<string>(input), "SHA-256");
					break;
				} else {
					auto hash = StringUtils::toLower(r.get<string>(0));
					passwd.emplace_back(move(hash), algo);
				}
			}
		});

		if (!passwd.empty()) cachePassword(createPasswordKey(id, authid), domain, passwd, mCacheExpire);
		if (listener) {
			listener->onResult(passwd.empty() ? PASSWORD_NOT_FOUND : PASSWORD_FOUND, passwd);
		}
	} catch (SociHelper::DatabaseException& e) {
		if (listener) listener->onResult(AUTH_ERROR, passwd);
	}
}

void SociAuthDB::getUserWithPhoneWithPool(const string& phone, const string& domain, AuthDbListener* listener) {
	string user;

	try {
		SociHelper sociHelper(*conn_pool);

		if (get_user_with_phone_request != "") {
			sociHelper.execute(
			    [&](session& sql) { sql << get_user_with_phone_request, into(user), use(phone, "phone"); });
		} else {
			string s = get_users_with_phones_request;
			int index = s.find(":phones");
			while (index > -1) {
				s = s.replace(index, 7, phone);
				index = s.find(":phones");
			}
			sociHelper.execute([&](session& sql) {
				rowset<row> ret = (sql.prepare << s);
				for (rowset<row>::const_iterator it = ret.begin(); it != ret.end(); ++it) {
					row const& row = *it;
					user = row.get<string>(0);
				}
			});
		}
		if (!user.empty()) {
			cacheUserWithPhone(phone, domain, user);
		}
		if (listener) {
			listener->onResult(user.empty() ? PASSWORD_NOT_FOUND : PASSWORD_FOUND, user);
		}
	} catch (SociHelper::DatabaseException& e) {
		if (listener) listener->onResult(PASSWORD_NOT_FOUND, user);
	}
}

void SociAuthDB::getUsersWithPhonesWithPool(list<tuple<string, string, AuthDbListener*>>& creds) {
	set<pair<string, string>> presences;
	ostringstream in;
	list<string> phones;
	list<string> domains;
	bool first = true;

	for (const auto& cred : creds) {
		const auto& phone = std::get<0>(cred);
		phones.push_back(phone);
		domains.push_back(std::get<1>(cred));
		if (first) {
			first = false;
			in << "'" << phone << "'";
		} else {
			in << ",'" << phone << "'";
		}
	}

	string s = get_users_with_phones_request;
	int index = s.find(":phones");
	while (index > -1) {
		s = s.replace(index, 7, in.str());
		index = s.find(":phones");
	}

	try {
		SociHelper sociHelper(*conn_pool);
		sociHelper.execute([&](session& sql) {
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
	} catch (SociHelper::DatabaseException& e) {
		SLOGE << "[SOCI] MySQL request causing the error was : " << s;
		presences.clear();
		notifyAllListeners(creds, presences);
	}
}

void SociAuthDB::notifyAllListeners(std::list<std::tuple<std::string, std::string, AuthDbListener*>>& creds,
                                    const std::set<std::pair<std::string, std::string>>& presences) {
	for (const auto& cred : creds) {
		const string& phone = std::get<0>(cred);
		AuthDbListener* listener = std::get<2>(cred);
		auto presence = find_if(presences.cbegin(), presences.cend(),
		                        [&phone](const pair<string, string>& p) { return p.second == phone; });
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

void SociAuthDB::getPasswordFromBackend(const string& id,
                                        const string& domain,
                                        const string& authid,
                                        AuthDbListener* listener) {

	if (!_connected) connectDatabase();
	if (!_connected) {
		if (listener) listener->onResult(AUTH_ERROR, PwList());
		return;
	}

	// create a thread to grab a pool connection and use it to retrieve the auth information
	auto func = bind(&SociAuthDB::getPasswordWithPool, this, id, domain, authid, listener);

	bool success = thread_pool->run(func);
	if (!success) {
		// Enqueue() can fail when the queue is full, so we have to act on that
		SLOGE << "[SOCI] Auth queue is full, cannot fullfil password request for " << id << " / " << domain << " / "
		      << authid;
		if (listener) listener->onResult(AUTH_ERROR, PwList());
	}
}

void SociAuthDB::getUserWithPhoneFromBackend(const string& phone, const string& domain, AuthDbListener* listener) {
	if (!_connected) connectDatabase();
	if (!_connected) {
		if (listener) listener->onResult(AUTH_ERROR, "");
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

void SociAuthDB::getUsersWithPhonesFromBackend(list<tuple<string, string, AuthDbListener*>>& creds) {
	if (!_connected) connectDatabase();
	if (!_connected) {
		for (const auto& cred : creds) {
			AuthDbListener* listener = std::get<2>(cred);
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
		for (const auto& cred : creds) {
			AuthDbListener* listener = std::get<2>(cred);
			if (listener) listener->onResult(AUTH_ERROR, "");
		}
	}
}
