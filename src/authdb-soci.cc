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
#include <thread>

using namespace soci;

SociAuthDB::SociAuthDB() : pool(NULL) {

	// TODO: get all these from the configuration
	poolSize = 100;
	connection_string    = "db=mydb user=user password='pass' host=myhost.com";
	backend              = "mysql";
	get_password_request = "select password from accounts where login=:id";

	pool = new connection_pool(poolSize);

	LOGD("[SOCI] Authentication provider for backend %s created. Pooled for %d connections", backend, poolSize);

	for( auto i = 0; i<poolSize; i++ ){
		pool->at(i).open(backend, connection_string);
	}
}

SociAuthDB::~SociAuthDB() {
	delete pool;
}

void SociAuthDB::getPasswordWithPool(su_root_t* root, const std::string &id, const std::string &domain, const std::string &authid, AuthDbListener *listener){

	// will grab a connection from the pool. This is thread safe
	session sql(*pool);
	std::string pass;

	try
	{
		sql << get_password_request, into(pass), use(id,"id"), use(domain, "domain"), use(authid, "authid");
		SLOGD << "[SOCI] Got pass for " << id << endl;
		cachePassword( createPasswordKey(id, domain, authid), domain, pass, mCacheExpire);
		notifyPasswordRetrieved(root, listener, PASSWORD_FOUND, pass);
	}
	catch (mysql_soci_error const & e)
	{
		SLOGE << "[SOCI] MySQL error: " << e.err_num_ << " " << e.what() << endl;
		notifyPasswordRetrieved(root, listener, PASSWORD_NOT_FOUND, pass);
	}
	catch (exception const & e)
	{
		SLOGE << "[SOCI] Some other error: " << e.what() << endl;
		notifyPasswordRetrieved(root, listener, PASSWORD_NOT_FOUND, pass);
	}
}

#pragma mark - Inherited virtuals

void SociAuthDB::getPasswordFromBackend(su_root_t *root, const std::string& id, const std::string& domain, const std::string& authid, AuthDbListener *listener) {

	// create a thread to grab a pool connection and use it to retrieve the auth information
	auto func = bind(&SociAuthDB::getPasswordWithPool, this, root, id, domain, authid, listener);
	thread t = std::thread(func);
	t.detach();

	return;

}