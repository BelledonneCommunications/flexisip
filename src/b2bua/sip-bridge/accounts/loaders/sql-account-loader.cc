/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include "sql-account-loader.hh"

#include <soci/session.h>

#include "soci-helper.hh"

namespace flexisip::b2bua::bridge {
using namespace std;
using namespace soci;

SQLAccountLoader::SQLAccountLoader(const std::shared_ptr<sofiasip::SuRoot>& suRoot,
                                   const config::v2::SQLLoader& loaderConf)
    : mSuRoot{suRoot}, mInitQuery{loaderConf.initQuery}, mUpdateQuery{loaderConf.updateQuery} {
	for (auto i = 0; i < 50; ++i) {
		session& sql = mSociConnectionPool.at(i);
		sql.open(loaderConf.dbBackend, loaderConf.connection);
	}
}

std::vector<config::v2::Account> SQLAccountLoader::initialLoad() {
	std::vector<config::v2::Account> accountsLoaded{};
	SociHelper helper{mSociConnectionPool};
	helper.execute([&initQuery = mInitQuery, &accountsLoaded](auto& sql) {
		config::v2::Account account;
		soci::statement statement = (sql.prepare << initQuery, into(account));
		statement.execute();
		while (statement.fetch()) {
			accountsLoaded.push_back(account);
		}
	});

	return accountsLoaded;
}

void SQLAccountLoader::accountUpdateNeeded(const RedisAccountPub& redisAccountPub, const OnAccountUpdateCB& cb) {
	mThreadPool.run([this, redisAccountPub, cb] {
		config::v2::Account account;
		SociHelper helper{mSociConnectionPool};
		helper.execute([&updateQuery = mUpdateQuery, &account, &redisAccountPub](auto& sql) {
			sql << updateQuery, use(redisAccountPub.identifier, "identifier"), into(account);
		});

		mSuRoot->addToMainLoop([cb, account, redisAccountPub]() {
			// Uri cannot be empty unless no account was found in DB.
			cb(redisAccountPub.uri.str(), (account.uri.empty() ? nullopt : optional<config::v2::Account>{account}));
		});
	});
}

} // namespace flexisip::b2bua::bridge