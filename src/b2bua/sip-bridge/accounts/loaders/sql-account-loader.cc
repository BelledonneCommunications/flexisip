/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2026 Belledonne Communications SARL, All rights reserved.

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

#include "exceptions/bad-configuration.hh"
#include "soci/session.h"
#include "utils/soci-helper.hh"

namespace flexisip::b2bua::bridge {
using namespace std;
using namespace soci;

namespace {

unsigned int readThreadPoolSizeFromConfig(const config::v2::SQLLoader& loaderConf) {
	if (loaderConf.threadPoolSize <= 0)
		throw BadConfiguration{"invalid thread pool size (" + to_string(loaderConf.threadPoolSize) +
		                       ") set in SQL Account loader"};

	return static_cast<unsigned int>(loaderConf.threadPoolSize);
}

} // namespace

SQLAccountLoader::SQLAccountLoader(const std::shared_ptr<sofiasip::SuRoot>& suRoot,
                                   const config::v2::SQLLoader& loaderConf)
    : mSuRoot{suRoot}, mThreadPool{readThreadPoolSizeFromConfig(loaderConf), 0}, mInitQuery{loaderConf.initQuery},
      mUpdateQuery{loaderConf.updateQuery} {
	for (auto i = 0; i < loaderConf.threadPoolSize; ++i) {
		session& sql = mSociConnectionPool.at(i);
		sql.open(loaderConf.dbBackend, loaderConf.connection);
	}
}

std::vector<config::v2::Account> SQLAccountLoader::loadAll() {
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
		try {
			config::v2::Account account;
			SociHelper helper{mSociConnectionPool};
			helper.execute([&updateQuery = mUpdateQuery, &account, &redisAccountPub](auto& sql) {
				sql << updateQuery, use(redisAccountPub.identifier, "identifier"), into(account);
			});

			mSuRoot->addToMainLoop([cb, account, redisAccountPub]() {
				// Uri cannot be empty unless no account was found in DB.
				cb(redisAccountPub.uri.str(), (account.getUri().empty() ? nullopt : optional{account}));
			});
		} catch (const exception& exception) {
			LOGE_CTX(mLogPrefix, "accountUpdateNeeded")
			    << "An error occurred during SQL query execution: " << exception.what();
		} catch (...) {
			LOGE_CTX(mLogPrefix, "accountUpdateNeeded") << "Caught an unknown exception";
		}
	});
}

void SQLAccountLoader::validateInitQuery() {
	SociHelper client{mSociConnectionPool};
	try {
		client.execute([&initQuery = mInitQuery](session& session) {
			config::v2::Account account{};

			// If present, remove the last ';' so we can extend the query.
			if (const auto pos = initQuery.find_last_of(";"); pos != string::npos)
				initQuery.erase(initQuery.find_last_of(";"));

			session << initQuery << " LIMIT 1;", into(account);
		});
	} catch (const DatabaseException&) {
		throw BadConfiguration{"an error occurred while validating initialization SQL query (see error in logs)"};
	}
}

} // namespace flexisip::b2bua::bridge