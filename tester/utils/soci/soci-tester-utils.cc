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

#include "soci-tester-utils.hh"

#include <fstream>

#include "utils/soci-helper.hh"

using namespace std;

namespace flexisip::tester {

ConnectionPool::ConnectionPool(std::string_view dbName, std::string_view connectString, unsigned int poolSize)
    : mPool(poolSize) {
	const std::string backendName{dbName};
	const std::string connectionString{connectString};
	for (unsigned int sessionId = 0; sessionId < poolSize; ++sessionId) {
		mPool.at(sessionId).open(backendName, connectionString);
	}
}

void SqLite3Backend::restart() {
	stop();
	mDirectory = TmpDir{kDirectoryName.data()};
	mConnectionString = createDbFile().string();
}

void SqLite3Backend::stop() {
	std::filesystem::remove_all(mDirectory.path());
}

void SqLite3Backend::clear() {
	restart();
}

std::filesystem::path SqLite3Backend::createDbFile() const {
	const auto filePath = mDirectory.path() / "database.db";
	std::ofstream file{filePath};
	file.close();
	if (!filesystem::exists(filePath))
		throw runtime_error{"failed to create sqlite3 database file ("s + filePath.string() + ")"};
	return filePath;
}

MySqlBackend::MySqlBackend() {
	mServer->waitReady();
}

void MySqlBackend::restart() {
	if (isStopped()) {
		mServer = make_unique<MysqlServer>();
		mServer->waitReady();
	} else {
		mServer->restart();
	}
}

void MySqlBackend::stop() {
	mServer.reset();
}

void MySqlBackend::clear() {
	mServer->clear();
}

} // namespace flexisip::tester