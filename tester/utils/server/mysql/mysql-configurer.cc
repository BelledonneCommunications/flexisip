/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2025 Belledonne Communications SARL, All rights reserved.

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

#include "mysql-configurer.hh"
#include "db-server-configurer.hh"

#include <unistd.h>

#include <fstream>

#include "flexisip-tester-config.hh"
#include "mysql-server.hh"
#include "utils/posix-process.hh"
#include "utils/rand.hh"

using namespace std;
using namespace std::string_literals;

namespace flexisip::tester {

std::unique_ptr<DbServerConfigurer> DbServerConfigurer::getConfigurer(MysqlServer& server) {
	return make_unique<MysqlConfigurer>(server);
}

process::Process MysqlConfigurer::initialSetup(const string& dataDirArg) {
	process::Process setup([&dataDirArg] {
		::execl(MYSQL_SERVER_EXEC, MYSQL_SERVER_EXEC,
		        // Some distros pack default install configurations (like default user), ignore that
		        "--no-defaults",
		        // Initialize the database
		        "--initialize-insecure", "--default-storage-engine=MEMORY",
		        //
		        dataDirArg.c_str(), nullptr);
	});

	return setup;
}

std::vector<std::string> MysqlConfigurer::getExecArgs() {
	// Generate a random undo directory, because for some unknown reason MySQL can't seem to reuse these files and shows
	// an error everytime.
	const auto undoDirPath = mServer.getDatadirPath() / ("undo" + [] {
		                         static Random random{};
		                         return random.string().generate(10);
	                         }());
	return {
	    "--innodb_undo_directory=" + undoDirPath.string(),
	};
}

void MysqlConfigurer::onReady() {
	mServer.createDatabaseIfNotExists();
}

} // namespace flexisip::tester