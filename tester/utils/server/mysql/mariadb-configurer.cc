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

#include "mariadb-configurer.hh"
#include "db-server-configurer.hh"

#include <unistd.h>

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <utility>
#include <variant>

#include "flexisip-tester-config.hh"
#include "flexisip/logmanager.hh"
#include "mysql-server.hh"
#include "utils/pipe.hh"
#include "utils/posix-process.hh"
#include "utils/rand.hh"
#include "utils/string-utils.hh"
#include "utils/sys-err.hh"

using namespace std;
using namespace std::string_literals;

namespace flexisip::tester {

std::unique_ptr<DbServerConfigurer> DbServerConfigurer::getConfigurer(MysqlServer& server) {
	return make_unique<MariaDbConfigurer>(server);
}

process::Process MariaDbConfigurer::initialSetup(const string& dataDirArg) {
	process::Process setup([&dataDirArg] {
		::execl(MYSQL_SERVER_EXEC, MYSQL_SERVER_EXEC,
		        // Some distros pack default install configurations (like default user), ignore that
		        "--no-defaults",
		        // Bypass mysql_install_db to speedup database setup
		        "--bootstrap",
		        // Skip InnoDB startup
		        "--innodb=OFF", "--default-storage-engine=MEMORY",
		        //
		        dataDirArg.c_str(), nullptr);
	});

	{
		auto setupStdin = visit(
		    [](auto& state) -> pipe::WriteOnly {
			    if constexpr (is_same_v<decay_t<decltype(state)>, process::Running>) {
				    return visit(
				        [](auto&& pipe) -> pipe::WriteOnly {
					        if constexpr (is_same_v<decay_t<decltype(pipe)>, pipe::WriteOnly>) {
						        return std::move(pipe);
					        } else {
						        cerr << "Stdin pipe to mysql setup process in unexpected state: " << pipe << endl;
						        ::exit(EXIT_FAILURE);
						        throw runtime_error{"unreachable"};
					        }
				        },
				        exchange(state.mStdin, pipe::Closed()));
			    }

			    cerr << "Mysql setup process unexpectedly quit";
			    ::exit(EXIT_FAILURE);
			    throw runtime_error{"unreachable"};
		    },
		    setup.state());

		ostringstream sql{};
		sql << "CREATE DATABASE IF NOT EXISTS mysql;\n";
		sql << "USE mysql;\n";
		sql << ifstream(MYSQL_SYSTEM_TABLES_SETUP).rdbuf();
		sql << "CREATE DATABASE IF NOT EXISTS " << MysqlServer::kDbName << ";\n";
		if (auto err = setupStdin.write(sql.str())) {
			cerr << "Failed to write to mysql setup process stdin: " << *err << endl;
			::exit(EXIT_FAILURE);
		}
	} // closing stdin

	return setup;
}

} // namespace flexisip::tester