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

#include <flexisip/logmanager.hh>
#include <tclap/CmdLine.h>

#include "exceptions/exit.hh"
#include "main/flexisip.hh"

using namespace std;

int main(int argc, const char* argv[]) {
	/**
	 * Log message using provided level if the LogManager is initialized, otherwise log to stdout or stderr.
	 */
	static const auto log = [](BctbxLogLevel level, string_view message) {
		if (flexisip::LogManager::get().isInitialized()) STREAM_LOG(level) << message;
		else switch (level) {
				case BCTBX_LOG_ERROR:
					cerr << message << '\n';
					break;
				case BCTBX_LOG_DEBUG:
				default:
					cout << message << '\n';
					break;
			}
	};

	try {
		return flexisip::main(argc, argv);
	} catch (const TCLAP::ExitException& exception) {
		// Exception raised when the program failed to correctly parse command line options.
		return exception.getExitStatus();
	} catch (const flexisip::ExitSuccess& exception) {
		if (exception.what() != nullptr && exception.what()[0] != '\0')
			log(BCTBX_LOG_DEBUG, "Exit success: "s + exception.what());

		return EXIT_SUCCESS;
	} catch (const flexisip::Exit& exception) {
		if (exception.what() != nullptr && exception.what()[0] != '\0')
			log(BCTBX_LOG_ERROR, "Exit failure: "s + exception.what());

		return exception.code();
	} catch (const exception& exception) {
		log(BCTBX_LOG_ERROR, "Error, caught an unexpected exception: "s + exception.what());
		return EXIT_FAILURE;
	} catch (...) {
		log(BCTBX_LOG_ERROR, "Error, caught an unknown exception");
		return EXIT_FAILURE;
	}
}