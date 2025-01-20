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

#include "main/flexisip.hh"

using namespace std;
using namespace flexisip;

int main(int argc, const char* argv[]) {
	try {
		return _main(argc, argv);
	} catch (const TCLAP::ExitException& exception) {
		// Exception raised when the program failed to correctly parse command line options.
		return exception.getExitStatus();
	} catch (const ExitSuccess& exception) {
		if (exception.what() != nullptr && exception.what()[0] != '\0') {
			SLOGD << "Exit success: " << exception.what();
		}
		return EXIT_SUCCESS;
	} catch (const Exit& exception) {
		cerr << "Error: " << exception.what() << endl;
		return exception.code();
	} catch (const exception& exception) {
		cerr << "Error, caught an unexpected exception: " << exception.what() << endl;
		return EXIT_FAILURE;
	} catch (...) {
		cerr << "Error, caught an unknown exception" << endl;
		return EXIT_FAILURE;
	}
}