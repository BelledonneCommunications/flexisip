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


#include <boost/version.hpp> 
#if (BOOST_VERSION >= 105400)
#include <boost/log/utility/setup/filter_parser.hpp>
#include <boost/log/utility/setup/formatter_parser.hpp>

#else
#include <boost/log/utility/init/filter_parser.hpp>
#include <boost/log/utility/init/formatter_parser.hpp>
#endif

#include "logmanager.hh"
namespace flexisip {
namespace log {

void register_log_factories() {
#if (BOOST_VERSION >= 105400)
boost::log::register_simple_formatter_factory< flexisip::log::level, char>("Severity");
boost::log::register_simple_filter_factory< flexisip::log::level, char>("Severity");
#else
	boost::log::register_simple_formatter_factory< flexisip::log::level >("Severity");
	boost::log::register_simple_filter_factory< flexisip::log::level >("Severity");

#endif
}

}}
