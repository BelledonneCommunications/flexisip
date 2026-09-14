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

#include "flexisip/configmanager.hh"

using namespace std::string_literals;

namespace flexisip::space_store {
namespace {
constexpr auto configSection = "global::domains";

// Statically define default configuration items.
auto& defineConfig = ConfigManager::defaultInit().emplace_back([](GenericStruct& root) {
	ConfigItemDescriptor items[] = {
	    {
	        String,
	        "domains-configuration",
	        "Specifies how this server obtains the SIP domains and associated users it manages.\n"
	        "The server can retrieve the SIP domain and user configuration from:\n"
	        "\t- 'flexiapi': fetch from a server that implements the FlexiAPI (configure in the [global::flexiapi] "
	        "section)\n"
	        "\t- 'path/to/config.json': path to json configuration file (loaded once during startup phase)\n"
	        "Leave empty to disable the feature.",
	        "",
	    },
	    {
	        DurationMIN,
	        "refresh-delay",
	        "The duration in minutes between two refreshes of the dynamic domain cache.\n"
	        "This is only useful when the parameter \"domains-configuration\" is set to 'flexiapi'.",
	        "5",
	    },
	    config_item_end,
	};

	auto uS = std::make_unique<GenericStruct>(configSection,
	                                          "Configuration parameters for multi-domains uses of Flexisip", 0);
	auto* s = root.addChild(std::move(uS));
	s->addChildrenValues(items);
});
} // namespace
} // namespace flexisip::space_store
