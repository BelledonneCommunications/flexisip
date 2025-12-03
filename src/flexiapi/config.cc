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

#include "config.hh"

#include <memory>

#include "agent.hh"
#include "exceptions/bad-configuration.hh"
#include "flexisip/configmanager.hh"
#include "flexisip/utils/sip-uri.hh"
#include "utils/transport/http/http2client.hh"

using namespace std::string_literals;

namespace flexisip::flexiapi {
namespace {
constexpr auto configSection = "global::flexiapi";

// Statically define default configuration items.
auto& defineConfig = ConfigManager::defaultInit().emplace_back([](GenericStruct& root) {
	ConfigItemDescriptor items[] = {
	    {
	        String,
	        "url",
	        "HTTPS URL of the FlexiAPI server.\n"
	        "Example: https://flexiapi.org",
	        "",
	    },
	    {
	        String,
	        "api-key",
	        "API key for the FlexiAPI.",
	        "",
	    },
	    config_item_end,
	};

	auto uS = std::make_unique<GenericStruct>(
	    configSection,
	    "Configuration parameters for establishing a connection to the HTTP server that implements the FlexiAPI "
	    "interface. For now, these settings are exclusively used for the push notification gateway functionality.",
	    0);
	auto* s = root.addChild(std::move(uS));
	s->addChildrenValues(items);
});
} // namespace

std::shared_ptr<Http2Client> createClient(const std::shared_ptr<ConfigManager>& cfg, sofiasip::SuRoot& root) {
	// Create the HTTP Client that should be used for the FlexiAPI
	const auto* flexiApiConfigSection = cfg->getRoot()->get<GenericStruct>(configSection);
	const auto* flexiApiUrlParameter = flexiApiConfigSection->get<ConfigString>("url");
	try {
		const sofiasip::Url flexiApiUrl{flexiApiUrlParameter->read()};
		if (!flexiApiUrl.empty()) {
			auto urlType = flexiApiUrl.getType();
			if (urlType != url_https) {
				throw BadConfigurationValue{flexiApiUrlParameter, "URL scheme MUST be 'HTTPS'"};
			}
			return Http2Client::make(root, flexiApiUrl.getHost(), std::string{flexiApiUrl.getPortWithFallback()});
		}
	} catch (std::exception& e) {
		throw BadConfigurationValue{flexiApiUrlParameter, "invalid URL ("s + e.what() + ")"};
	}
	return nullptr;
}

} // namespace flexisip::flexiapi