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

#pragma once

#include <map>
#include <memory>
#include <string>

#include "http-mock/http-mock.hh"
#include "lib/nlohmann-json-3-11-2/json.hpp"

namespace flexisip::tester {

class FlexiapiBuilder {
public:
	inline static nlohmann::json kDefaultSpace = {{
	    {"domain", "sip.example.org"},
	    {"name", "example"},
	    {"host", "127.0.0.1"},
	}};

	FlexiapiBuilder() = default;
	FlexiapiBuilder(FlexiapiBuilder&&) = default;
	// We don't want to share spaces or handlers between builders
	FlexiapiBuilder(const FlexiapiBuilder&) = delete;

	/**
	 * Add a space to the list of served spaces.
	 * @param space JSON array of a space.
	 */
	FlexiapiBuilder& addSpace(const nlohmann::json& space);

	/**
	 * Replace the current spaces served on GET /api/spaces.
	 * @param spaces JSON array of spaces objects.
	 */
	FlexiapiBuilder& setSpaces(const nlohmann::json& spaces);

	/**
	 * Add a custom endpoint.
	 * @param path Custom path that the mock server will serve.
	 * @param response Custom response for the provided path.
	 */
	FlexiapiBuilder& addEndpoint(const std::string& path, const std::string& response = "");

	/**
	 * Set custom endpoints.
	 * @param endpoints Custom endpoints that the mock server will provide.
	 */
	FlexiapiBuilder& setEndpoints(const std::map<std::string, std::string>& endpoints);

	/**
	 * Add a custom handler.
	 * @param path Custom path that the mock server will serve.
	 * @param handler Custom handler for the provided path.
	 */
	FlexiapiBuilder& addHandler(const std::string& path, http_mock::HttpMockHandler& handler);

	/**
	 * Set custom handlers.
	 * @param handlers Custom handlers that the mock server will provide.
	 */
	FlexiapiBuilder& setHandlers(const std::map<std::string, http_mock::HttpMockHandler>& handlers);

	/**
	 * Create the mock server, bind it on 'listeningAddress' and serve asynchronously.
	 * @return the served mock; read the listening port with getFirstPort() (-1 if serving failed).
	 */
	std::unique_ptr<http_mock::HttpMock> build(const std::string& listeningAddress = "127.0.0.1",
	                                           const std::string& port = "0") const;

private:
	nlohmann::json mSpaces = kDefaultSpace;
	std::map<std::string, std::string> mEndpoints{};
	std::map<std::string, http_mock::HttpMockHandler> mHandlers{};
};

} // namespace flexisip::tester
