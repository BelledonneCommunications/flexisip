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

#include "flexiapi-builder.hh"

namespace flexisip::tester {

namespace {

constexpr std::string_view kSpacesApiPath{"/api/spaces"};

} // namespace

FlexiapiBuilder& FlexiapiBuilder::addSpace(const nlohmann::json& space) {
	mSpaces.push_back(space);
	return *this;
}

FlexiapiBuilder& FlexiapiBuilder::setSpaces(const nlohmann::json& spaces) {
	mSpaces = spaces;
	return *this;
}

FlexiapiBuilder& FlexiapiBuilder::addEndpoint(const std::string& path, const std::string& response) {
	mEndpoints.emplace(path, response);
	return *this;
}

FlexiapiBuilder& FlexiapiBuilder::setEndpoints(const std::map<std::string, std::string>& endpoints) {
	mEndpoints = endpoints;
	return *this;
}

FlexiapiBuilder& FlexiapiBuilder::addHandler(const std::string& path, http_mock::HttpMockHandler& handler) {
	mHandlers.emplace(path, handler);
	return *this;
}

FlexiapiBuilder& FlexiapiBuilder::setHandlers(const std::map<std::string, http_mock::HttpMockHandler>& handlers) {
	mHandlers = handlers;
	return *this;
}

std::unique_ptr<http_mock::HttpMock> FlexiapiBuilder::build(const std::string& listeningAddress,
                                                            const std::string& port) const {
	auto mock = std::make_unique<http_mock::HttpMock>();

	if (!mSpaces.empty()) mock->addEndpoint(kSpacesApiPath.data(), mSpaces.dump());

	for (const auto& [path, response] : mEndpoints) {
		mock->addEndpoint(path, response);
	}

	for (const auto& [path, handler] : mHandlers) {
		mock->addHandler(path, handler);
	}

	mock->setListeningAddress(listeningAddress);
	mock->serveAsync(port);

	return mock;
}

} // namespace flexisip::tester