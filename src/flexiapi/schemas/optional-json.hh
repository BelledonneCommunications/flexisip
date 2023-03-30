/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023 Belledonne Communications SARL, All rights reserved.

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

#include <optional>

#include "lib/nlohmann-json-3-11-2/json.hpp"

NLOHMANN_JSON_NAMESPACE_BEGIN
template <typename T>
struct adl_serializer<std::optional<T>> {
	static void to_json(json& j, const std::optional<T>& opt) {
		if (opt == std::nullopt) {
			j = nullptr;
		} else {
			j = *opt; // this will call adl_serializer<T>::to_json which will
			          // find the free function to_json in T's namespace!
		}
	}

	static void from_json(const json& j, std::optional<T>& opt) {
		if (j.is_null()) {
			opt = std::nullopt;
		} else {
			opt = j.get<T>(); // same as above, but with
			                  // adl_serializer<T>::from_json
		}
	}
};
NLOHMANN_JSON_NAMESPACE_END