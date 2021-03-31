/*
 Flexisip, a flexible SIP proxy server with media capabilities.
 Copyright (C) 2010-2021  Belledonne Communications SARL, All rights reserved.

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

#pragma once

#include <sstream>
#include <string>
#include <vector>

#include <nghttp2/nghttp2.h>

namespace flexisip {

class NgDataProvider {
  public:
	NgDataProvider(const std::vector<char>& data) noexcept;
	NgDataProvider(const std::string& data) noexcept;

	const nghttp2_data_provider* getCStruct() const noexcept {
		return &mDataProv;
	}

  private:
	ssize_t read(uint8_t* buf, size_t length, uint32_t* data_flags) noexcept;

	nghttp2_data_provider mDataProv{{0}};
	std::stringstream mData{};
};

} // namespace flexisip
