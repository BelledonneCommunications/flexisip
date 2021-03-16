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

#include <string>
#include <vector>

#include <nghttp2/nghttp2.h>

namespace flexisip {

class HeaderStore {
  public:
	struct Header {
		std::string name{};
		std::string value{};
		uint8_t flags{NGHTTP2_FLAG_NONE};
	};

	using HeaderList = std::vector<Header>;
	using CHeaderList = std::vector<nghttp2_nv>;

	HeaderStore() = default;
	HeaderStore(const HeaderStore &) = default;
	HeaderStore(HeaderStore &&) = default;

	HeaderStore &operator=(const HeaderStore &) = default;
	HeaderStore &operator=(HeaderStore &&) = default;

	const HeaderList &getMHList() const {
		return mHList;
	}

	void add(std::string name, std::string value, uint8_t flags = NGHTTP2_FLAG_NONE) noexcept;
	std::string toString() const noexcept;

	CHeaderList makeHeaderList() const noexcept;

  private:
	HeaderList mHList{};
};

} // namespace flexisip
