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

#include "header-store.hh"

namespace flexisip {

class HttpMessage {
  public:
	HttpMessage() = default;
	HttpMessage(const HeaderStore& headerStore,const std::vector<char> body) : mHeaderStore(headerStore), mBody(body){};
	virtual ~HttpMessage() = default;

	const std::vector<char>& getBody() const{
		return mBody;
	}

	void setBody(std::vector<char>& body) {
		this->mBody = body;
	}

	void appendBody(std::string& body) {
		this->mBody.insert(mBody.end(), body.begin(), body.end());
	}

	const HeaderStore& getHeaderStore() const {
		return mHeaderStore;
	}

	HeaderStore& getHeaderStore() {
		return mHeaderStore;
	}

	void setHeaderStore(const HeaderStore& headerStore) {
		this->mHeaderStore = headerStore;
	}

	std::string toString() const noexcept;

  protected:
	HeaderStore mHeaderStore{};
	std::vector<char> mBody{};
};

} // namespace flexisip
