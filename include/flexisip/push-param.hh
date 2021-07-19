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

namespace flexisip {

class PushParam {
public:
	PushParam(const std::string& prId, const std::string& param) : mPrId{prId}, mParam{param} {};
	~PushParam() = default;

	const std::string& getParam() const {
		return mParam;
	}

	const std::string& getPrId() const {
		return mPrId;
	}

	bool operator==(const PushParam& pp) const;

private:
	std::string mPrId{};
	std::string mParam{};
};

class PushParamList {
public:
	PushParamList() = default;
	PushParamList(const std::string& provider, const std::string& customPrId, const std::string& customParam);
	~PushParamList() = default;

	const std::string& getProvider() const {
		return mProvider;
	}

	const std::vector<PushParam>& getPushParams() const {
		return mPushParams;
	}

	bool operator==(const PushParamList& ppl) const;

private:
	std::string mProvider{};
	std::vector<PushParam> mPushParams{};
};

std::ostream& operator<<(std::ostream& os, const flexisip::PushParam& pushParam) noexcept;
std::ostream& operator<<(std::ostream& os, const flexisip::PushParamList& pushParamList) noexcept;

} // namespace flexisip
