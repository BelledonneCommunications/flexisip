/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

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

#include <string>
#include <vector>

namespace flexisip {

/**
 * All this class is think with
 * https://wiki.linphone.org/xwiki/wiki/public/view/Flexisip/D.%20Specifications/Push%20notifications/
 * in mind.
 * Legacy contact parameters for push can looks like :
 * app-id=a.bundle.id.prod;pn-type=apple;pn-tok=ATOKEN;
 * app-id=a.bundle.id.dev;pn-type=apple;pn-tok=ATOKEN;
 * app-id=a.project.id;pn-type=google;pn-tok=ATOKEN;
 * app-id=a.project.id;pn-type=firebase;pn-tok=ATOKEN;
 */
class PushParam {
public:
	PushParam(const std::string& prId, const std::string& param);

	const std::string& getParam() const {
		return mParam;
	}

	const std::string& getPrId() const {
		return mPrId;
	}

	bool isInvalid() const {
		return mPrId.empty() || mParam.empty();
	}

	bool operator==(const PushParam& pp) const;

private:
	std::string mPrId{};
	std::string mParam{};
};

class PushParamList {
public:
	PushParamList() = default;
	PushParamList(const std::string& provider, const std::string& customPrId, const std::string& customParam,
	              bool isLegacyContactParams = false);
	~PushParamList() = default;

	const std::string& getProvider() const {
		return mProvider;
	}

	const std::vector<PushParam>& getPushParams() const {
		return mPushParams;
	}

	bool operator==(const PushParamList& ppl) const;

private:
	void constructFromContactParameters(const std::string& provider, const std::string& customPrid,
	                                    const std::string& customParam);
	void constructFromLegacyContactParameters(const std::string& pnType, const std::string& pnTok,
	                                          const std::string& appId);

	std::string mProvider{};
	std::vector<PushParam> mPushParams{};
};

std::ostream& operator<<(std::ostream& os, const flexisip::PushParam& pushParam) noexcept;
std::ostream& operator<<(std::ostream& os, const flexisip::PushParamList& pushParamList) noexcept;

} // namespace flexisip
