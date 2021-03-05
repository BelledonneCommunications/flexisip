/*
 * Flexisip, a flexible SIP proxy server with media capabilities.
 * Copyright (C) 2021  Belledonne Communications SARL, All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include <set>

#include <flexisip/auth/authentifier.hh>
#include <flexisip/common.hh>

namespace flexisip {

class TrustedHostAuthentifier : public Authentifier {
public:
	template <typename T>
	TrustedHostAuthentifier(T &&tHosts) : mTrustedHosts{std::forward<T>(tHosts)} {}
	TrustedHostAuthentifier(const TrustedHostAuthentifier &) = delete;
	TrustedHostAuthentifier(TrustedHostAuthentifier &&) = delete;

	void verify(const std::shared_ptr<AuthStatus> &as) override;

private:
	static bool empty(const char *value) {return value == nullptr || value[0] == '\0';}

	std::set<BinaryIp> mTrustedHosts{};
};

} // namespace flexisip
