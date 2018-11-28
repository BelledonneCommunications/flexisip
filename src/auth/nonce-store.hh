/*
 * Flexisip, a flexible SIP proxy server with media capabilities.
 * Copyright (C) 2018  Belledonne Communications SARL, All rights reserved.
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

#include <ctime>
#include <map>
#include <mutex>
#include <string>

#include <sofia-sip/msg_types.h>


class NonceStore {
public:
	void setNonceExpires(int value) {mNonceExpires = value;}
	int getNc(const std::string &nonce);
	void insert(msg_header_t *response);
	void insert(const std::string &nonce);
	void updateNc(const std::string &nonce, int newnc);
	void erase(const std::string &nonce);
	void cleanExpired();

private:
	struct NonceCount {
		NonceCount(int c, time_t ex) : nc(c), expires(ex) {
		}
		int nc;
		std::time_t expires;
	};

	std::map<std::string, NonceCount> mNc;
	std::mutex mMutex;
	int mNonceExpires = 3600;
};
