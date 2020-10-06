/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2010-2020  Belledonne Communications SARL, All rights reserved.

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

#include "pushnotificationclient.hh"

namespace flexisip {
namespace pushnotification {

class ClientWp : public LegacyClient {
	public:
		ClientWp(std::unique_ptr<Transport> &&transport, const std::string &name,
			const Service &service, unsigned maxQueueSize,
			const std::string &packageSID, const std::string &applicationSecret);
		~ClientWp() override = default;

		bool sendPush(const std::shared_ptr<Request> &req) override;

	protected:
		void retrieveAccessToken();

	private:
		std::string mPackageSID{};
		std::string mApplicationSecret{};
		std::string mAccessToken{};
		time_t mTokenExpiring{0};
};

}
}
