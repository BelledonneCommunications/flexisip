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

#include <sofia-sip/sip.h>

#include "registrardb.hh"

namespace flexisip {

class RegistrarDbInternal : public RegistrarDb {
public:
	RegistrarDbInternal(Agent* ag);
	void clearAll();

	void fetchExpiringContacts(time_t startTimestamp,
	                           std::chrono::seconds timeRange,
	                           std::function<void(std::vector<ExtendedContact>&&)>&& callback) const override;

private:
	void doBind(const MsgSip &msg, const BindingParameters &parameters, const std::shared_ptr<ContactUpdateListener> &listener) override;
	void doClear(const MsgSip &msg, const std::shared_ptr<ContactUpdateListener> &listener) override;
	void doFetch(const SipUri &url, const std::shared_ptr<ContactUpdateListener> &listener) override;
	void doFetchInstance(const SipUri &url, const std::string &uniqueId, const std::shared_ptr<ContactUpdateListener> &listener) override;
	void doMigration() override;
	void publish(const std::string &topic, const std::string &uid) override;

	std::map<std::string, std::shared_ptr<Record>> mRecords;
};

}
