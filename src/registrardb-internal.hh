/*
		Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2012  Belledonne Communications SARL.
	Author: Guillaume Beraudo

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

#include <flexisip/registrardb.hh>
#include <sofia-sip/sip.h>

namespace flexisip {

class RegistrarDbInternal : public RegistrarDb {
  public:
	RegistrarDbInternal(Agent *ag);
	void clearAll();

  private:
	virtual void doBind(const sip_t *sip, int globalExpire, bool alias, int version, const std::shared_ptr<ContactUpdateListener> &listener) override;
	virtual void doClear(const sip_t *sip, const std::shared_ptr<ContactUpdateListener> &listener) override;
	virtual void doFetch(const SipUri &url, const std::shared_ptr<ContactUpdateListener> &listener) override;
	virtual void doFetchInstance(const SipUri &url, const std::string &uniqueId, const std::shared_ptr<ContactUpdateListener> &listener) override;
	virtual void doMigration() override;
	virtual void publish(const std::string &topic, const std::string &uid) override;
	std::map<std::string, std::shared_ptr<Record>> mRecords;
};

}
