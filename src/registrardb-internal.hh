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

#ifndef registrardb_internal_hh
#define registrardb_internal_hh

#include "registrardb.hh"
#include <sofia-sip/sip.h>

class RegistrarDbInternal : public RegistrarDb {
  public:
	RegistrarDbInternal(const std::string &preferredRoute);
	void clearAll();

  private:
	virtual void doBind(const url_t *ifrom, sip_contact_t *icontact, const char *iid, uint32_t iseq, const sip_path_t *ipath, 
		std::list<std::string> acceptHeaders, bool usedAsRoute, int expire, int alias, int version, const std::shared_ptr<ContactUpdateListener> &listener);
	virtual void doClear(const sip_t *sip, const std::shared_ptr<ContactUpdateListener> &listener);
	virtual void doFetch(const url_t *url, const std::shared_ptr<ContactUpdateListener> &listener);
	virtual void doFetchForGruu(const url_t *url, const std::string &gruu, const std::shared_ptr<ContactUpdateListener> &listener);
	virtual void doMigration();
	virtual void publish(const std::string &topic, const std::string &uid);
};

#endif
