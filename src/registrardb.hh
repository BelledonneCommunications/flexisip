/*
	Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010  Belledonne Communications SARL.

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

#ifndef registrardb_hh
#define registrardb_hh

#include <map>
#include <string>

#include <sofia-sip/sip.h>

class Record{
	public:
		Record(const sip_from_t *from, const sip_contact_t *contact, time_t expireTime);
		const sip_contact_t * getContact()const{
			return mContact;
		}
		time_t getExpireTime()const{
			return mExpireTime;
		}
		~Record();
	private:
		su_home_t mHome;
		sip_from_t *mFrom;
		sip_contact_t *mContact;
		int mExpireTime;
};

/**
 * A singleton class which holds records contact addresses associated with a from.
 * It is used by the Registrar module.
**/
class RegistrarDb{
	public:
		static RegistrarDb *get();
		void addRecord(const sip_from_t *from, const sip_contact_t *contact, int expires);
		const sip_contact_t* retrieveMostRecent(const url_t *from);
	private:
		RegistrarDb();
		std::map<std::string,Record*> mRecords;
		static RegistrarDb *sUnique;
};

#endif
