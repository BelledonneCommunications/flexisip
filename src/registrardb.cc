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

#include "registrardb.hh"

#include <time.h>
#include <cstdio>


#include <sofia-sip/sip_protos.h>

using namespace::std;

Record::Record(const sip_from_t *from, const sip_contact_t *contact, time_t expireTime){
	su_home_init(&mHome);
	mExpireTime=expireTime;
	mFrom=sip_from_copy (&mHome,from);
	mContact=sip_contact_copy(&mHome,contact);
}

Record::~Record(){
	su_home_deinit(&mHome);
}

RegistrarDb::RegistrarDb(){
}

void RegistrarDb::addRecord(const sip_from_t *from, const sip_contact_t *contact, time_t expireTime){
	char tmp[128]={0};
	
	snprintf(tmp,sizeof(tmp)-1,"%s@%s",from->a_url->url_user,from->a_url->url_host);
	Record * &ref_record=mRecords[tmp];
	if (ref_record!=NULL){
		delete ref_record;
	}
	ref_record=new Record(from,contact,expireTime);
	
}

const sip_contact_t* RegistrarDb::retrieve(const sip_from_t *from){
	map<string,Record*>::iterator it;

	char tmp[128]={0};
	snprintf(tmp,sizeof(tmp)-1,"%s@%s",from->a_url->url_user,from->a_url->url_host);
	it=mRecords.find(tmp);
	if (it!=mRecords.end()){
		Record *r=(*it).second;
		/*check expiration*/
		if (time(NULL) <= r->getExpireTime()){
			return r->getContact();
		}else{
			/*can be removed*/
			mRecords.erase(it);
			delete r;
		}
	}
	return NULL;
}

