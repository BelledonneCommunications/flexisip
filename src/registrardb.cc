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
	mFrom=sip_from_dup(&mHome,from);
	mContact=sip_contact_dup(&mHome,contact);
}

Record::~Record(){
	su_home_deinit(&mHome);
}

RegistrarDb::RegistrarDb(){
}

void RegistrarDb::addRecord(const sip_from_t *from, const sip_contact_t *contact, int expires){
	char tmp[128]={0};
	map<string,Record*>::iterator it;
	
	snprintf(tmp,sizeof(tmp)-1,"%s@%s",from->a_url->url_user,from->a_url->url_host);
	it=mRecords.find(tmp);
	if (expires>0){
		time_t expireTime=time(NULL)+expires;
		Record *rec=new Record(from,contact,expireTime);
		if (it!=mRecords.end()){
			delete (*it).second;
			(*it).second=rec;
		}else mRecords.insert(make_pair(tmp,rec));
	}else if (it!=mRecords.end()){
		mRecords.erase(it);
	}
}

const sip_contact_t* RegistrarDb::retrieveMostRecent(const url_t *a_url){
	map<string,Record*>::iterator it;

	char tmp[128]={0};
	snprintf(tmp,sizeof(tmp)-1,"%s@%s",a_url->url_user,a_url->url_host);
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

RegistrarDb *RegistrarDb::sUnique=NULL;

RegistrarDb *RegistrarDb::get(){
	if (sUnique==NULL)
		sUnique=new RegistrarDb ();
	return sUnique;
}
