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

#include "etchosts.hh"

#include <cstdio>

using namespace ::std;

EtcHostsResolver *EtcHostsResolver::sInstance=NULL;

EtcHostsResolver::EtcHostsResolver(){
	char line[256]={0};
	FILE *f=fopen("/etc/hosts","r");
	if (f==NULL) {
		LOGE("Could not open /etc/hosts");
		return;
	}

	/* Parse the /etc/hosts file */
	while(fgets(line,sizeof(line)-1,f)!=NULL){
		char ip[256];
		char name[256];
		int consumed;
		char* subLine = line;
		if (sscanf(subLine,"%s%n",ip,&consumed)==1 && ip[0]!='#'){
			subLine+=consumed;
			while (sscanf(subLine,"%s%n",name,&consumed)==1) {
				LOGD("Read %s %s",ip,name);
				mMap[name]=ip;
				subLine+=consumed;
			}
		}
	}
	fclose(f);
}

void EtcHostsResolver::atexit() {
	if (sInstance!=NULL) {
		delete sInstance;
		sInstance = NULL;
	}
}


EtcHostsResolver *EtcHostsResolver::get(){
	if (sInstance==NULL){
		sInstance=new EtcHostsResolver();
		::atexit(EtcHostsResolver::atexit);
	}
	return sInstance;
}

bool EtcHostsResolver::resolve(const string &name, string *result)const{
	auto it=mOverrideMap.find(name);
	if (it!=mOverrideMap.end()) {
		*result=(*it).second;
		return true;
	}

	it=mMap.find(name);
	if (it!=mMap.end()) {
		*result=(*it).second;
		return true;
	}

	return false;
}

void EtcHostsResolver::setHost(const std::string &name, const std::string &result) {
	if (result.empty()) {
		LOGD("Erasing host association for %s", name.c_str());
		mOverrideMap.erase(name);
	}
	else {
		LOGD("Overriding hostname %s with address %s", name.c_str(), result.c_str());
		mOverrideMap.insert(make_pair(name, result));
	}
}
