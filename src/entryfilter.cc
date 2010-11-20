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

#include "entryfilter.hh"
#include "module.hh"

using namespace::std;

ConfigEntryFilter::ConfigEntryFilter(){
}

ConfigEntryFilter::~ConfigEntryFilter(){
}

void ConfigEntryFilter::loadConfig(const ConfigArea &module_config){
	list<string> defaultvalue;
	defaultvalue.push_back("*");
	mDomains=module_config.get("domains",defaultvalue);
	mEnabled=module_config.get("enabled",true);
}

bool ConfigEntryFilter::canEnter(sip_t *sip){
	if (!mEnabled) return false;
	
	url_t *sipuri=sip->sip_from->a_url;
	if (sipuri && sipuri->url_host)
		return ModuleToolbox::matchesOneOf(sipuri->url_host,mDomains);
	return true;
}

