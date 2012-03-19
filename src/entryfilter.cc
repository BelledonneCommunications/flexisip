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

ConfigItemDescriptor configaaa[]={
	{	Boolean,		"enabled",					"Indicate whether the module is activated.",	"true"},
	{	StringList,		"from-domains",	"List of domain names in sip from allowed to enter the module.",	"*"},
	{	StringList,		"to-domains"	,		"List of domain names in sip to allowed to enter the module.",		"*"},
	config_item_end
};

void ConfigEntryFilter::declareConfig(GenericStruct *module_config){
	module_config->addChildrenValues(configaaa);
}

void ConfigEntryFilter::loadConfig(const GenericStruct  *module_config){
	mFromDomains=module_config->get<ConfigStringList>("from-domains")->read();
	mToDomains=module_config->get<ConfigStringList>("to-domains")->read();
	mEnabled=module_config->get<ConfigBoolean>("enabled")->read();
}

bool ConfigEntryFilter::canEnter(sip_t *sip){
	if (!mEnabled) return false;
	
	url_t *sipuri=sip->sip_from->a_url;
	// Early fail if not the normal state
	if (/*sipuri && sipuri->url_host && */!ModuleToolbox::matchesOneOf(sipuri->url_host,mFromDomains))
		return false;
	sipuri=sip->sip_to->a_url;
	if (/*sipuri && sipuri->url_host && */!ModuleToolbox::matchesOneOf(sipuri->url_host,mToDomains))
		return false;
	return true;
}

bool ConfigEntryFilter::isEnabled(){
	return mEnabled;
}

