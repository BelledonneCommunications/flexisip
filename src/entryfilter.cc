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
#include <stdexcept>

using namespace::std;

ConfigEntryFilter::ConfigEntryFilter(){
}

ConfigEntryFilter::~ConfigEntryFilter(){
}

ConfigItemDescriptor config[]={
	{	Boolean,	"enabled",		"Indicate whether the module is activated.",	"true"},
	{	String,		"from-domains",	"Deprecated: List of domain names in sip from allowed to enter the module.",	"*"},
	{	String,		"to-domains",	"Deprecated: List of domain names in sip to allowed to enter the module.",		"*"},
	{	String,		"filter",		"A request/response enters module if the boolean filter evaluates to true. Ex:"
			" from contains 'sip.linphone.org', fromdomains in 'a.org b.org c.org',"
			" todomains in 'a.org b.org c.org', ua = 'Linphone v2'",
			""},
	config_item_end
};

void ConfigEntryFilter::declareConfig(GenericStruct *module_config){
	module_config->addChildrenValues(config, FALSE);
}

void ConfigEntryFilter::loadConfig(const GenericStruct  *mc){
	string filter=mc->get<ConfigString>("filter")->read();
	if (filter.empty()) {
		string fromDomains=mc->get<ConfigString>("from-domains")->read();
		if (!fromDomains.empty() && fromDomains != "*") {
			filter = "fromdomain in '" + fromDomains + "'";
		}

		string toDomains=mc->get<ConfigString>("to-domains")->read();
		if (!toDomains.empty() && toDomains != "*") {
			if (!filter.empty()) filter += " && ";
			filter += "todomain in '" + toDomains + "'";
		}
	}
	mEnabled=mc->get<ConfigBoolean>("enabled")->read();
	mBooleanExprFilter=BooleanExpression::parse(filter);
}

class SipArguments : public Arguments {
	sip_t *mSip;
public:
	SipArguments(sip_t *sip) : mSip(sip){};
	virtual std::string get(const std::string &arg) const {
		if (arg == "fromdomain") {
			if (!mSip->sip_from || !mSip->sip_from->a_url || !mSip->sip_from->a_url[0].url_host) {
				throw new invalid_argument("from domain not found in sip msg");
			}
			return mSip->sip_from->a_url[0].url_host;
		}

		if (arg == "todomain") {
			if (!mSip->sip_to || !mSip->sip_to->a_url || !mSip->sip_to->a_url[0].url_host) {
				throw new invalid_argument("to domain not found in sip msg");
			}
			return mSip->sip_to->a_url[0].url_host;
		}

		if (arg == "ua" || arg == "useragent") {
			if (!mSip->sip_user_agent || !mSip->sip_user_agent->g_string) {
				throw new invalid_argument("ua not found in sip msg");
			}
			return mSip->sip_user_agent->g_string;
		}

		throw new runtime_error("unhandled arg " + arg);
	}
};

bool ConfigEntryFilter::canEnter(sip_t *sip){
	if (!mEnabled) return false;

	SipArguments arguments(sip);
	try {
		return mBooleanExprFilter->eval(&arguments);
	} catch (invalid_argument &e) {
		LOGD("Entry forbidden on filtering error %s", e.what());
	}

	return false;
}

bool ConfigEntryFilter::isEnabled(){
	return mEnabled;
}

