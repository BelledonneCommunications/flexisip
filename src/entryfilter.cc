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

static ConfigItemDescriptor config[]={
	{	Boolean,	"enabled",		"Indicate whether the module is activated.",	"true"},
	{	String,		"from-domains",	"Deprecated: List of domain names in sip from allowed to enter the module.",	"*"},
	{	String,		"to-domains",	"Deprecated: List of domain names in sip to allowed to enter the module.",		"*"},
	{	BooleanExpr,	"filter",		"A request/response enters module if the boolean filter evaluates to true. Ex:"
			" from.uri.domain contains 'sip.linphone.org', from.uri.domain in 'a.org b.org c.org',"
			" (to.uri.domain in 'a.org b.org c.org') && (user-agent == 'Linphone v2')",
			""},
	config_item_end
};

void ConfigEntryFilter::declareConfig(GenericStruct *module_config){
	module_config->addChildrenValues(config, false);
	module_config->deprecateChild("from-domains");
	module_config->deprecateChild("to-domains");
	mCountEvalTrue=module_config->createStat("count-eval-true", "Number of filter evaluations to true.");
	mCountEvalFalse=module_config->createStat("count-eval-false", "Number of filter evaluations to false.");
}

void ConfigEntryFilter::loadConfig(const GenericStruct  *mc){
	string filter=mc->get<ConfigValue>("filter")->get();

	if (filter.empty()) {
		string fromDomains=mc->get<ConfigString>("from-domains")->read();
		if (!fromDomains.empty() && fromDomains != "*") {
			filter = "(from.uri.domain in '" + fromDomains + "')";
		}

		string toDomains=mc->get<ConfigString>("to-domains")->read();
		if (!toDomains.empty() && toDomains != "*") {
			if (!filter.empty()) filter += " && ";
			filter += "(to.uri.domain in '" + toDomains + "')";
		}
	}
	mEnabled=mc->get<ConfigBoolean>("enabled")->read();
	mBooleanExprFilter=BooleanExpression::parse(filter);
	mEntryName=mc->getName();
}


bool ConfigEntryFilter::canEnter(const shared_ptr<MsgSip> &ms) {
	if (!mEnabled) return false;

	auto attr=ms->getSipAttr();
	try {
		bool e=mBooleanExprFilter->eval(attr.get());
		if (e) ++*mCountEvalTrue; else ++*mCountEvalFalse;
		return e;
	} catch (invalid_argument &e) {
		LOGD("Fix your %s filter : %s", mEntryName.c_str(), e.what());
		throw;
	}
}

bool ConfigEntryFilter::isEnabled(){
	return mEnabled;
}

