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
			" from.uri.domain contains 'sip.linphone.org', from.uri.domain in 'a.org b.org c.org',"
			" (to.uri.domain in 'a.org b.org c.org') && (user-agent == 'Linphone v2')",
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

class SipArguments : public Arguments {
	sip_t *sip;

	static string subKey(const string &key, size_t *pos) {
		size_t dot=key.find('.', *pos)-*pos;
		if (dot != string::npos) {
			string id=key.substr(*pos, dot);
//			LOGD("SUBKEY '%s' from '%s'", id.c_str(), key.c_str());
			*pos+=dot+1;
			return id;
		}

		if (key.size() != *pos) {
//			LOGD("SUBKEY '%s'", key.c_str());
			*pos=key.size();
			return key;
		}
		return "";
	}

	static string cstring_get(const string &key, size_t pos, const char *str) {
		if (!str) throw new invalid_argument("Null string found in sip msg for " + key);
		return std::string(str);
	}

	static string url_get(const string &key, size_t pos, const url_t *url) {
		string id=subKey(key, &pos);
		if (!url) throw new invalid_argument("No url found in sip msg for " + key);
		if (id == "domain") return cstring_get(key, pos, url->url_host);
		if (id == "user") return cstring_get(key, pos, url->url_user);
		throw new runtime_error("url_get: unhandled arg '" + id + "' in " + key);
	}

	static string addr_get(const string &key, size_t pos, const sip_addr_s *addr) {
		string id=subKey(key, &pos);
		if (!addr) throw new invalid_argument("No address found in sip msg for " + key);
		if (id == "uri") return url_get(key, pos, addr->a_url);
		throw new runtime_error("addr_get: unhandled arg '" + id + "' in " + key);
	}

	static string request_get(const string &key, size_t pos, const sip_request_t *req) {
		string id=subKey(key, &pos);
		if (!req) throw new invalid_argument("No request found in sip msg for " + key);
		if (id == "uri") return url_get(key, pos, req->rq_url);
		if (id == "mn" || id == "method-name") return cstring_get(key, pos, req->rq_method_name);
		throw new runtime_error("request_get: unhandled arg '" + id + "' in " + key);
	}

	static string ua_get(const string &key, size_t pos, const sip_user_agent_t *ua)  {
		if (!ua) throw new invalid_argument("No user-agent found in sip msg for " + key);
		return cstring_get(key, pos, ua->g_string);
	}

	static bool is_request(sip_t *sip) {
		return sip_is_request((sip_header_t *)sip->sip_request);
	}
public:
	SipArguments(sip_t *sip) : sip(sip){};
	virtual std::string get(const std::string &key) const {
		size_t pos=0;
		string id=subKey(key, &pos);

		if (id == "from") return addr_get(key, pos, (sip_addr_s *)sip->sip_from);
		if (id == "to") return addr_get(key, pos, (sip_addr_s *)sip->sip_to);
		if (id == "request") return request_get(key, pos, sip->sip_request);
		if (id == "ua" || id == "user-agent") return ua_get(key, pos, sip->sip_user_agent);

		throw new runtime_error("unhandled arg '" + id + "' in '" + key+ "'");
	}

	virtual bool isTrue(const string &key) const {
		if (key == "is_request") {
			return is_request(sip);
		} else if (key == "is_response") {
			return !is_request(sip);
		}
		throw new runtime_error("unhandled true/false " + key);
	}
};

bool ConfigEntryFilter::canEnter(sip_t *sip) {
	if (!mEnabled) return false;

	SipArguments arguments(sip);
	try {
		return mBooleanExprFilter->eval(&arguments);
	} catch (const invalid_argument *e) {
		LOGD("Entry to %s forbidden on filtering error %s", mEntryName.c_str(), e->what());
		throw;
	}
}

bool ConfigEntryFilter::isEnabled(){
	return mEnabled;
}

