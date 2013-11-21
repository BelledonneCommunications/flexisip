/*
Flexisip, a flexible SIP proxy server with media capabilities.
Copyright (C) 2012  Belledonne Communications SARL.

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

#include "sipattrextractor.hh"
#include <string>
#include <sstream>
#include <sofia-sip/sip.h>
#include <sofia-sip/sip_protos.h>
#include <stdexcept>


using namespace std;


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

inline static string cstring_get(const string &key, size_t pos, const char *str) {
	if (!str) throw invalid_argument("Null string found in sip msg for " + key);
	return str;
}
inline static string cstring_or_empty_get(const string &key, size_t pos, const char *str) {
	return str? str : "";
}



inline static string int_get(const string &key, size_t pos, int value) {
	ostringstream oss;
	oss << value;
	return oss.str();
}

static string url_get(const string &key, size_t pos, const url_t *url) {
	string id=subKey(key, &pos);
	if (!url) throw invalid_argument("No url found in sip msg for " + key);
	if (id == "domain") return cstring_get(key, pos, url->url_host);
	if (id == "user") return cstring_get(key, pos, url->url_user);
	if (id == "params") return cstring_or_empty_get(key, pos, url->url_params);
	throw runtime_error("url_get: unhandled arg '" + id + "' in " + key);
}

static string addr_get(const string &key, size_t pos, const sip_addr_s *addr) {
	string id=subKey(key, &pos);
	if (!addr) throw invalid_argument("No address found in sip msg for " + key);
	if (id == "uri") return url_get(key, pos, addr->a_url);
	throw runtime_error("addr_get: unhandled arg '" + id + "' in " + key);
}

static string request_get(const string &key, size_t pos, const sip_request_t *req) {
	string id=subKey(key, &pos);
	if (!req) throw invalid_argument("No request found in sip msg for " + key);
	if (id == "uri") return url_get(key, pos, req->rq_url);
	if (id == "mn" || id == "method-name") return cstring_get(key, pos, req->rq_method_name);
	throw runtime_error("request_get: unhandled arg '" + id + "' in " + key);
}

static string ua_get(const string &key, size_t pos, const sip_user_agent_t *ua)  {
	if (!ua) throw invalid_argument("No user-agent found in sip msg for " + key);
	return cstring_get(key, pos, ua->g_string);
}

static string status_get(const string &key, size_t pos, const sip_status_s *status) {
	string id=subKey(key, &pos);
	if (!status) throw invalid_argument("No status found in sip msg for " + key);
	if (id == "phrase") return cstring_get(key, pos, status->st_phrase);
	if (id == "code") return int_get(key, pos, status->st_status);
	throw runtime_error("status_get: unhandled arg '" + id + "' in " + key);
}

static string callid_get(const string &key, size_t pos, const sip_call_id_s *callid) {
	string id=subKey(key, &pos);
	if (id.empty()) return cstring_get(key, pos, callid->i_id);
	if (id == "hash") return int_get(key, pos, callid->i_hash);
	throw runtime_error("callid_get: unhandled arg '" + id + "' in " + key);
}

static bool is_request(sip_t *sip) {
	return sip_is_request((sip_header_t *)sip->sip_request);
}


std::string SipAttributes::get(const std::string &key) const {
		size_t pos=0;
		string id=subKey(key, &pos);
		
		if (id == "from") return addr_get(key, pos, (sip_addr_s *)sip->sip_from);
		if (id == "to") return addr_get(key, pos, (sip_addr_s *)sip->sip_to);
		if (id == "request") return request_get(key, pos, sip->sip_request);
		if (id == "direction") return is_request(sip) ? "request" : "response";
		if (id == "status") return status_get(key, pos, (sip_status_s *) sip->sip_status);
		if (id == "ua" || id == "user-agent") return ua_get(key, pos, sip->sip_user_agent);
		if (id == "callid" ) return callid_get(key, pos, sip->sip_call_id);
		
		throw runtime_error("unhandled arg '" + id + "' in '" + key+ "'");
	}
	
bool SipAttributes::isTrue(const string &key) const {
		if (key == "is_request") {
			return is_request(sip);
		} else if (key == "is_response") {
			return !is_request(sip);
		}
		throw runtime_error("unhandled true/false " + key);
};
