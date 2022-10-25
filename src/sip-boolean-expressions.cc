/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include "sofia-sip/sip.h"

#include "flexisip/expressionparser-impl.cc"
#include "flexisip/sip-boolean-expressions.hh"

using namespace std;

namespace flexisip {

shared_ptr<SipBooleanExpressionBuilder> SipBooleanExpressionBuilder::sInstance;

static inline string stringFromC(const char* s) {
	return s ? string(s) : string();
}

static ExpressionRules<sip_t> rules = {
    {
        {"direction", [](const sip_t& sip) -> string { return sip.sip_request != nullptr ? "request" : "response"; }},

        {"request.method-name",
         [](const sip_t& sip) -> string {
	         return stringFromC((sip.sip_request && sip.sip_request->rq_method_name) ? sip.sip_request->rq_method_name
	                                                                                 : nullptr);
         }},
        {"request.method",
         [](const sip_t& sip) -> string {
	         return stringFromC((sip.sip_request && sip.sip_request->rq_method_name) ? sip.sip_request->rq_method_name
	                                                                                 : nullptr);
         }},
        {"request.uri.domain",
         [](const sip_t& sip) -> string {
	         return stringFromC(sip.sip_request ? sip.sip_request->rq_url->url_host : nullptr);
         }},
        {"request.uri.user",
         [](const sip_t& sip) -> string {
	         return stringFromC(sip.sip_request ? sip.sip_request->rq_url->url_user : nullptr);
         }},
        {"request.uri.params",
         [](const sip_t& sip) -> string {
	         return stringFromC(sip.sip_request ? sip.sip_request->rq_url->url_params : nullptr);
         }},

        {"from.uri.domain",
         [](const sip_t& sip) -> string {
	         return stringFromC(sip.sip_from ? sip.sip_from->a_url->url_host : nullptr);
         }},
        {"from.uri.user",
         [](const sip_t& sip) -> string {
	         return stringFromC(sip.sip_from ? sip.sip_from->a_url->url_user : nullptr);
         }},
        {"from.uri.params",
         [](const sip_t& sip) -> string {
	         return stringFromC(sip.sip_from ? sip.sip_from->a_url->url_params : nullptr);
         }},

        {"to.uri.domain",
         [](const sip_t& sip) -> string { return stringFromC(sip.sip_to ? sip.sip_to->a_url->url_host : nullptr); }},
        {"to.uri.user",
         [](const sip_t& sip) -> string { return stringFromC(sip.sip_to ? sip.sip_to->a_url->url_user : nullptr); }},
        {"to.uri.params",
         [](const sip_t& sip) -> string { return stringFromC(sip.sip_to ? sip.sip_to->a_url->url_params : nullptr); }},

        {"contact.uri.domain",
         [](const sip_t& sip) -> string {
	         return stringFromC(sip.sip_contact ? sip.sip_contact->m_url->url_host : nullptr);
         }},
        {"contact.uri.user",
         [](const sip_t& sip) -> string {
	         return stringFromC(sip.sip_contact ? sip.sip_contact->m_url->url_user : nullptr);
         }},
        {"contact.uri.params",
         [](const sip_t& sip) -> string {
	         return stringFromC(sip.sip_contact ? sip.sip_contact->m_url->url_params : nullptr);
         }},

        {"user-agent",
         [](const sip_t& sip) -> string {
	         return stringFromC(sip.sip_user_agent ? sip.sip_user_agent->g_string : nullptr);
         }},

        {"call-id",
         [](const sip_t& sip) -> string { return stringFromC(sip.sip_call_id ? sip.sip_call_id->i_id : nullptr); }},
        {"call-id.hash",
         [](const sip_t& sip) -> string {
	         ostringstream ostr;
	         if (sip.sip_call_id) ostr << sip.sip_call_id->i_hash;
	         return ostr.str();
         }},

        {"status.phrase",
         [](const sip_t& sip) -> string { return stringFromC(sip.sip_status ? sip.sip_status->st_phrase : nullptr); }},
        {"status.code",
         [](const sip_t& sip) -> string {
	         ostringstream ostr;
	         if (sip.sip_status) ostr << sip.sip_status->st_status;
	         return ostr.str();
         }},

        {"content-type",
         [](const sip_t& sip) -> string {
	         return stringFromC(sip.sip_content_type ? sip.sip_content_type->c_type : nullptr);
         }},
    },
    {
        {"is_request", [](const sip_t& sip) -> bool { return sip.sip_request != nullptr; }},
        {"is_response", [](const sip_t& sip) -> bool { return sip.sip_request == nullptr; }},
    },
};

SipBooleanExpressionBuilder::SipBooleanExpressionBuilder() : BooleanExpressionBuilder<sip_t>(rules) {
}

SipBooleanExpressionBuilder& SipBooleanExpressionBuilder::get() {
	if (!sInstance) {
		sInstance = shared_ptr<SipBooleanExpressionBuilder>(new SipBooleanExpressionBuilder());
	}
	return *sInstance;
}

shared_ptr<SipBooleanExpression> SipBooleanExpressionBuilder::parse(const string& expression) {
	return BooleanExpressionBuilder<sip_t>::parse(expression);
}

} // namespace flexisip
