/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include <sofia-sip/nua.h>
#include <sofia-sip/sip_header.h>

#include "flexisip/logmanager.hh"
#include "flexisip/module.hh"

#include "uac-register.hh"

using namespace std;
using namespace flexisip;

UacRegister::UacRegister(const sip_from_t* ifrom, const sip_to_t* ito, int iexpire, nua_t* nua, nua_hmagic_t* userptr) {
	su_home_init(&home);

	nh = NULL;
	expire = iexpire;
	from = sip_from_dup(&home, ifrom);
	to = sip_to_dup(&home, ito);

	SLOGD << "Creating UacRegister " << this << " from " << from->a_url->url_user << "@" << from->a_url->url_host;
	nh = nua_handle(nua, userptr, SIPTAG_FROM(from), SIPTAG_TO(to), TAG_END());
	state = INITIAL;
	challengeReceived = false;
}

void UacRegister::send(const sip_contact_t *contact) {
	char expirechars[32];
	state = INITIAL;
	SLOGD << "Sending UacRegister " << this << " with refresh " << expire << "s";
	snprintf(expirechars, sizeof(expirechars), "%i", expire);
	// string expirestr = to_string((long long int)expire); //does not work with gcc-4.4.
	string expirestr = expirechars;
	string refreshtag = string("expires=") + expirestr;
	nua_register(nh, SIPTAG_CONTACT(contact), NUTAG_M_FEATURES(refreshtag.c_str()),
				 SIPTAG_EXPIRES_STR(expirestr.c_str()), TAG_END());
	challengeReceived = false;
}

UacRegister::~UacRegister() {
	if (nh)
		nua_handle_destroy(nh);
	su_home_deinit(&home);
	SLOGD << "Destroyed UacRegister " << this;
}

void UacRegister::authenticate(const msg_param_t *au_params) {
	if (challengeReceived) {
		SLOGD << "A second challenge was received.";
		state = ERROR;
		return;
	}
	challengeReceived = true;
	ostringstream digest;
	digest << "Digest:";

	const char *realm = msg_params_find(au_params, "realm=");
	if (realm[0] != '"')
		digest << "\"";
	digest << realm;
	if (realm[strlen(realm) - 1] != '"')
		digest << "\"";

	string user(from->a_url->url_user);

	digest << ":" << user << ":" << password;

	string digeststr(digest.str());
	// LOGD("GR authentication with %s", digeststr.c_str()); // expose password
	nua_authenticate(nh, NUTAG_AUTH(digeststr.c_str()), TAG_END());
}

void UacRegister::onMessage(const sip_t *sip) {
	switch (sip->sip_status->st_status) {
		case 200:
			LOGD("REGISTER done");
			state = REGISTERED;
			break;
		case 408:
			LOGD("REGISTER timeout");
			state = ERROR;
			break;
		case 401:
			LOGD("REGISTER challenged 401");
			authenticate(sip->sip_www_authenticate->au_params);
			break;
		case 407:
			LOGD("REGISTER challenged 407");
			authenticate(sip->sip_proxy_authenticate->au_params);
			break;
		default:
			LOGD("REGISTER not handled response: %i", sip->sip_status->st_status);
			state = ERROR;
			break;
	}
}
