/*
 * Flexisip, a flexible SIP proxy server with media capabilities.
 * Copyright (C) 2013  Belledonne Communications SARL.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include <string>
#include <sofia-sip/su_alloc.h>
#include <sofia-sip/msg.h>
#include <sofia-sip/sip.h>
#include <sofia-sip/nua.h>

namespace flexisip {

class Agent;

struct UacRegister {
	enum State { INITIAL, REGISTERED, ERROR } state;
	bool challengeReceived;
	su_home_t home;
	nua_handle_t *nh;

	sip_from_t *from;
	sip_to_t *to;

	int expire;
	std::string password;

	UacRegister(const sip_from_t *from, const sip_to_t *to, int expire, nua_t *nua, nua_hmagic_t *userptr);
	~UacRegister();
	void onMessage(const sip_t *sip);

	void send(const sip_contact_t *contact);

  private:
	void authenticate(const msg_param_t *au_params);
};

}