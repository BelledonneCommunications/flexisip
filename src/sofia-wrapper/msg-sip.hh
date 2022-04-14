/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL.

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

#pragma once

#include <ostream>
#include <string>

#include <sofia-sip/msg_types.h>
#include <sofia-sip/sip_protos.h>
#include <sofia-sip/su_alloc.h>

namespace sofiasip {

class MsgSip {
public:
	MsgSip() : mMsg{msg_create(sip_default_mclass(), 0)} {
	}
	/**
	 * Construct a MsgSip providing a sofia-sip msg_t.
	 * If transferOwnership is true, the msg_t is directly taken without taking a ref,
	 * in other words the caller transfers the reference it owns to the MsgSip object.
	 */
	MsgSip(msg_t* msg, bool transferOwnership = false) {
		if (!transferOwnership) assignMsg(msg);
		else mMsg = msg;
	}
	MsgSip(const MsgSip& msgSip);
	/**
	* Construct a MsgSip parsing the string parameter.
	*
	* @throw Throw std::runtime_error if a parsing error occurred.
	*/
	MsgSip(int flags, const std::string& msg);
	~MsgSip() noexcept {
		msg_unref(mMsg);
	}

	msg_t* getMsg() const {
		return mMsg;
	}
	sip_t* getSip() const {
		return (sip_t*)msg_object(mMsg);
	}
	su_home_t* getHome() const {
		return msg_home(mMsg);
	}

	msg_header_t* findHeader(const std::string& name, bool searchUnknowns = false);
	const msg_header_t* findHeader(const std::string& name) const {
		return const_cast<MsgSip*>(this)->findHeader(name);
	}

	void serialize() const {
		msg_serialize(mMsg, (msg_pub_t*)getSip());
	}
	const char* print() const;
	std::string printString() const;
	std::string printContext() const;

	bool isGroupChatInvite() const noexcept;

private:
	// Private methods
	void assignMsg(msg_t* msg) {
		mMsg = msg_ref_create(msg);
	}

	// Private attributes
	msg_t* mMsg{nullptr};
};

inline std::ostream& operator<<(std::ostream& strm, const sofiasip::MsgSip& obj) {
	// Here we hack out the constness.
	// The print method is non const as it will modify the underlying msg_t
	// during serialization. Moreover, the underlying sofia calls also take
	// a non const sip_t...
	auto& hack = const_cast<sofiasip::MsgSip&>(obj);
	strm << hack.print();
	return strm;
}

}; // namespace sofiasip
