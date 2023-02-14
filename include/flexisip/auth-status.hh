/*
 * Flexisip, a flexible SIP proxy server with media capabilities.
 * Copyright (C) 2018  Belledonne Communications SARL, All rights reserved.
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

#include <functional>
#include <string>

#include <sofia-sip/auth_module.h>

namespace flexisip {

/**
 * @brief Plain C++ wrapper for SofiaSip's auth_status_t structure.
 * @warning Like auth_status_t, this classe doesn't take ownership
 * on strings that have been set by setters. That means you must
 * guarantees the life of such strings while the authentication is processing.
 * If you cannot, you may copy the string by using the AuthStatus' internal
 * home_t object before giving it to the setter method. This one can be
 * got thanks to home() method.
 * @see See http://sofia-sip.sourceforge.net/refdocs/iptsec/structauth__status__t.html
 * for more documentation.
 */
class AuthStatus {
public:
	using ResponseCb = std::function<void(AuthStatus &as)>;

	AuthStatus() {
		su_home_init(&mHome);
		mPriv = auth_status_new(&mHome);
		mPriv->as_plugin = reinterpret_cast<auth_splugin_t *>(this);
		mPriv->as_callback = responseCb;
	}
	AuthStatus(const AuthStatus &other) = delete;
	virtual ~AuthStatus() {su_home_deinit(&mHome);}

	bool allow() const {return mPriv->as_allow;}
	void allow(bool val) {mPriv->as_allow = val;}

	bool anonymous() const {return mPriv->as_anonymous;}
	void anonymous(bool val) {mPriv->as_anonymous = val;}

	const void *body() const {return mPriv->as_body;}
	void body(const void *val) {mPriv->as_body = val;}

	isize_t bodyLen() const {return mPriv->as_bodylen;}
	void bodyLen(isize_t val) {mPriv->as_bodylen = val;}

	bool blacklist() const {return mPriv->as_blacklist;}
	void blacklist(bool val) {mPriv->as_blacklist = val;}

	const ResponseCb &callback() const {return mResponseCb;}
	void callback(const ResponseCb &cb) {mResponseCb = cb;}

	const char *display() const {return mPriv->as_display;}
	void display(const char *val) {mPriv->as_display = val;}

	/**
	 * Internal home_t, which will be destroyed on destruction
	 * of the AuthStatus.
	 */
	su_home_t *home() {return mPriv->as_home;}

	msg_header_t *info() const {return mPriv->as_info;}
	void info(msg_header_t *val) {mPriv->as_info = val;}

	auth_magic_t *magic() const {return mPriv->as_magic;}
	void magic(auth_magic_t *val) {mPriv->as_magic = val;}

	msg_header_t *match() const {return mPriv->as_match;}
	void match(msg_header_t *val) {mPriv->as_match = val;}

	const char *method() const {return mPriv->as_method;}
	void method(const char *val) {mPriv->as_method = val;}

	msg_time_t nonceIssued() const {return mPriv->as_nonce_issued;}
	void nonceIssued(msg_time_t val) {mPriv->as_nonce_issued = val;}

	const char *phrase() const {return mPriv->as_phrase;}
	void phrase(const char *val) {mPriv->as_phrase = val;}

	const char *realm() const {return mPriv->as_realm;}
	void realm(const char *val) {mPriv->as_realm = val;}
	void realm(const std::string &val) {mPriv->as_realm = su_strdup(&mHome, val.c_str());}

	msg_header_t *response() const {return mPriv->as_response;}
	void response(msg_header_t *val) {mPriv->as_response = val;}

	su_addrinfo_t  *source() const {return mPriv->as_source;}
	void source(su_addrinfo_t  *val) {mPriv->as_source = val;}

	bool stale() const {return mPriv->as_stale;}
	void stale(bool val) {mPriv->as_stale = val;}

	int status() const {return mPriv->as_status;}
	void status(int val) {mPriv->as_status = val;}

	const char *user() const {return mPriv->as_user;}
	void user(const char *val) {mPriv->as_user = val;}

	const url_t *userUri() const {return mPriv->as_user_uri;}
	void userUri(const url_t *val) {mPriv->as_user_uri = val;}

	/**
	 * Return the underlying SofiaSip's auth_status_t object.
	 */
	auth_status_t *getPtr() {return mPriv;}

private:
	static void responseCb([[maybe_unused]] auth_magic_t *magic, auth_status_t *as) {
		AuthStatus &authStatus = *reinterpret_cast<AuthStatus *>(as->as_plugin);
		if (authStatus.mResponseCb) authStatus.mResponseCb(authStatus);
	}

	su_home_t mHome;
	auth_status_t *mPriv = nullptr;
	ResponseCb mResponseCb;
};

}
