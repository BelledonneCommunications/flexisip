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

#include <sofia-sip/msg_header.h>

#include <flexisip/common.hh>
#include <flexisip/logmanager.hh>

#include "nonce-store.hh"

using namespace std;
using namespace flexisip;

// ====================================================================================================================
//  NonceStore class
// ====================================================================================================================

int NonceStore::getNc(const string &nonce) {
	unique_lock<mutex> lck(mMutex);
	auto it = mNc.find(nonce);
	if (it != mNc.end())
		return (*it).second.nc;
	return -1;
}

void NonceStore::insert(msg_header_t *response) {
	const char *nonce = msg_header_find_param((msg_common_t const *)response, "nonce");
	string snonce(nonce);
	snonce = snonce.substr(1, snonce.length() - 2);
	LOGD("New nonce %s", snonce.c_str());
	insert(snonce);
}

void NonceStore::insert(const string &nonce) {
	unique_lock<mutex> lck(mMutex);
	time_t expiration = getCurrentTime() + mNonceExpires;
	auto it = mNc.find(nonce);
	if (it != mNc.end()) {
		LOGE("Replacing nonce count for %s", nonce.c_str());
		it->second.nc = 0;
		it->second.expires = expiration;
	} else {
		mNc.insert(make_pair(nonce, NonceCount(0, expiration)));
	}
}

void NonceStore::updateNc(const string &nonce, int newnc) {
	unique_lock<mutex> lck(mMutex);
	auto it = mNc.find(nonce);
	if (it != mNc.end()) {
		LOGD("Updating nonce %s with nc=%d", nonce.c_str(), newnc);
		(*it).second.nc = newnc;
	} else {
		LOGE("Couldn't update nonce %s: not found", nonce.c_str());
	}
}

void NonceStore::erase(const string &nonce) {
	unique_lock<mutex> lck(mMutex);
	LOGD("Erasing nonce %s", nonce.c_str());
	mNc.erase(nonce);
}

void NonceStore::cleanExpired() {
	unique_lock<mutex> lck(mMutex);
	int count = 0;
	time_t now = getCurrentTime();
	size_t size = 0;
	for (auto it = mNc.begin(); it != mNc.end();) {
		if (now > it->second.expires) {
			LOGD("Cleaning expired nonce %s", it->first.c_str());
			auto eraseIt = it;
			++it;
			mNc.erase(eraseIt);
			++count;
		} else
			++it;
		size++;
	}
	if (count)
		LOGD("Cleaned %d expired nonces, %zd remaining", count, size);
}

// ====================================================================================================================
