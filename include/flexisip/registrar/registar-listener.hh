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

#pragma once

#include <memory>

#include "flexisip/configmanager.hh"

namespace flexisip {

class Record;
struct ExtendedContact;

/**
 * @brief Interface for RegistrarDB listeners.
 */
class RegistrarDbListener : public StatFinishListener {
public:
	virtual ~RegistrarDbListener();

	/**
	 * @brief Method called when searching for
	 * a record matching a given SIP identity is completed.
	 * @param[in] r The found record or nullptr if no record
	 * could be found. If not null, the ownership on the object
	 * is held by the implementation and the object might be
	 * destroyed immediately after onRecordFound() has returned.
	 */
	virtual void onRecordFound(const std::shared_ptr<Record>& r) = 0;
	virtual void onError() = 0;
	virtual void onInvalid() = 0;
};

class ContactUpdateListener : public RegistrarDbListener {
public:
	virtual ~ContactUpdateListener();
	virtual void onContactUpdated(const std::shared_ptr<ExtendedContact>& ec) = 0;
};

class ListContactUpdateListener {
public:
	virtual ~ListContactUpdateListener() = default;
	virtual void onContactsUpdated() = 0;

	std::vector<std::shared_ptr<Record>> records;
};

class ContactRegisteredListener {
public:
	virtual ~ContactRegisteredListener();
	virtual void onContactRegistered(const std::shared_ptr<Record>& r, const std::string& uid) = 0;
};

class LocalRegExpireListener {
public:
	virtual ~LocalRegExpireListener();
	virtual void onLocalRegExpireUpdated(unsigned int count) = 0;
};

class RegistrarDbStateListener {
public:
	virtual void onRegistrarDbWritable(bool writable) = 0;
};

} // namespace flexisip
