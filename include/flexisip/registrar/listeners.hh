/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <memory>
#include <vector>

#include <flexisip/configmanager.hh>

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
	// Internal error, translated to a 500 response by the registrar module
	virtual void onError() = 0;
	// Replayed CSeq, translated to a 400 (Invalid) response by the registrar module
	virtual void onInvalid() = 0;
};

class RegistrarDbStateListener {
public:
	virtual void onRegistrarDbWritable(bool writable) = 0;
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

} // namespace flexisip
