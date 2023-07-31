/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "contact-inserter.hh"

#include <utility>

#include "registrar/extended-contact.hh"
#include "registrar/record.hh"
#include "registrar/registrar-db.hh"
#include "utils/test-patterns/test.hh"

namespace flexisip::tester {

ContactInserter::ContactInserter(RegistrarDb& regDb, std::shared_ptr<ContactInsertedListener>&& listener)
    : mRegDb(regDb), mListener(std::move(listener)), mGenerateUniqueId(false) {
	mParameters.callId = "placeholder-call-id";
}

ContactInserter& ContactInserter::insert(const ContactInsertArgs& args) {
	const std::string_view& contactUri = args.contact.empty() ? mAor.str() : args.contact;
	sofiasip::Home home{};
	const auto createContact = [&home, &contactUri, &paramsVec = mContactParams](auto&&... params) {
		return home.createContact(contactUri, paramsVec, params...);
	};
	std::string uniqueId{args.uniqueId};
	if (uniqueId.empty() && mGenerateUniqueId) uniqueId = "test-contact-" + std::to_string(mCount);
	if (!uniqueId.empty()) uniqueId = "+sip.instance=\"<" + uniqueId + ">\"";
	const auto sipContact = uniqueId.empty() ? createContact() : createContact(uniqueId);
	BC_HARD_ASSERT(sipContact != nullptr);
	mListener->contactsToBeInserted.insert(ExtendedContact::urlToString(sipContact->m_url));
	mRegDb.bind(mAor, sipContact, mParameters, mListener);
	mCount++;
	return *this;
}

void ContactInsertedListener::onRecordFound(const std::shared_ptr<Record>& r) {
	for (const auto& contact : r->getExtendedContacts()) {
		contactsToBeInserted.erase(contact->urlAsString());
	}
}

} // namespace flexisip::tester
