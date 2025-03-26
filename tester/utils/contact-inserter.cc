/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2025 Belledonne Communications SARL, All rights reserved.

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

#include "contact-inserter.hh"

#include <utility>

#include "registrar/extended-contact.hh"
#include "registrar/record.hh"
#include "registrar/registrar-db.hh"
#include "utils/test-patterns/test.hh"
#include "utils/uri-utils.hh"

using namespace std;

namespace flexisip::tester {

ContactInserter::ContactInserter(RegistrarDb& regDb, shared_ptr<ContactInsertedListener>&& listener)
    : mRegDb(regDb), mListener(std::move(listener)), mGenerateUniqueId(false) {
	mParameters.callId = "placeholder-call-id";
}

ContactInserter& ContactInserter::insert(const ContactInsertArgs& args) {
	const string_view& contactUri = args.contact.empty() ? mAor.str() : args.contact;
	sofiasip::Home home{};
	const auto createContact = [&home, &contactUri, &paramsVec = mContactParams](auto&&... params) {
		return home.createContact(contactUri, paramsVec, params...);
	};
	string uniqueId{args.uniqueId};
	if (uniqueId.empty() && mGenerateUniqueId) uniqueId = "test-contact-" + to_string(mCount);
	if (!uniqueId.empty()) uniqueId = "+sip.instance=" + UriUtils::grToUniqueId(uniqueId);
	const auto sipContact = uniqueId.empty() ? createContact() : createContact(uniqueId);
	BC_HARD_ASSERT(sipContact != nullptr);
	mListener->contactsToBeInserted.insert(ExtendedContact::urlToString(sipContact->m_url));
	mRegDb.bind(mAor, sipContact, mParameters, mListener);
	mCount++;
	return *this;
}

void ContactInsertedListener::onRecordFound(const shared_ptr<Record>& r) {
	for (const auto& contact : r->getExtendedContacts()) {
		contactsToBeInserted.erase(contact->urlAsString());
	}
}

} // namespace flexisip::tester