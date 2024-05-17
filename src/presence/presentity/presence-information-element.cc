/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023 Belledonne Communications SARL, All rights reserved.

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

#include "presence-information-element.hh"

#include <memory>

#include <ostream>

#include "flexisip/flexisip-exception.hh"
#include <belle-sip/belle-sip.h>

#include "flexisip/logmanager.hh"
#include "xml/data-model.hh"
#include "xml/pidf+xml.hh"
#include "xml/rpid.hh"

using namespace std;
using namespace std::chrono;

namespace flexisip {

PresenceInformationElement::PresenceInformationElement(Xsd::Pidf::Presence::TupleSequence* tuples,
                                                       Xsd::DataModel::Person* person,
                                                       const std::weak_ptr<StatPair>& countPresenceElement)
    : mCountPresenceElement(countPresenceElement) {
	SLOGD << "Presence information element [" << this << "] created.";
	for (auto tupleIt = tuples->begin(); tupleIt != tuples->end();) {
		SLOGT << "Adding tuple id [" << tupleIt->getId() << "] to presence info element [" << this << "]";
		unique_ptr<Xsd::Pidf::Tuple> r;
		tupleIt = tuples->detach(tupleIt, r);
		mTuples.push_back(unique_ptr<Xsd::Pidf::Tuple>(r.release()));
	}
	if (person) {
		for (const auto& activity : person->getActivities()) {
			mPerson.getActivities().push_back(activity);
		}
		mPerson.setTimestamp(person->getTimestamp());
	}

	if (auto sharedCounter = mCountPresenceElement.lock()) {
		sharedCounter->incrStart();
	} else {
		SLOGE << "PresenceInformationElement [" << this << "] - weak_ptr mCountPresenceElement should be present here.";
	}
}

PresenceInformationElement::PresenceInformationElement(const belle_sip_uri_t* contact,
                                                       const std::weak_ptr<StatPair>& countPresenceElement)
    : mCountPresenceElement(countPresenceElement) {
	SLOGD << "Presence information element [" << this << "] created as default element.";
	char* contact_as_string = belle_sip_uri_to_string(contact);
	time_t t;
	time(&t);
	struct tm* now = gmtime(&t);
	Xsd::Pidf::Status status;
	status.setBasic(Xsd::Pidf::Basic("open"));
	auto tup = std::make_unique<Xsd::Pidf::Tuple>(status, string(generatePresenceId()));
	tup->setTimestamp(Xsd::XmlSchema::DateTime(now->tm_year + 1900, now->tm_mon + 1, now->tm_mday, now->tm_hour,
	                                           now->tm_min, now->tm_sec));
	tup->setContact(Xsd::Pidf::Contact(contact_as_string));
	mTuples.clear(); // just in case
	mTuples.push_back(unique_ptr<Xsd::Pidf::Tuple>(tup.release()));
	auto act = Xsd::Rpid::Activities();
	act.getAway().push_back(Xsd::Rpid::Empty());
	mPerson.setId(generatePresenceId());
	mPerson.getActivities().push_back(act);
	belle_sip_free(contact_as_string);

	if (auto sharedCounter = mCountPresenceElement.lock()) {
		sharedCounter->incrStart();
	} else {
		SLOGE << "PresenceInformationElement [" << this << "] - weak_ptr mCountPresenceElement should be present here.";
	}
}

PresenceInformationElement::~PresenceInformationElement() {
	if (auto sharedCounter = mCountPresenceElement.lock()) {
		sharedCounter->incrFinish();
	} else {
		SLOGE << "PresenceInformationElement [" << this << "] - weak_ptr mCountPresenceElement should be present here.";
	}
	SLOGD << "Presence information element [" << this << "] deleted";
}

void PresenceInformationElement::clearTuples() {
	mTuples.clear();
}

const unique_ptr<Xsd::Pidf::Tuple>& PresenceInformationElement::getTuple(const string& id) const {
	for (const unique_ptr<Xsd::Pidf::Tuple>& tup : mTuples) {
		if (tup->getId() == id) return tup;
	}
	throw FLEXISIP_EXCEPTION << "No tuple found for id [" << id << "]";
}
const list<unique_ptr<Xsd::Pidf::Tuple>>& PresenceInformationElement::getTuples() const {
	return mTuples;
}
const Xsd::DataModel::Person PresenceInformationElement::getPerson() const {
	return mPerson;
}
const string& PresenceInformationElement::getEtag() {
	return mEtag;
}
void PresenceInformationElement::setEtag(const string& eTag) {
	mEtag = eTag;
}

std::string PresenceInformationElement::generatePresenceId() {
	// code from linphone
	// TODO code is now different, should it be updated ?
	/*defined in http://www.w3.org/TR/REC-xml/*/
	static char presence_id_valid_characters[] = "0123456789abcdefghijklmnopqrstuvwxyz-.";
	/*NameStartChar (NameChar)**/
	static char presence_id_valid_start_characters[] = "_abcdefghijklmnopqrstuvwxyz";
	char id[7];
	int i;
	id[0] = presence_id_valid_start_characters[belle_sip_random() % (sizeof(presence_id_valid_start_characters) - 1)];
	for (i = 1; i < 6; i++) {
		id[i] = presence_id_valid_characters[belle_sip_random() % (sizeof(presence_id_valid_characters) - 1)];
	}
	id[6] = '\0';

	return id;
}

} /* namespace flexisip */
