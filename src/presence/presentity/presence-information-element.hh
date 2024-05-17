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

#pragma once

#include <list>

#include <belle-sip/belle-sip.h>

#include "flexisip/configmanager.hh"

#include "presence/belle-sip-using.hh"
#include "xml/pidf+xml.hh"

namespace flexisip {

class PresenceInformationElement {
public:
	/* Re-definition of BelleSipSourcePtr in order to use BelleSipSourceCancelingDeleter as deleter */
	using BelleSipSourcePtr = std::unique_ptr<belle_sip_source_t, BelleSipSourceCancelingDeleter>;

	PresenceInformationElement(Xsd::Pidf::Presence::TupleSequence* tuples,
	                           Xsd::DataModel::Person* person,
	                           const std::weak_ptr<StatPair>& countPresenceElement);
	template <typename T>
	PresenceInformationElement(Xsd::Pidf::Presence::TupleSequence* tuples,
	                           Xsd::DataModel::Person* person,
	                           const std::string& eTag,
	                           T&& timer,
	                           const std::weak_ptr<StatPair>& countPresenceElement)
	    : PresenceInformationElement(tuples, person, countPresenceElement) {
		setEtag(eTag);
		setExpiresTimer(std::move(timer));
	};
	// create an information element with a default tuple set to open.
	explicit PresenceInformationElement(const belle_sip_uri_t* contact,
	                                    const std::weak_ptr<StatPair>& countPresenceElement);
	~PresenceInformationElement();

	template <typename T>
	void setExpiresTimer(T&& timer) {
		mTimer = std::forward<T>(timer);
	}

	const std::unique_ptr<Xsd::Pidf::Tuple>& getTuple(const std::string& id) const;
	const std::list<std::unique_ptr<Xsd::Pidf::Tuple>>& getTuples() const;
	const Xsd::DataModel::Person getPerson() const;
	void clearTuples();
	const std::string& getEtag();
	void setEtag(const std::string& eTag);

private:
	static std::string generatePresenceId();

	const std::weak_ptr<StatPair> mCountPresenceElement;
	std::list<std::unique_ptr<Xsd::Pidf::Tuple>> mTuples;
	Xsd::DataModel::Person mPerson{""};
	BelleSipSourcePtr mTimer;
	std::string mEtag;
};

} /* namespace flexisip */
