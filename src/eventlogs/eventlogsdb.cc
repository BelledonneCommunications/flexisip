/*
	Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010  Belledonne Communications SARL.

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

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#include "eventlogsdb.hh"

#include <iostream>
#include <iomanip>
#include <sstream>
#include <typeinfo>

using namespace ::std;
using namespace odb::core;

inline ostream & operator<<(ostream & ostr, const sip_user_agent_t *ua){
	char tmp[500]={0};
	sip_user_agent_e(tmp,sizeof(tmp)-1,(msg_header_t*)ua,0);
	ostr<<tmp;
	return ostr;
}

inline ostream & operator<<(ostream & ostr, const url_t *url){
	char tmp[500]={0};
	url_e(tmp,sizeof(tmp)-1,url);
	ostr<<tmp;
	return ostr;
}

inline ostream & operator<<(ostream & ostr, const sip_from_t *from){
	if (from->a_display && *from->a_display!='\0') ostr<<from->a_display;
	ostr<<from->a_url;
	return ostr;
}

inline ostream & operator<<(ostream & ostr, const sip_contact_t *contact){
	if (contact && contact->m_url) ostr<<contact->m_url;
	return ostr;
}

EventLogDb::~EventLogDb(){
}

void EventLogDb::setFrom(const sip_from_t *sFrom){
	ostringstream msg;
	msg<<sFrom;
	from=msg.str();
}

void EventLogDb::setTo(const sip_to_t *sTo){
	ostringstream msg;
	msg<<sTo;
	to=msg.str();
}

void EventLogDb::setUserAgent(const sip_user_agent_t *ag){
	ostringstream msg;
	msg<<ag;
	userAgent=msg.str();
}

RegistrationLogDb::RegistrationLogDb(const std::shared_ptr<RegistrationLog> & rLog){
	date=rLog->mDate;
	instanceId=rLog->mInstanceId;
	type=(RegistrationLogDb::Type) rLog->mType;
	statusCode=rLog->mStatusCode;
	completed=rLog->mCompleted;

	setFrom(rLog->mFrom);
	setContacts(rLog->mContacts);
	setUserAgent(rLog->mUA);
}

void RegistrationLogDb::setContacts(const sip_contact_t *sContacts){
	ostringstream msg;
	msg<<sContacts;
	contacts=msg.str();
}

CallLogDb::CallLogDb(const std::shared_ptr<CallLog> & cLog){
	statusCode=cLog->mStatusCode;
	date=cLog->mDate;
	reason=cLog->mReason;
	cancelled=cLog->mCancelled;
	completed=cLog->mCompleted;

	setFrom(cLog->mFrom);
	setTo(cLog->mTo);
}

MessageLogDb::MessageLogDb (const std::shared_ptr<MessageLog> & mLog) {
	mId=mLog->mId;
	date=mLog->mDate;
	reason=mLog->mReason;
	statusCode=mLog->mStatusCode;
	reportType=(MessageLogDb::ReportType) mLog->mReportType;
	completed=mLog->mCompleted;

	setFrom(mLog->mFrom);
	setTo(mLog->mTo);
	setDestination(mLog->mUri);
}

void MessageLogDb::setDestination(const url_t *url){
	ostringstream msg;
	msg<<url;
	uri=msg.str();
}

CallQualityStatisticsLogDb::CallQualityStatisticsLogDb(const std::shared_ptr<CallQualityStatisticsLog> & csLog){
	date=csLog->mDate;
	statusCode=csLog->mStatusCode;
	reason=csLog->mReason;
	report=csLog->mReport;
	completed=csLog->mCompleted;

	setFrom(csLog->mFrom);
	setTo(csLog->mTo);
}

AuthLogDb::AuthLogDb(const std::shared_ptr<AuthLog> & aLog){
	userExists=aLog->mUserExists;
	date=aLog->mDate;
	method=aLog->mMethod;
	reason=aLog->mReason;
	statusCode=aLog->mStatusCode;
	completed=aLog->mCompleted;

	setFrom(aLog->mFrom);
	setTo(aLog->mTo);
	setOrigin(aLog->mOrigin);
}

void AuthLogDb::setOrigin(const url_t *url){
	ostringstream msg;
	msg<<url;
	origin=msg.str();
}
