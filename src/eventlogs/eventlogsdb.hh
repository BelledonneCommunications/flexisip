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

#ifndef eventlogsdb_hh
#define eventlogsdb_hh

#include <string>
#include <memory>

#include <odb/core.hxx>

#include "eventlogs.hh"

#pragma db model version(1, 1)

#pragma db object polymorphic table("EventLog")
class EventLogDb {
public:
	EventLogDb() {};
	virtual ~EventLogDb();
	void setFrom(const sip_from_t *from);
	void setTo(const sip_to_t *to);
	void setUserAgent(const sip_user_agent_t *ag);
	void setDate(time_t t);
protected:
	friend class odb::access;
	std::string from;
	std::string to;
	std::string userAgent;
	time_t date;
	int statusCode;
	std::string reason;
	bool completed;
	#pragma db id auto
	unsigned long id_;
};

#pragma db object table("RegistrationLog")
class RegistrationLogDb : public EventLogDb{
public:
	enum Type {Register, Unregister, Expired};
	RegistrationLogDb(const std::shared_ptr<RegistrationLog> & rLog);
	RegistrationLogDb() {};
	void setContacts(const sip_contact_t *contacts);
private:
	friend class odb::access;
	Type type;
	std::string contacts;
	std::string instanceId;
};

#pragma db object table("CallLog")
class CallLogDb : public EventLogDb{
public:
	CallLogDb(const std::shared_ptr<CallLog> & cLog);
	CallLogDb() {};
private:
	friend class odb::access;
	bool cancelled;
};

#pragma db object table("MessageLog")
class MessageLogDb : public EventLogDb{
public:
	enum ReportType {Reception, Delivery};
	MessageLogDb(const std::shared_ptr<MessageLog> & mLog);
	MessageLogDb() {};
	void setDestination(const url_t *url);
private:
	friend class odb::access;
	ReportType reportType;
	std::string uri;
	unsigned long mId;
};

#pragma db object table("AuthLog")
class AuthLogDb : public EventLogDb{
public:
	AuthLogDb(const std::shared_ptr<AuthLog> & aLog);
	AuthLogDb() {};
	void setOrigin(const url_t *url);
private:
	friend class odb::access;
	std::string origin;
	std::string method;
	bool userExists;
};

#pragma db object table("CallQualityStatisticsLog")
class CallQualityStatisticsLogDb : public EventLogDb{
public:
	CallQualityStatisticsLogDb(const std::shared_ptr<CallQualityStatisticsLog> & csLog);
	CallQualityStatisticsLogDb() {};
private:
	friend class odb::access;
	std::string report;
};

#endif
