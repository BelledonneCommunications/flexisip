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

#pragma db model version(1, 3)

#pragma db object polymorphic table("EventLog")
class EventLogDb {
public:
	EventLogDb() {}
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
	RegistrationLogDb() {}
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
	CallLogDb() {}
private:
	friend class odb::access;
	bool cancelled;
};

#pragma db object table("MessageLog")
class MessageLogDb : public EventLogDb{
public:
	enum ReportType {Reception, Delivery};
	MessageLogDb(const std::shared_ptr<MessageLog> & mLog);
	MessageLogDb() {}
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
	AuthLogDb() {}
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
	CallQualityStatisticsLogDb() {}
private:
	friend class odb::access;

	#pragma db value
	struct reporting_addr {
		std::string id;
		std::string ip;
		int port;
		uint32_t ssrc;

		std::string group;
		std::string mac; // optional
	};

	#pragma db value
	struct reporting_content_metrics {
		reporting_content_metrics(){
			ts_start = ts_stop = 0;

			sd_payload_type = -1;
			sd_sample_rate = -1;
			sd_frame_duration = -1;
			sd_packet_loss_concealment = -1;

			pl_network_packet_loss_rate = -1;
			pl_jitter_buffer_discard_rate = -1;

			jb_adaptive = -1;
			jb_abs_max = -1;
			jb_nominal = jb_max = -1;

			pl_network_packet_loss_rate = pl_jitter_buffer_discard_rate = -1.f;

			d_end_system_delay = -1;
			d_interarrival_jitter = -1;
			d_round_trip_delay = d_mean_abs_jitter = -1;
			d_symm_one_way_delay = -1;

			s_level = 127;
			s_noise_level = 127;

			qe_moslq = -1.f;
			qe_moscq = -1.f;
		}
		// timestamps - mandatory
		time_t ts_start;
		time_t ts_stop;

		// session description - optional
		int sd_payload_type;
		std::string sd_payload_desc;
		int sd_sample_rate;
		int sd_frame_duration;
		std::string sd_fmtp;
		int sd_packet_loss_concealment;

		// jitter buffet - optional
		int jb_adaptive;
		int jb_nominal;
		int jb_max;
		int jb_abs_max;

		// packet loss - optional
		float pl_network_packet_loss_rate;
		float pl_jitter_buffer_discard_rate;

		// delay - optional
		int d_round_trip_delay;
		int d_end_system_delay;
		int d_symm_one_way_delay;
		int d_interarrival_jitter;
		int d_mean_abs_jitter;

		// signal - optional
		int s_level;
		int s_noise_level;

		// quality estimates - optional
		float qe_moslq;
		float qe_moscq;

		std::string user_agent;
	};

	std::string report_type; /*interval or session report*/
	bool call_term_report;
	std::string call_id;
	std::string orig_id;

	reporting_addr local_addr;
	reporting_addr remote_addr;

	reporting_content_metrics local_metrics;
	reporting_content_metrics remote_metrics; // optional

	std::string dialog_id; // optional

	// Quality of Service analyzer - custom extension
	/* This should allow us to analysis bad network conditions and quality adaptation*/
	std::string qos_name; /*type of the QoS analyzer used*/
	std::string qos_timestamp; /*time of each decision in seconds*/
	std::string qos_input_leg; /*input parameters' name*/
	std::string qos_input; /*set of inputs for each decision, semicolon separated*/
	std::string qos_output_leg; /*output parameters' name*/
	std::string qos_output; /*set of outputs for each decision, semicolon separated*/
};

#endif
