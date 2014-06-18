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

AuthLogDb::AuthLogDb(const std::shared_ptr<AuthLog> & aLog){
	date=aLog->mDate;
	userExists=aLog->mUserExists;
	method=aLog->mMethod;
	reason=aLog->mReason;
	statusCode=aLog->mStatusCode;
	completed=aLog->mCompleted;

	setFrom(aLog->mFrom);
	setTo(aLog->mTo);
	setOrigin(aLog->mOrigin);
	setUserAgent(aLog->mUA);
}

void AuthLogDb::setOrigin(const url_t *url){
	ostringstream msg;
	msg<<url;
	origin=msg.str();
}

CallQualityStatisticsLogDb::CallQualityStatisticsLogDb(const std::shared_ptr<CallQualityStatisticsLog> & csLog)
	: call_term_report(false), local_addr(), remote_addr(), local_metrics(), remote_metrics()
{
	std::stringstream iss(csLog->mReport);
	std::string token;
	std::string line;
	std::string section;
	reporting_content_metrics * current_metrics = &local_metrics;
	reporting_addr * current_addr = &local_addr;

	date=csLog->mDate;
	statusCode=csLog->mStatusCode;
	reason=csLog->mReason;
	completed=csLog->mCompleted;
	setFrom(csLog->mFrom);
	setTo(csLog->mTo);

	getline(iss, line);
	report_type=line.substr(0, line.find(':'));
	call_term_report=(line=="VQSessionReport: CallTerm\r");
	while (iss >> token){
		size_t colon_loc = token.find(':');
		size_t equal_loc = token.find('=');

		SLOGD << "CallQualityStatisticsLogDb: New token: " << token << " " << colon_loc << " " << equal_loc;

		/*special case when value is in inverted commas eg FMTP="useinbandfec=1; stereo=0; sprop-stereo=0":
		When first character is a quote, then we need to read the stream until the matching one is reached*/
		if (equal_loc != std::string::npos && token[equal_loc+1]=='\"'){
			string tmp;
			while (token[token.size()-1]!='\"'&&(iss >> tmp)){
				token += " " + tmp;
			}
			/*remove quotes*/
			token.erase(token.begin()+equal_loc+1);
			token.erase(token.end()-1);
		}

		if (token=="CallID:") getline(iss, call_id);
		if (token=="LocalID:") getline(iss, local_addr.id);
		if (token=="RemoteID:") getline(iss, remote_addr.id);
		if (token=="OrigID:") getline(iss, orig_id);
		if (token=="LocalGroup:") getline(iss, local_addr.group);
		if (token=="RemoteGroup:") getline(iss, remote_addr.group);
		if (token=="LocalMAC:") getline(iss, local_addr.mac);
		if (token=="RemoteMAC:") getline(iss, remote_addr.mac);
		if (token=="RemoteAddr:") current_addr = &remote_addr;
		if (token=="RemoteMetrics:") current_metrics = &remote_metrics;
		if (token=="DialogID:") getline(iss, dialog_id);

		/* avoid false positives colon contained in key/value pairs
		like START=2014-06-17T12:20:04Z. */
		if (colon_loc!=std::string::npos && equal_loc==std::string::npos){
			section=token.substr(0, colon_loc);
		}

		/*token is of the form some_key=some_value*/
		if (equal_loc != std::string::npos){
			std::string key = token.substr(0, equal_loc);
			std::string value = token.substr(equal_loc+1, std::string::npos);

			if (key=="IP") current_addr->ip = value;
			else if (key=="PORT") current_addr->port = atoi(value.c_str());
			else if (key=="SSRC") current_addr->ssrc =(unsigned int)atoi(value.c_str());
			else if (section=="Timestamps"){
				time_t * ts;
				if (key=="START") ts = &current_metrics->ts_start;
				else if (key=="STOP") ts = &current_metrics->ts_stop;

				/*convert RFC3336 string to GMT timestamps*/
				if (ts){
					struct tm tm;
					strptime(value.c_str(), "%Y-%m-%dT%H:%M:%SZ", &tm);
					*ts = mktime(&tm);
				}else{
					SLOGE << "CallQualityStatisticsLogDb: Unhandled key=" << key << " value="<<value<<" in section="<<section;
				}
			}
			else if (section=="SessionDesc"&&key=="PT") current_metrics->sd_payload_type = strtod(value.c_str(),NULL);
			else if (section=="SessionDesc"&&key=="PD") current_metrics->sd_payload_desc = value;
			else if (section=="SessionDesc"&&key=="SR") current_metrics->sd_sample_rate = strtod(value.c_str(),NULL);
			else if (section=="SessionDesc"&&key=="FD") current_metrics->sd_frame_duration = strtod(value.c_str(),NULL);
			else if (section=="SessionDesc"&&key=="FMTP") current_metrics->sd_fmtp = value;
			else if (section=="SessionDesc"&&key=="PLC") current_metrics->sd_packet_loss_concealment = strtod(value.c_str(),NULL);
			else if (section=="JitterBuffer"&&key=="JBA") current_metrics->jb_adaptive = strtod(value.c_str(),NULL);
			else if (section=="JitterBuffer"&&key=="JBN") current_metrics->jb_nominal = strtod(value.c_str(),NULL);
			else if (section=="JitterBuffer"&&key=="JBM") current_metrics->jb_max = strtod(value.c_str(),NULL);
			else if (section=="JitterBuffer"&&key=="JBX") current_metrics->jb_abs_max = strtod(value.c_str(),NULL);
			else if (section=="PacketLoss"&&key=="NLR") current_metrics->pl_network_packet_loss_rate = strtod(value.c_str(),NULL);
			else if (section=="PacketLoss"&&key=="JDR") current_metrics->pl_jitter_buffer_discard_rate = strtod(value.c_str(),NULL);
			else if (section=="Delay"&&key=="RTD") current_metrics->d_round_trip_delay = strtod(value.c_str(),NULL);
			else if (section=="Delay"&&key=="ESD") current_metrics->d_end_system_delay = strtod(value.c_str(),NULL);
			else if (section=="Delay"&&key=="IAJ") current_metrics->d_interarrival_jitter = strtod(value.c_str(),NULL);
			else if (section=="Delay"&&key=="MAJ") current_metrics->d_mean_abs_jitter = strtod(value.c_str(),NULL);
			else if (section=="Signal"&&key=="SL") current_metrics->s_level = strtod(value.c_str(),NULL);
			else if (section=="Signal"&&key=="NL") current_metrics->s_noise_level = strtod(value.c_str(),NULL);
			else if (section=="QualityEst"&&key=="MOSLQ") current_metrics->qe_moslq = strtod(value.c_str(),NULL);
			else if (section=="QualityEst"&&key=="MOSCQ") current_metrics->qe_moscq = strtod(value.c_str(),NULL);
			else if (section=="AdaptiveAlg"&&key=="NAME") qos_name = value;
			else if (section=="AdaptiveAlg"&&key=="TS") qos_timestamp = value;
			else if (section=="AdaptiveAlg"&&key=="IN_LEG") qos_input_leg = value;
			else if (section=="AdaptiveAlg"&&key=="IN") qos_input = value;
			else if (section=="AdaptiveAlg"&&key=="OUT_LEG") qos_output_leg = value;
			else if (section=="AdaptiveAlg"&&key=="OUT") qos_output = value;
			else SLOGE << "CallQualityStatisticsLogDb: Unhandled key="<<key<<" value="<<value<<" in section="<<section;
		}
	}
}
