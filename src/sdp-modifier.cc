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

#include "sdp-modifier.hh"

#include <sofia-sip/sip_protos.h>
#include <sstream>

using namespace ::std;

SdpModifier *SdpModifier::createFromSipMsg(su_home_t *home, sip_t *sip){
	if (!sip->sip_payload || !sip->sip_payload->pl_data) return NULL;
	SdpModifier *sm=new SdpModifier(home);
	if (!sm->initFromSipMsg(sip)) {
		delete sm;
		sm=NULL;
	}
	return sm;
}

bool SdpModifier::hasSdp(const sip_t *sip){
	sip_payload_t *payload=sip->sip_payload;
	if (payload==NULL || payload->pl_data==NULL) {
		return false;
	}
	return true;
}

bool SdpModifier::initFromSipMsg(sip_t *sip){
	sip_payload_t *payload=sip->sip_payload;
	if (payload==NULL || payload->pl_data==NULL) {
		LOGE("SIP message has no payload");
		return false;
	}
	mParser = sdp_parse(mHome, payload->pl_data, payload->pl_len, 0);
	mSession=sdp_session(mParser);
	if (mSession==NULL) {
		LOGE("SDP parsing error: %s",sdp_parsing_error(mParser));
		return false;
	}
	if (mSession->sdp_media==NULL){
		LOGE("SDP with no mline.");
		return false;
	}
	mSip=sip;
	return true;
}

SdpModifier::SdpModifier(su_home_t *home){
	mParser=NULL;
	mSip=NULL;
	mHome=home;
	mSession=NULL;
}

SdpModifier::~SdpModifier(){
	if (mParser) sdp_parser_free(mParser);
}

/*
static sdp_list_t *sdp_list_append(su_home_t *home, sdp_list_t *l, char *text){
	sdp_list_t *elem=(sdp_list_t*)su_zalloc(home,sizeof(sdp_list_t));
	sdp_list_t *begin=l;
	elem->l_size=sizeof(sdp_list_t);
	elem->l_text=text;
	if (l==NULL) return elem;
	while(l->l_next!=NULL) l=l->l_next;
	l->l_next=elem;
	return begin;
}
*/

static PayloadType *payload_type_make_from_sdp_rtpmap(sdp_rtpmap_t *rtpmap){
	if (rtpmap->rm_rate == 0 || rtpmap->rm_encoding == NULL) {
		LOGE("Bad media description for payload type : %i", rtpmap->rm_pt);
		return NULL;
	}
	PayloadType *pt=payload_type_new();
	pt->type=PAYLOAD_AUDIO_PACKETIZED;
	pt->mime_type=ms_strdup(rtpmap->rm_encoding);
	pt->clock_rate=rtpmap->rm_rate;
	payload_type_set_number(pt,rtpmap->rm_pt);
	payload_type_set_send_fmtp(pt,rtpmap->rm_fmtp);
	return pt;
}

static sdp_rtpmap_t *sdp_rtpmap_make_from_payload_type(su_home_t *home, PayloadType *pt, int number){
	sdp_rtpmap_t *map=(sdp_rtpmap_t*)su_zalloc(home,sizeof(sdp_rtpmap_t));
	map->rm_size=sizeof(sdp_rtpmap_t);
	map->rm_encoding=su_strdup(home,pt->mime_type);
	map->rm_rate=pt->clock_rate;
	map->rm_pt=number;
	map->rm_fmtp=su_strdup(home,pt->recv_fmtp);
	return map;
}

static sdp_rtpmap_t *sdp_rtpmap_append(sdp_rtpmap_t *rtpmaps, sdp_rtpmap_t *newmap){
	sdp_rtpmap_t *begin=rtpmaps;
	if (rtpmaps==NULL) return newmap;
	while(rtpmaps->rm_next){
		rtpmaps=rtpmaps->rm_next;
	}
	rtpmaps->rm_next=newmap;
	return begin;
}
/*
static sdp_rtpmap_t *sdp_rtpmaps_find_by_number(sdp_rtpmap_t *rtpmaps, int number){
	sdp_rtpmap_t *elem;
	for(elem=rtpmaps;elem!=NULL;elem=elem->rm_next){
		if (elem->rm_pt==(unsigned int)number)
			return elem;
	}
	return NULL;
}
*/

static PayloadType *find_by_number(const MSList *elem, int number){
	for(;elem!=NULL;elem=elem->next){
		PayloadType *pt=(PayloadType*)elem->data;
		if (payload_type_get_number(pt)==number)
			return pt;
	}
	return NULL;
}

static PayloadType *find_payload(const MSList *elem, const char *mime, int rate){
	for(;elem!=NULL;elem=elem->next){
		PayloadType *pt=(PayloadType*)elem->data;
		if (strcasecmp(pt->mime_type,mime)==0 && rate==pt->clock_rate)
			return pt;
	}
	return NULL;
}

MSList *SdpModifier::readPayloads(){
	sdp_media_t *mline=mSession->sdp_media;
	sdp_rtpmap_t *elem=mline->m_rtpmaps;
	MSList *ret=NULL;
	for(;elem!=NULL;elem=elem->rm_next){
		PayloadType * pt = payload_type_make_from_sdp_rtpmap (elem);
		if (pt != NULL) ret=ms_list_append(ret,pt);
	}
	return ret;
}

int SdpModifier::readPtime(){
	sdp_media_t *mline=mSession->sdp_media;
	if (mline && mline->m_attributes){
		sdp_attribute_t *at=sdp_attribute_find(mline->m_attributes,"ptime");
		if (at && at->a_value){
			return atoi(at->a_value);
		}
	}
	return 0;
}

void SdpModifier::setPtime(int ptime){
	sdp_media_t *mline=mSession->sdp_media;
	if (mline && mline->m_attributes){
		if (ptime>0){
			sdp_attribute_t *at=sdp_attribute_find(mline->m_attributes,"ptime");
			if (at){
				at->a_value=su_sprintf(mHome,"%i",ptime);
			}else{
				sdp_attribute_t *cat= (sdp_attribute_t *)su_alloc(mHome, sizeof(sdp_attribute_t));
				memset(cat,0,sizeof(*cat));
				cat->a_size=sizeof(*cat);
				cat->a_name="ptime";
				cat->a_value=su_sprintf(mHome,"%i",ptime);
				sdp_attribute_append(&mline->m_attributes,cat);
			}
		}else{
			sdp_attribute_remove(&mline->m_attributes,"ptime");
		}
	}
}

MSList *SdpModifier::findCommon(const MSList *offer, const MSList *answer, bool use_offer_numbering){
	MSList *ret=NULL;
	const MSList *e1,*e2;
	for (e1=offer;e1!=NULL;e1=e1->next){
		PayloadType *pt1=(PayloadType *)e1->data;
		for(e2=answer;e2!=NULL;e2=e2->next){
			PayloadType *pt2=(PayloadType *)e2->data;
			if (strcasecmp(pt1->mime_type,pt2->mime_type)==0
			    && pt1->clock_rate==pt2->clock_rate ){
				PayloadType *found=payload_type_clone(pt2);
				if (use_offer_numbering)
					payload_type_set_number(found,payload_type_get_number(pt1));
				else
					payload_type_set_number(found,payload_type_get_number(pt2));
				ret=ms_list_append(ret,found);
			}
		}
	}
	return ret;
}

void SdpModifier::replacePayloads(const MSList *payloads, const MSList *preserved_numbers){
	const MSList *elem;
	PayloadType *pt;
	sdp_rtpmap_t ref;
	int pt_index=100;
	
	memset(&ref,0,sizeof(ref));
	ref.rm_size=sizeof(ref);

	sdp_media_t *mline=mSession->sdp_media;
	mline->m_rtpmaps=NULL;
	
	for(elem=payloads;elem!=NULL;elem=elem->next){
		pt=(PayloadType*)elem->data;
		ref.rm_encoding=pt->mime_type;
		ref.rm_rate=pt->clock_rate;
		LOGD("Adding new payload to sdp: %s/%i",pt->mime_type,pt->clock_rate);
		int number=payload_type_get_number(pt);
		if (number==-1){
			/*see if it was numbered in the original offer*/
			PayloadType *orig=find_payload(preserved_numbers,pt->mime_type,pt->clock_rate);
			if (orig){
				number=payload_type_get_number(orig);
			}else{
				/* find a dynamic  payload type number */
				for(;pt_index<127;++pt_index){
					if (find_by_number(preserved_numbers,pt_index)==NULL){
						number=pt_index;
						++pt_index;
						break;
					}
				}
			}
		}
		sdp_rtpmap_t *map=sdp_rtpmap_make_from_payload_type(mHome,pt,number);
		mline->m_rtpmaps=sdp_rtpmap_append(mline->m_rtpmaps,map);
	}
}

short SdpModifier::getAudioIpVersion() {
      sdp_connection_t *c=mSession->sdp_media->m_connections;
      if (c && c->c_addrtype == sdp_addr_ip6) return 6;
      return 4;
}

void SdpModifier::getAudioIpPort(string *ip, int *port){
	*ip=mSession->sdp_media->m_connections?mSession->sdp_media->m_connections->c_address:mSession->sdp_connection->c_address;
	*port=mSession->sdp_media->m_port;
}

void SdpModifier::changeAudioIpPort(const char *ip, int port){
	mSession->sdp_media->m_connections
			?mSession->sdp_media->m_connections->c_address=su_strdup(mHome,ip)
			:mSession->sdp_connection->c_address=su_strdup(mHome,ip);
	mSession->sdp_media->m_port=port;
}

void SdpModifier::changeMediaConnection(sdp_media_t *mline, const char *relay_ip){
	sdp_connection_t *c=sdp_connection_dup(mHome,mSession->sdp_connection);
	if (c == NULL) {
		if (mline->m_connections) {
			mline->m_connections->c_address=su_strdup(mHome, relay_ip);
		}
	} else {
		c->c_address=su_strdup(mHome,relay_ip);
		if (sdp_connection_cmp(mSession->sdp_connection, c)) {
			mline->m_connections=c;
		} else {
			su_free(mHome,c);
		}
	}
}

void SdpModifier::addIceCandidate(function<void(int, string *, int *)> forward_fct, function<void(int, string *, int *)> backward_fct)
{
	char foundation[32];
	sdp_media_t *mline=mSession->sdp_media;
	uint64_t r;
	int i;
	string global_c_address;

	if (mSession->sdp_connection && mSession->sdp_connection->c_address) global_c_address=mSession->sdp_connection->c_address;

	r = (((uint64_t)random()) << 32) | (((uint64_t)random()) & 0xffffffff);
	snprintf(foundation, sizeof(foundation), "%llx", (long long unsigned int)r);
	for(i=0;mline!=NULL;mline=mline->m_next,++i){
		if (hasMediaAttribute(mline,"candidate") && !hasMediaAttribute(mline,"remote-candidates") && !hasMediaAttribute(mline,"nortpproxy")) {
			string relay_ip=(mline->m_connections && mline->m_connections->c_address) ? mline->m_connections->c_address : global_c_address;
			int relay_port=mline->m_port;
			string source_ip=relay_ip;
			int source_port=relay_port;
			uint32_t priority;

			forward_fct(i,&relay_ip,&relay_port);
			backward_fct(i,&source_ip,&source_port);

			for (uint16_t componentID=1; componentID<=2; componentID++) {
				if (componentID == 1) {
					/* Fix the connection line if needed */
					changeMediaConnection(mline, relay_ip.c_str());
				}
				if (!hasIceCandidate(mline, relay_ip, relay_port + componentID - 1)) {
					priority = (65535 << 8) | (256 - componentID);
					ostringstream candidate_line;
					candidate_line << foundation << ' ' << componentID << " UDP " << priority << ' ' << relay_ip << ' ' << relay_port + componentID - 1
						<< " typ relay raddr " << source_ip << " rport " << source_port + componentID - 1;
					addMediaAttribute(mline, "candidate", candidate_line.str().c_str());
				}
			}
			addMediaAttribute(mline, "nortpproxy", "yes");
		}
	}
}

void SdpModifier::iterate(function<void(int, const string &, int )> fct){
	sdp_media_t *mline=mSession->sdp_media;
	int i;
	string global_c_address;

	if (mSession->sdp_connection && mSession->sdp_connection->c_address) global_c_address=mSession->sdp_connection->c_address;

	for(i=0;mline!=NULL;mline=mline->m_next,++i){
		string ip=(mline->m_connections && mline->m_connections->c_address) ? mline->m_connections->c_address : global_c_address;
		int port=mline->m_port;

		fct(i, ip, port);
	}
}

void SdpModifier::masquerade(function<void(int, string *, int *)> fct){
	sdp_media_t *mline=mSession->sdp_media;
	sdp_attribute_t *rtcp_attribute;
	int i;
	string global_c_address;
	bool sdp_connection_translated = false;

	if (mSession->sdp_connection && mSession->sdp_connection->c_address) global_c_address=mSession->sdp_connection->c_address;

	for(i=0;mline!=NULL;mline=mline->m_next,++i){
		string ip=(mline->m_connections && mline->m_connections->c_address) ? mline->m_connections->c_address : global_c_address;
		int port=mline->m_port;

		if (hasMediaAttribute(mline,"nortpproxy")) continue;
		fct(i,&ip,&port);
		
		if (mline->m_connections){
			mline->m_connections->c_address=su_strdup(mHome,ip.c_str());
		}else if (mSession->sdp_connection){
			if (sdp_connection_translated){
				// If the global connection has already been translated, add a media specific connection if needed
				changeMediaConnection(mline,ip.c_str());
			}else{
				mSession->sdp_connection->c_address=su_strdup(mHome,ip.c_str());
				sdp_connection_translated = true;
			}
		}
		mline->m_port=port;
		rtcp_attribute = sdp_attribute_find(mline->m_attributes,"rtcp");
		if (rtcp_attribute) {
			int previous_port;
			string ip_version, network_family, protocol, rtcp_addr;
			ostringstream ost;
			ost << port + 1;
			istringstream ist(string(rtcp_attribute->a_value));
			ist >> previous_port;
			if (!ist.eof()) ist >> network_family;
			if (!ist.fail() && !ist.eof()) ist >> protocol;
			if (!ist.fail() && !ist.eof()) ist >> rtcp_addr;
			if (!ist.fail() && !ist.eof()) {
				ost << ' ' << network_family << ' ' << protocol << ' ' << ip;
			}
			sdp_attribute_t *a=(sdp_attribute_t *)su_alloc(mHome, sizeof(sdp_attribute_t));
			memset(a,0,sizeof(*a));
			a->a_size=sizeof(*a);
			a->a_name=su_strdup(mHome, "rtcp");
			a->a_value=su_strdup(mHome, ost.str().c_str());
			sdp_attribute_replace(&mline->m_attributes, a, 0);
		}
	}

	if (sdp_connection_translated) {
		/* By changing the global connection address we may have broken the connection address of some mlines
		   that were marked as "nortpproxy". So we need to fix the connection address of these mlines now. */
		mline = mSession->sdp_media;
		for (i = 0; mline != NULL; mline = mline->m_next, ++i) {
			if (hasMediaAttribute(mline, "nortpproxy") && !mline->m_connections) {
				changeMediaConnection(mline, global_c_address.c_str());
			}
		}
	}
}

bool SdpModifier::hasAttribute(const char *name) {
	return sdp_attribute_find(mSession->sdp_attributes,name);
}

bool SdpModifier::hasMediaAttribute(sdp_media_t *mline, const char *name)
{
	return sdp_attribute_find(mline->m_attributes,name);
}

bool SdpModifier::hasIceCandidate(sdp_media_t *mline, const string &addr, int port)
{
	sdp_attribute_t *candidate = mline->m_attributes;

	while ((candidate = sdp_attribute_find(candidate,"candidate")) != NULL) {
		string foundation, protocol, candidate_addr, type;
		int componentID, candidate_port;
		uint32_t priority;
		istringstream stream(string(candidate->a_value));
		stream >> foundation;
		stream >> componentID;
		stream >> protocol;
		stream >> priority;
		stream >> candidate_addr;
		stream >> candidate_port;
		stream >> type;
		if ((candidate_port == port) && (addr.compare(candidate_addr) == 0)) return true;
		candidate = candidate->a_next;
	}
	return false;
}

void SdpModifier::addAttribute(const char *name, const char *value) {
	sdp_attribute_t *a= (sdp_attribute_t *)su_alloc(mHome, sizeof(sdp_attribute_t));
	memset(a,0,sizeof(*a));
	a->a_size=sizeof(*a);
	a->a_name=su_strdup(mHome, name);
	a->a_value=su_strdup(mHome, value);
	sdp_attribute_append(&mSession->sdp_attributes,a);
}

void SdpModifier::addMediaAttribute(sdp_media_t *mline, const char *name, const char *value)
{
	sdp_attribute_t *a=(sdp_attribute_t *)su_alloc(mHome, sizeof(sdp_attribute_t));
	memset(a,0,sizeof(*a));
	a->a_size=sizeof(*a);
	a->a_name=su_strdup(mHome, name);
	a->a_value=su_strdup(mHome, value);
	sdp_attribute_append(&mline->m_attributes,a);
}

void SdpModifier::update(msg_t *msg, sip_t *sip){
	char buf[2048];
	sdp_printer_t *printer = sdp_print(mHome, mSession, buf, sizeof(buf), 0);

	if (sdp_message(printer)) {
		char const *sdp = sdp_message(printer);
		size_t msgsize = sdp_message_size(printer);
		sip_payload_t *payload=sip_payload_make(mHome,sdp);
		int err;
		err=sip_header_remove(msg,sip,(sip_header_t*)sip_payload(sip));
		if (err!=0){
			LOGE("Could not remove payload from SIP message");
		}
		err=sip_header_insert(msg,sip,(sip_header_t*)payload);
		if (err!=0){
			LOGE("Could not add payload to SIP message");
		}
		if (sip->sip_content_length!=NULL){
			sip_header_remove(msg,sip,(sip_header_t*)sip->sip_content_length);
			sip_header_insert(msg,sip,(sip_header_t*)
			                  sip_content_length_format (mHome,"%i",(int)msgsize));
		}
	}else{
		LOGE("Could not print SDP message !");
	}
	sdp_printer_free(printer);
}
