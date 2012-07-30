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

using namespace ::std;

SdpModifier *SdpModifier::createFromSipMsg(su_home_t *home, sip_t *sip){
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
		if (hasMediaAttribute(mline,"candidate") && !hasMediaAttribute(mline,"remote-candidates")) {
			char candidate_line[256];
			string relay_ip=(mline->m_connections && mline->m_connections->c_address) ? mline->m_connections->c_address : global_c_address;
			int relay_port=mline->m_port;
			string source_ip=relay_ip;
			int source_port=relay_port;
			uint32_t priority;

			forward_fct(i,&relay_ip,&relay_port);
			backward_fct(i,&source_ip,&source_port);

			for (uint16_t componentID=1; componentID<=2; componentID++) {
				priority = (65535 << 8) | (256 - componentID);
				snprintf(candidate_line, sizeof(candidate_line), "%s %d UDP %d %s %d typ relay raddr %s rport %d",
					foundation, componentID, priority, relay_ip.c_str(), relay_port + componentID - 1, source_ip.c_str(), source_port + componentID - 1);
				addMediaAttribute(mline, "candidate", candidate_line);
			}
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

void SdpModifier::translate(function<void(int, string *, int *)> fct){
	sdp_media_t *mline=mSession->sdp_media;
	sdp_attribute_t *rtcp_attribute;
	int i;
	string global_c_address;

	if (mSession->sdp_connection && mSession->sdp_connection->c_address) global_c_address=mSession->sdp_connection->c_address;

	for(i=0;mline!=NULL;mline=mline->m_next,++i){
		string ip=(mline->m_connections && mline->m_connections->c_address) ? mline->m_connections->c_address : global_c_address;
		int port=mline->m_port;

		fct(i,&ip,&port);
		
		if (mline->m_connections){
			mline->m_connections->c_address=su_strdup(mHome,ip.c_str());
		}else if (i==0 && mSession->sdp_connection){
			mSession->sdp_connection->c_address=su_strdup(mHome,ip.c_str());
		}
		mline->m_port=port;
		rtcp_attribute = sdp_attribute_find(mline->m_attributes,"rtcp");
		if (rtcp_attribute) {
			char port_str[256];
			char rtcp_ip[128];
			char ip_version[2];
			int previous_port;
			int nb;
			nb = sscanf(rtcp_attribute->a_value, "%d IN IP%[46] %s", &previous_port, ip_version, rtcp_ip);
			if (nb == 1) {
				snprintf(port_str, sizeof(port_str), "%d", port+1);
			} else if (nb == 3) {
				snprintf(port_str, sizeof(port_str), "%d IN IP%s %s", port+1, ip_version, ip.c_str());
			} else continue;
			sdp_attribute_t *a=(sdp_attribute_t *)su_alloc(mHome, sizeof(sdp_attribute_t));
			memset(a,0,sizeof(*a));
			a->a_size=sizeof(*a);
			a->a_name=su_strdup(mHome, "rtcp");
			a->a_value=su_strdup(mHome, port_str);
			sdp_attribute_replace(&mline->m_attributes, a, 0);
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
