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


SdpModifier *SdpModifier::createFromSipMsg(su_home_t *home, sip_t *sip){
	SdpModifier *sm=new SdpModifier(home);
	if (!sm->initFromSipMsg(sip)) {
		delete sm;
		sm=NULL;
	}
	return sm;
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
	}
	
	return mSession!=NULL;
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
	sdp_rtpmap_t *elem=rtpmaps;
	if (rtpmaps==NULL) return newmap;
	while(elem->rm_next!=NULL)
		elem=elem->rm_next;
	elem->rm_next=newmap;
	return rtpmaps;
}

static sdp_rtpmap_t *sdp_rtpmaps_find_by_number(sdp_rtpmap_t *rtpmaps, int number){
	sdp_rtpmap_t *elem;
	for(elem=rtpmaps;elem!=NULL;elem=elem->rm_next){
		if (elem->rm_pt==(unsigned int)number)
			return elem;
	}
	return NULL;
}

MSList *SdpModifier::readPayloads(){
	sdp_media_t *mline=mSession->sdp_media;
	sdp_rtpmap_t *elem=mline->m_rtpmaps;
	MSList *ret=NULL;
	for(;elem!=NULL;elem=elem->rm_next){
		ret=ms_list_append(ret,payload_type_make_from_sdp_rtpmap (elem));
	}
	return ret;
}

MSList *SdpModifier::findCommon(const MSList *offer, const MSList *answer){
	MSList *ret=NULL;
	const MSList *e1,*e2;
	for (e1=offer;e1!=NULL;e1=e1->next){
		PayloadType *pt1=(PayloadType *)e1->data;
		for(e2=answer;e2!=NULL;e2=e2->next){
			PayloadType *pt2=(PayloadType *)e2->data;
			if (strcasecmp(pt1->mime_type,pt2->mime_type)==0
			    && pt1->clock_rate==pt2->clock_rate ){
				PayloadType *found=payload_type_clone(pt2);
				payload_type_set_number(found,payload_type_get_number(pt2));
				ret=ms_list_append(ret,found);
			}
		}
	}
	return ret;
}

void SdpModifier::appendNewPayloadsAndRemoveUnsupported(const MSList *payloads){
	const MSList *elem;
	PayloadType *pt;
	sdp_rtpmap_t ref;
	memset(&ref,0,sizeof(ref));
	ref.rm_size=sizeof(ref);

	removeUnwantedPayloads(payloads); // payloads are the ones to keep

	sdp_media_t *mline=mSession->sdp_media;
	sdp_rtpmap_t *rtpmaps=mline->m_rtpmaps;
	
	for(elem=payloads;elem!=NULL;elem=elem->next){
		sdp_rtpmap_t *matching;
		pt=(PayloadType*)elem->data;
		ref.rm_encoding=pt->mime_type;
		ref.rm_rate=pt->clock_rate;
		if ((matching=sdp_rtpmap_find_matching(rtpmaps,&ref))==NULL){
			LOGD("Adding new payload to sdp: %s/%i",pt->mime_type,pt->clock_rate);
			int number=payload_type_get_number(pt);
			if (number==-1){
				/* find a dynamic  payload type number */
				for(int i=100;i<127;++i){
					if (sdp_rtpmaps_find_by_number(mline->m_rtpmaps,i)==NULL){
						number=i;
						break;
					}
				}
			}
			sdp_rtpmap_t *map=sdp_rtpmap_make_from_payload_type (mHome,pt,number);
			mline->m_rtpmaps=sdp_rtpmap_append(mline->m_rtpmaps,map);
		}else{
			//eventually add our recv fmtp
			if (matching->rm_fmtp==NULL && pt->recv_fmtp!=NULL){
				matching->rm_fmtp=su_strdup(mHome,pt->recv_fmtp);
			}
		}
	}
}

static PayloadType *findPayload(const MSList *ref, const char *mime, int rate){
	for(;ref!=NULL;ref=ref->next){
		PayloadType *pt=(PayloadType*)ref->data;
		if (strcasecmp(pt->mime_type,mime)==0 && pt->clock_rate==rate){
			return pt;
		}
	}
	return NULL;
}

void SdpModifier::removeUnwantedPayloads(const MSList *tokeep){
	sdp_media_t *mline=mSession->sdp_media;
	sdp_rtpmap_t *rtpmaps=mline->m_rtpmaps;
	sdp_rtpmap_t *elem,*prev_elem;
	
	for(prev_elem=NULL,elem=rtpmaps;elem!=NULL;elem=elem->rm_next){
		if (findPayload(tokeep,elem->rm_encoding,elem->rm_rate)==NULL){
			sdp_rtpmap_t *next=elem->rm_next;
			if (prev_elem==NULL){
				mline->m_rtpmaps=next;
			}else{
				prev_elem->rm_next=next;
			}
		}else{
			prev_elem=elem;
		}
	}
}

void SdpModifier::getAudioIpPort(std::string *ip, int *port){
	*ip=mSession->sdp_media->m_connections?mSession->sdp_media->m_connections->c_address:mSession->sdp_connection->c_address;
	*port=mSession->sdp_media->m_port;
}

void SdpModifier::changeAudioIpPort(const char *ip, int port){
	mSession->sdp_media->m_connections
			?mSession->sdp_media->m_connections->c_address=su_strdup(mHome,ip)
			:mSession->sdp_connection->c_address=su_strdup(mHome,ip);
	mSession->sdp_media->m_port=port;
}

void SdpModifier::update(msg_t *msg, sip_t *sip){
	char buf[1024];
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
