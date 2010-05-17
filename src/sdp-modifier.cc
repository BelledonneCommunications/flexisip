/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*- */
/*
 * bcproxy
 * Copyright (C) Simon Morlat 2010 <simon.morlat@linphone.org>
 * 
 * bcproxy is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * bcproxy is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "sdp-modifier.hh"

#include <sofia-sip/sip_protos.h>
#include "offeranswer.h"

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
		LOGW("SIP message has no payload");
		return false;
	}
	sdp_parser_t *parser = sdp_parse(mHome, payload->pl_data, payload->pl_len, 0);
	mSession=sdp_session(parser);
	if (mSession==NULL) {
		LOGE("SDP parsing error: %s",sdp_parsing_error(parser));
	}
	sdp_parser_free(parser);
	return mSession!=NULL;
}

SdpModifier::SdpModifier(su_home_t *home){
	mSip=NULL;
	mHome=home;
	mSession=NULL;
}

SdpModifier::~SdpModifier(){
	
}

static sdp_list_t *sdp_list_append(su_home_t *home, sdp_list_t *l, char *text){
	sdp_list_t *elem=(sdp_list_t*)su_zalloc(home,sizeof(sdp_list_t));
	elem->l_size=sizeof(sdp_list_t);
	elem->l_text=text;
	if (l==NULL) return elem;
	while(l->l_next!=NULL) l=l->l_next;
	l->l_next=elem;
	return l;
}

static sdp_list_t * sdp_list_find(sdp_list_t *l, const char *text){
	for(;l!=NULL;l=l->l_next){
		if (l->l_text && strcmp(l->l_text,text)==0){
			return l;
		}
	}
	return NULL;
}

static sdp_rtpmap_t *sdp_rtpmap_make_from_payload_type(su_home_t *home, PayloadType *pt, int number){
	sdp_rtpmap_t *map=(sdp_rtpmap_t*)su_zalloc(home,sizeof(sdp_rtpmap_t));
	map->rm_size=sizeof(sdp_rtpmap_t);
	map->rm_encoding=su_strdup(home,pt->mime_type);
	map->rm_rate=pt->clock_rate;
	map->rm_pt=number;
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

void SdpModifier::appendNewPayloads(const MSList *payloads){
	const MSList *elem;
	PayloadType *pt;
	sdp_rtpmap_t ref;
	sdp_media_t *mline=mSession->sdp_media;
	sdp_rtpmap_t *rtpmaps=mline->m_rtpmaps;
	memset(&ref,0,sizeof(ref));
	ref.rm_size=sizeof(ref);
	
	for(elem=payloads;elem!=NULL;elem=elem->next){
		pt=(PayloadType*)elem->data;
		ref.rm_encoding=pt->mime_type;
		ref.rm_rate=pt->clock_rate;
		if (sdp_rtpmap_find_matching(rtpmaps,&ref)==NULL){
			LOGD("Adding new payload to sdp: %s/%i",pt->mime_type,pt->clock_rate);
			int number=payload_type_get_number(pt);
			if (number==-1){
				/* find a dynamic  payload type number */
				for(int i=100;i<127;++i){
					char tmp[10];
					snprintf(tmp,sizeof(tmp),"%i",i);
					if (sdp_list_find(mline->m_format,tmp)==NULL){
						number=i;
						break;
					}
				}
			}
			sdp_rtpmap_t *map=sdp_rtpmap_make_from_payload_type (mHome,pt,number);
			mline->m_rtpmaps=sdp_rtpmap_append(mline->m_rtpmaps,map);
			sdp_list_append(mHome,mline->m_format,su_sprintf(mHome,"%i",number));
		}
	}
}

void SdpModifier::changeAudioIpPort(const char *ip, int port){
	mSession->sdp_connection->c_address=su_strdup(mHome,ip);
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
