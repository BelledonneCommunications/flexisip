/*
linphone
Copyright (C) 2010  Simon MORLAT (simon.morlat@free.fr)

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*/

#ifndef offeranswer_h
#define offeranswer_h

#include <mediastreamer2/mscommon.h>

#define payload_type_set_number(pt,n)	(pt)->user_data=(void*)(long)n
#define payload_type_get_number(pt)		(int)(long)(pt)->user_data

typedef enum {
	SalTransportDatagram,
	SalTransportStream
}SalTransport;

typedef enum {
	SalAudio,
	SalVideo,
	SalOther
} SalStreamType;

typedef enum{
	SalProtoUnknown,
	SalProtoRtpAvp,
	SalProtoRtpSavp
}SalMediaProto;

typedef struct SalEndpointCandidate{
	char addr[64];
	int port;
}SalEndpointCandidate;

#define SAL_ENDPOINT_CANDIDATE_MAX 2

typedef struct SalStreamDescription{
	SalMediaProto proto;
	SalStreamType type;
	char addr[64];
	int port;
	MSList *payloads; //<list of PayloadType
	int bandwidth;
	int ptime;
	SalEndpointCandidate candidates[SAL_ENDPOINT_CANDIDATE_MAX];
} SalStreamDescription;

#define SAL_MEDIA_DESCRIPTION_MAX_STREAMS 4

typedef struct SalMediaDescription{
	int refcount;
	char addr[64];
	char username[64];
	int nstreams;
	int bandwidth;
	SalStreamDescription streams[SAL_MEDIA_DESCRIPTION_MAX_STREAMS];
} SalMediaDescription;

SalMediaDescription *sal_media_description_new();
void sal_media_description_ref(SalMediaDescription *md);
void sal_media_description_unref(SalMediaDescription *md);
bool_t sal_media_description_empty(SalMediaDescription *md);
const SalStreamDescription *sal_media_description_find_stream(const SalMediaDescription *md,
    SalMediaProto proto, SalStreamType type);

/** 
 This header files defines the SDP offer answer API.
 It can be used by implementations of SAL directly.
**/


/**
 * Returns a media description to run the streams with, based on a local offer
 * and the returned response (remote).
**/
int offer_answer_initiate_outgoing(const SalMediaDescription *local_offer,
									const SalMediaDescription *remote_answer,
    							SalMediaDescription *result);

/**
 * Returns a media description to run the streams with, based on the local capabilities and
 * and the received offer.
 * The returned media description is an answer and should be sent to the offerer.
**/
int offer_answer_initiate_incoming(const SalMediaDescription *local_capabilities,
						const SalMediaDescription *remote_offer,
    					SalMediaDescription *result);
					
#endif

