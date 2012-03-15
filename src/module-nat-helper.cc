/*
	Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010  Belledonne Communications SARL.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTIC<ULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "agent.hh"

#include <sofia-sip/msg_addr.h>

class NatHelper : public Module, protected ModuleToolbox{
	public:
		NatHelper(Agent *ag) : Module(ag){
		}
		~NatHelper(){
		}
		virtual void onRequest(SipEvent *ev) {
			sip_request_t *rq=ev->mSip->sip_request;
			/* if we receive a request whose first via is wrong (received or rport parameters are present),
			fix any possible Contact headers with the same wrong ip address and ports */
			fixContactFromVia(ev->getHome(),ev->mSip,ev->mSip->sip_via);

			if (rq->rq_method==sip_method_invite || rq->rq_method==sip_method_subscribe){
				//be in the record route for all requests that can estabish a dialog
				addRecordRoute (ev->getHome(),getAgent(),ev->mMsg,ev->mSip);
			}
		}
		virtual void onResponse(SipEvent *ev){
			sip_status_t *st=ev->mSip->sip_status;
			sip_cseq_t *cseq=ev->mSip->sip_cseq;
			/*in responses that establish a dialog, masquerade Contact so that further requests (including the ACK) are routed in the same way*/
			if (cseq && (cseq->cs_method==sip_method_invite || cseq->cs_method==sip_method_subscribe)){
				if (st->st_status>=200 && st->st_status<=299){	
					fixContactInResponse(ev->getHome(),ev->mMsg,ev->mSip);
				}
			}
		}
	private:
		bool empty(const char *value){
			return value==NULL || value[0]=='\0';
		}
		void fixContactInResponse(su_home_t *home, msg_t *msg, sip_t *sip){
			const su_addrinfo_t *ai=msg_addrinfo(msg);
			const sip_via_t *via=sip->sip_via;
			const char *via_transport=sip_via_transport(via);
			char ct_transport[20]={0};
			if (ai!=NULL){
				char ip[NI_MAXHOST];
				char port[NI_MAXSERV];
				int err=getnameinfo(ai->ai_addr,ai->ai_addrlen,ip,sizeof(ip),port,sizeof(port),NI_NUMERICHOST|NI_NUMERICSERV);
				if (err!=0){
					LOGE("getnameinfo() error: %s",gai_strerror(err));
				}else{
					sip_contact_t *ctt=sip->sip_contact;
					if (ctt && ctt->m_url && ctt->m_url->url_host){
						if (strcmp(ip,ctt->m_url->url_host)!=0 || !sipPortEquals(ctt->m_url->url_port,port)){
							LOGD("Response is coming from %s:%s, fixing contact",ip,port);
							ctt->m_url->url_host=su_strdup(home,ip);
							ctt->m_url->url_port=su_strdup(home,port);
						}else LOGD("Contact in response is correct.");
						url_param(ctt->m_url->url_params,"transport",ct_transport,sizeof(ct_transport)-1);
						if (strcasecmp(via_transport,"UDP")==0){
							if (ct_transport[0]!='\0'){
								LOGD("Contact in response has incorrect transport parameter, removing it");
								ctt->m_url->url_params=url_strip_param_string(su_strdup(home,ctt->m_url->url_params),"transport");
							}
						}else if (strcasecmp(via_transport,ct_transport)!=0) {
							char param[64];
							snprintf(param,sizeof(param)-1,"transport=%s",via_transport);
							LOGD("Contact in response has incorrect transport parameter, replacing by %s",via_transport);
							ctt->m_url->url_params=url_strip_param_string(su_strdup(home,ctt->m_url->url_params),"transport");
							url_param_add(home,ctt->m_url,param);
						}
					}
				}
			}
		}
		void fixContactFromVia(su_home_t *home, sip_t *msg, const sip_via_t *via){
			sip_contact_t *ctt=msg->sip_contact;
			const char *received=via->v_received;
			const char *rport=via->v_rport;
			const char *via_transport=sip_via_transport(via);
			bool is_frontend=(via->v_next==NULL); /*true if we are the first proxy the request is walking through*/
			bool single_contact=(ctt!=NULL && ctt->m_next==NULL);

			if (empty(received) && empty(rport))
				return; /*nothing to do*/

			if (empty(received)){
				/*case where the rport is not empty  but received is empty (because the host was correct)*/
				received=via->v_host;
			}
			
			for (;ctt!=NULL;ctt=ctt->m_next){
				if (ctt->m_url && ctt->m_url->url_host){
					const char *host=ctt->m_url->url_host;
					char ct_transport[20]={0};
					url_param(ctt->m_url->url_params,"transport",ct_transport,sizeof(ct_transport)-1);
					/*If we have a single contact and we are the front-end proxy, or if we found a ip:port in a contact that seems incorrect
						because the same appeared fixed in the via, then fix it*/
					if ( (is_frontend && single_contact)
						|| (strcmp(host,via->v_host)==0 && sipPortEquals(ctt->m_url->url_port,via->v_port) && transportEquals(via_transport,ct_transport))){
						
						if (strcmp(host,received)!=0 || !sipPortEquals(ctt->m_url->url_port,rport)){
							LOGD("Fixing contact header with %s:%s to %s:%s",
							   ctt->m_url->url_host, ctt->m_url->url_port ? ctt->m_url->url_port :"" ,
							   received, rport ? rport : "");
							ctt->m_url->url_host=received;
							ctt->m_url->url_port=rport;
						}
						if (!transportEquals(via_transport,ct_transport)) {
							char param[64];
							snprintf(param,sizeof(param)-1,"transport=%s",via_transport);
							LOGD("Contact in request has incorrect transport parameter, replacing by %s",via_transport);
							ctt->m_url->url_params=url_strip_param_string(su_strdup(home,ctt->m_url->url_params),"transport");
							url_param_add(home,ctt->m_url,param);
						}
					}
				}
			}
		}
		static ModuleInfo<NatHelper> sInfo;
};

ModuleInfo<NatHelper> NatHelper::sInfo("NatHelper",
	"The NatHelper module executes small tasks to make SIP work smoothly despite firewalls."
    "It corrects the Contact headers that contain obviously inconsistent addresses, and adds "
    "a Record-Route to ensure subsequent requests are routed also by the proxy, through the UDP or TCP "
    "channel each client opened to the proxy.",0);
