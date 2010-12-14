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

#include "agent.hh"

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
				addRecordRoute (ev->getHome(),getAgent(),ev->mSip);
			}
		}
		virtual void onResponse(SipEvent *ev){
		}
	private:
		bool empty(const char *value){
			return value==NULL || value[0]=='\0';
		}
		void fixContactFromVia(su_home_t *home, sip_t *msg, const sip_via_t *via){
			sip_contact_t *ctt=msg->sip_contact;
			const char *received=via->v_received;
			const char *rport=via->v_rport;
			
			if (empty(received) && empty(rport))
				return; /*nothing to do*/

			if (empty(received)){
				/*case where the rport is not empty  but received is empty (because the host was correct)*/
				received=via->v_host;
			}
			
			for (;ctt!=NULL;ctt=ctt->m_next){
				const char *host=ctt->m_url->url_host;
				if (host && strcmp(host,via->v_host)==0 
				    && sipPortEquals(ctt->m_url->url_port,via->v_port) ){
					/*we have found a ip:port in a contact that seems incorrect, so fix it*/
					LOGD("Fixing contact header with %s:%s to %s:%s",
					   ctt->m_url->url_host, ctt->m_url->url_port ? ctt->m_url->url_port :"" ,
					   received, rport ? rport : "");
					ctt->m_url->url_host=received;
					ctt->m_url->url_port=rport;
				}
			}
		}
		static ModuleInfo<NatHelper> sInfo;
};

ModuleInfo<NatHelper> NatHelper::sInfo("NatHelper");
