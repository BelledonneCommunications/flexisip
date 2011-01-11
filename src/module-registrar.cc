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
#include "registrardb.hh"

using namespace::std;

class Registrar : public Module {
	public:
		Registrar(Agent *ag) : Module(ag){
		}
		
		virtual void onLoad(Agent *agent, const ConfigArea & module_config){
			list<string>::const_iterator it;
			mDomains=module_config.get("reg_domains",list<string>());
			for (it=mDomains.begin();it!=mDomains.end();++it){
				LOGD("Found registrar domain: %s",(*it).c_str());
			}
		}
		
		virtual void onRequest(SipEvent *ev){
			sip_t *sip=ev->mSip;
			if (sip->sip_request->rq_method==sip_method_register){
				url_t *sipurl=sip->sip_from->a_url;
				if (sipurl->url_host && isManagedDomain(sipurl->url_host)){
					sip_expires_t *expires=sip->sip_expires;
					if (expires){
						int delta=expires->ex_delta;
						if (delta<30){
							delta=30;
						}
						if (delta > 3600*24)
							delta=3600*24;
						
						RegistrarDb::get()->addRecord(sip->sip_from,sip->sip_contact,delta);
						LOGD("Added record to registrar database.");
						/*we need to answer directly */
						nta_msg_treply(getAgent()->getSofiaAgent (),ev->mMsg,200,"Registration succesful",
						               SIPTAG_CONTACT(sip->sip_contact),
						               TAG_END());
						ev->stopProcessing();
					}
				}
			}else{
				/*see if we can route other requests */
				url_t *sipurl=sip->sip_to->a_url;
				if (sipurl->url_host &&  isManagedDomain(sipurl->url_host)){
					const sip_contact_t *ct=RegistrarDb::get()->retrieveMostRecent(sip->sip_to);
					if (ct){
						LOGD("Registrar: found contact information in database, rewriting request uri");
						/*rewrite request-uri */
						sip->sip_request->rq_url[0]=*url_hdup(ev->getHome(),ct->m_url);             
					}else{
						if (sip->sip_request->rq_method!=sip_method_ack){
							LOGD("This user isn't registered.");
							nta_msg_treply(getAgent()->getSofiaAgent (),ev->mMsg,404,"User not found",
						               TAG_END());
						}
						ev->stopProcessing();
					}
				}
			}
		}
		virtual void onResponse(SipEvent *ev){
		}

	private:
		bool isManagedDomain(const char *domain){
			return ModuleToolbox::matchesOneOf(domain,mDomains);
		}
		list<string> mDomains;
		static ModuleInfo<Registrar> sInfo;
};

ModuleInfo<Registrar> Registrar::sInfo("Registrar");

