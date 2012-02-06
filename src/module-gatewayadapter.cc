/*
        Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2012  Belledonne Communications SARL.
    Author: Yann Diorcet

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
#include <sofia-sip/nua.h>

static void nua_callback(nua_event_t event,
        int status, char const *phrase,
        nua_t *nua, nua_magic_t *_t,
        nua_handle_t *nh, nua_hmagic_t *hmagic,
        sip_t const *sip,
        tagi_t tags[]);

class GatewayAdapter : public Module, public ModuleToolbox {
public:

        GatewayAdapter(Agent *ag);

        ~GatewayAdapter();

        virtual void onDeclare(ConfigStruct *module_config) {
                ConfigItemDescriptor items[] = {
                        { String, "gateway", "A gateway uri where to send all requests", ""},
                        { String, "gateway-domain", "Force the domain of send all requests", ""},
                        config_item_end
                };
                module_config->addChildrenValues(items);
        }

        virtual void onLoad(Agent *agent, const ConfigStruct *module_config);

        virtual void onRequest(std::shared_ptr<SipEvent> &ev);

        virtual void onResponse(std::shared_ptr<SipEvent> &ev);

private:
        static ModuleInfo<GatewayAdapter> sInfo;
        su_home_t *mHome;
        nua_t *mNua;
        url_t *mDomain;
};

GatewayAdapter::GatewayAdapter(Agent *ag) : Module(ag), mDomain(NULL) {
        mHome = su_home_create();
}

GatewayAdapter::~GatewayAdapter() {
        su_home_destroy(mHome);
}

void GatewayAdapter::onLoad(Agent *agent, const ConfigStruct *module_config) {
        std::string gateway = module_config->get<ConfigString > ("gateway")->read();
        std::string domain = module_config->get<ConfigString > ("gateway-domain")->read();
        if (!domain.empty()) {
                mDomain = url_make(mHome, domain.c_str());
        }
        mNua = nua_create(agent->getRoot(), nua_callback, NULL, NUTAG_REGISTRAR(gateway.c_str()), TAG_END());
}

void GatewayAdapter::onRequest(std::shared_ptr<SipEvent> &ev) {
        sip_t *sip = ev->mSip;
        if (sip->sip_request->rq_method == sip_method_register) {
                if (sip->sip_contact != NULL) {
                        nua_handle_t *nh = nua_handle(mNua, NULL, TAG_END());
                        sip_from_t *from = sip_from_dup(ev->getHome(), sip->sip_from);
                        sip_to_t *to = sip_to_dup(ev->getHome(), sip->sip_to);
                        if (mDomain != NULL) {
                                from->a_url->url_host = mDomain->url_host;
                                from->a_url->url_port = mDomain->url_port;
                                to->a_url->url_host = mDomain->url_host;
                                to->a_url->url_port = mDomain->url_port;
                        }
                        nua_register(nh,
                                SIPTAG_FROM(from),
                                SIPTAG_TO(to),
                                TAG_END());
                }
        }
}

void GatewayAdapter::onResponse(std::shared_ptr<SipEvent> &ev) {

}

ModuleInfo<GatewayAdapter> GatewayAdapter::sInfo("GatewayAdapter",
        "...");

static void
nua_callback(nua_event_t event,
        int status, char const *phrase,
        nua_t *nua, nua_magic_t *_t,
        nua_handle_t *nh, nua_hmagic_t *hmagic,
        sip_t const *sip,
        tagi_t tags[]) {

}

