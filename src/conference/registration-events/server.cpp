#include "server.hh"
#include "registrar/listener.hh"
#include <flexisip/registrardb.hh>

using namespace std;
using namespace linphone;

static const string CONTENT_TYPE = "application/reginfo+xml";

namespace RegistrationEvent {

void Server::onSubscribeReceived(
    const shared_ptr<Core> & lc,
    const shared_ptr<Event> & lev,
    const string & subscribeEvent,
    const shared_ptr<const Content> & body
) {
    string eventHeader = lev->getCustomHeader("Event");
    if (eventHeader != "reg") {
        lev->denySubscription(Reason::BadEvent);
    }

    string acceptHeader = lev->getCustomHeader("Accept");
    if (acceptHeader != "application/reginfo+xml") {
        lev->denySubscription(Reason::NotAcceptable);
    }

    lev->acceptSubscription();

    auto listener = make_shared<Registrar::Listener>(lev);

    SofiaAutoHome home;
    url_t *url = url_make(home.home(), lev->getTo()->asString().c_str());

    RegistrarDb::get()->subscribe(url, listener);
    RegistrarDb::get()->fetch(url, listener, true);
}

}