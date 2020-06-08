#include "server-listener.hh"
#include "server-registrar-listener.hh"
#include <flexisip/registrardb.hh>

using namespace std;
using namespace linphone;
using namespace flexisip;

static const string CONTENT_TYPE = "application/reginfo+xml";

void ServerListener::onSubscribeReceived(const std::shared_ptr<linphone::Core> & lc, const std::shared_ptr<linphone::Event> & lev, const std::string & subscribeEvent, const std::shared_ptr<const linphone::Content> & body) {
    string eventHeader = lev->getCustomHeader("Event");
    if (eventHeader != "reg") {
        lev->denySubscription(Reason::BadEvent);
    }

    string acceptHeader = lev->getCustomHeader("Accept");
    if (acceptHeader != "application/reginfo+xml") {
        lev->denySubscription(Reason::NotAcceptable);
    }

    lev->acceptSubscription();

    auto listener = make_shared<ServerRegistrarListener>(lev);

    SofiaAutoHome home;
    url_t *url = url_make(home.home(), lev->getFrom()->asString().c_str());

    RegistrarDb::get()->subscribe(url, listener);
    RegistrarDb::get()->fetch(url, listener, true);
}