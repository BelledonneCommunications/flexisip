#include "server.hh"
#include "registrar/listener.hh"
#include <flexisip/registrardb.hh>

using namespace std;
using namespace linphone;

static const string CONTENT_TYPE = "application/reginfo+xml";


namespace RegistrationEvent {

Server::Init Server::sStaticInit; // The Init object is instanciated to load the config
Server::Server (su_root_t *root) : ServiceServer(root) {}
Server::~Server () {}

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

void Server::_init () {
    su_root_t *root = su_root_create(NULL);

    mCore = Factory::get()->createCore("", "", nullptr);
    auto config = GenericManager::get()->getRoot()->get<GenericStruct>("regevent-server");

    mCore->getConfig()->setString("storage", "uri", config->get<ConfigString>("database-connection-string")->read());
    mCore->getConfig()->setString("storage", "backend", config->get<ConfigString>("database-backend")->read());

    shared_ptr<Transports> regEventTransport = Factory::get()->createTransports();
    regEventTransport->setTcpPort(stoi(config->get<ConfigString>("port")->read()));
    mCore->setTransports(regEventTransport);
    mCore->addListener(make_shared<RegistrationEvent::Server>(root));
    mCore->start();
}

void Server::_run () {
    mCore->iterate();
}

void Server::_stop () {
    mCore->removeListener(shared_from_this());
}

Server::Init::Init() {
    ConfigItemDescriptor items[] = {
        {
            String,
            "database-backend",
            "Choose the type of backend that linphone will use for the connection.\n"
            "",
            "sqlite3"
        },
        {
            String,
            "database-connection-string",
            "The configuration parameters of the backend.\n"
            "",
            ":memory:"
        },
        {
            String,
            "port",
            "The port on which the RegEvent server is listening on.\n"
            "",
            "1234"
        },
        config_item_end
    };

    GenericStruct *s = new GenericStruct("regevent-server", "Flexisip RegEvent server parameters.", 0);
    GenericManager::get()->getRoot()->addChild(s);
    s->addChildrenValues(items);
}

}