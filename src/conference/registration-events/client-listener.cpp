#include "client-listener.hh"
#include "server-listener.hh"

#include <iostream>
#include <sstream>

using namespace std;
using namespace linphone;

void ClientListener::subscribe(const shared_ptr<Core> & lc, const shared_ptr<Address> to) {
    shared_ptr<Event> subscribe = lc->createSubscribe(to, "reg", 60);
    shared_ptr<Content> subsContent = Factory::get()->createContent();
    subsContent->setType("application");
    subsContent->setSubtype("xml");
    string notiFybody("<mon super xml de notify>");
    subsContent->setBuffer((uint8_t *)notiFybody.data(), notiFybody.length());

    subscribe->sendSubscribe(subsContent);
}