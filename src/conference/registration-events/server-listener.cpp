#include "server-listener.hh"

using namespace std;
using namespace linphone;

void onSubscribeReceived(const std::shared_ptr<linphone::Core> & lc, const std::shared_ptr<linphone::Event> & lev, const std::string & subscribeEvent, const std::shared_ptr<const linphone::Content> & body) {
    lev->acceptSubscription();
    shared_ptr<Content> notifyContent = Factory::get()->createContent();
    notifyContent->setType("application");
    notifyContent->setSubtype("xml");
    string notiFybody("<mon super xml de notify>");
    notifyContent->setBuffer((uint8_t *)notiFybody.data(), notiFybody.length());
    lev->notify(notifyContent);
}