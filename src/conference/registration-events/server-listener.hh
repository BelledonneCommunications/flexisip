#pragma once

#include <linphone++/linphone.hh>

using namespace std;
using namespace linphone;

class ServerListener : public CoreListener {
public:
    void onSubscribeReceived(const std::shared_ptr<linphone::Core> & lc, const std::shared_ptr<linphone::Event> & lev, const std::string & subscribeEvent, const std::shared_ptr<const linphone::Content> & body);
};