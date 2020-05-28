#pragma once

#include <linphone++/linphone.hh>

using namespace std;
using namespace linphone;

class ClientListener : public CoreListener {
public:
    void onNotifyReceived(const std::shared_ptr<linphone::Core> & lc, const std::shared_ptr<linphone::Event> & lev, const std::string & notifiedEvent, const std::shared_ptr<const linphone::Content> & body) override {
        notifyReceived = true;
    }
    bool notifyReceived = false;

};