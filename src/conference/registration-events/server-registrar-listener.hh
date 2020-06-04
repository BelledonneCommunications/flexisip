#pragma once

#include <linphone++/linphone.hh>
#include <flexisip/registrardb.hh>

using namespace std;
using namespace linphone;
using namespace flexisip;

class ServerRegistrarListener : public ContactRegisteredListener, public ContactUpdateListener {
    public:
        ServerRegistrarListener(const shared_ptr<linphone::Event> &lev);
        void onRecordFound(const shared_ptr<Record> &r) override;
        void onError() override {}
        void onInvalid() override {}
        void onContactRegistered(const shared_ptr<Record> &r, const string &uid) override;
        void onContactUpdated(const shared_ptr<ExtendedContact> &ec) override {}
    private:
        const shared_ptr<linphone::Event> event;
        void processRecord(const shared_ptr<Record> &r);
};