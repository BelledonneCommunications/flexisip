#pragma once

#include <memory>

#include "service-server.hh"
#include <linphone++/linphone.hh>

using namespace std;
using namespace linphone;
using namespace flexisip;

namespace RegistrationEvent {
    class Server : public ServiceServer
        , public enable_shared_from_this<Server>
        , public CoreListener {
    public:
        static const string CONTENT_TYPE;

        Server (su_root_t *root);
        ~Server ();

        void onSubscribeReceived(
            const shared_ptr<Core> & lc,
            const shared_ptr<Event> & lev,
            const string & subscribeEvent,
            const shared_ptr<const Content> & body
        );

    protected:
        void _init () override;
        void _run () override;
        void _stop () override;

    private:
        class Init {
        public:
            Init();
        };

        shared_ptr<Core> mCore;
    };
}
