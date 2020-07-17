#include "../conference-server.hh"
#include <linphone++/linphone.hh>
#include <iostream>

using namespace std;
using namespace linphone;
using namespace flexisip;

namespace RegistrationEvent {
    class Client : public CoreListener
        , public enable_shared_from_this<Client> {
    public:
        Client(
            const ConferenceServer &server,
            const shared_ptr<ChatRoom> &chatRoom,
            const shared_ptr<const Address> to);
        ~Client ();
        void subscribe();
        void onNotifyReceived(
            const shared_ptr<Core> & lc,
            const shared_ptr<linphone::Event> & lev,
            const string & notifiedEvent,
            const shared_ptr<const Content> & body
        ) override;
        bool notifyReceived = false;
    private:
        shared_ptr<linphone::Event> mSubscribeEvent;
        const ConferenceServer & mServer;
        shared_ptr<ChatRoom> mChatRoom;
        shared_ptr<const Address> mTo;
    };
}