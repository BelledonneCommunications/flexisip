#include <linphone++/linphone.hh>
#include <iostream>

using namespace std;
using namespace linphone;

namespace RegistrationEvent {
    class Client : public CoreListener {
    public:
        Client(
            const shared_ptr<ChatRoom> &chatRoom,
            const shared_ptr<const Address> to);
        void subscribe();
        void onNotifyReceived(
            const shared_ptr<Core> & lc,
            const shared_ptr<linphone::Event> & lev,
            const string & notifiedEvent,
            const shared_ptr<const Content> & body
        ) override;
        bool notifyReceived = false;
    private:
        shared_ptr<Event> subscribeEvent;
        const shared_ptr<ChatRoom> &chatRoom;
        const shared_ptr<const Address> to;
    };
}