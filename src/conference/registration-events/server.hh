#include <linphone++/linphone.hh>

using namespace std;
using namespace linphone;

namespace RegistrationEvent {
    class Server : public CoreListener {
    public:
        static const string CONTENT_TYPE;

        void onSubscribeReceived(
            const shared_ptr<Core> & lc,
            const shared_ptr<Event> & lev,
            const string & subscribeEvent,
            const shared_ptr<const Content> & body
        );
    };
}
