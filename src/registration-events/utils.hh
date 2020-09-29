#include "../conference/conference-server.hh"
#include <linphone++/linphone.hh>
#include <flexisip/registrardb.hh>

using namespace std;
using namespace linphone;

namespace flexisip {

namespace RegistrationEvent {
    class Utils {
    public:
        static int getMaskFromSpecs(const string &mask);
        static bool isContactCompatible(const ConferenceServer & server, const shared_ptr<ChatRoom> &cr, const string &specs);
        static string getDeviceName(const shared_ptr<ExtendedContact> &ec);
    };
}

}
