#pragma once

#include <linphone++/linphone.hh>
#include <flexisip/registrardb.hh>

using namespace std;
using namespace linphone;

namespace flexisip {

namespace RegistrationEvent {
namespace Registrar {
	
class Listener : public ContactRegisteredListener, public ContactUpdateListener {
public:
	Listener(const shared_ptr<linphone::Event> &lev);
	void onRecordFound(const shared_ptr<Record> &r) override;
	void onError() override {}
	void onInvalid() override {}
	void onContactRegistered(const shared_ptr<Record> &r, const string &uid) override;
	void onContactUpdated(const shared_ptr<ExtendedContact> &ec) override {}
private:
	const shared_ptr<linphone::Event> mEvent;
	void processRecord(const shared_ptr<Record> &r, const string &uidOfFreshlyRegistered);
	// version, previouscontacts
};

}
}

}
