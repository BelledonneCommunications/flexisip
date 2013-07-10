#include "recordserializer.hh"
#include "registrardb-redis.hh"
#include "common.hh"

#include <algorithm>

#include "configmanager.hh"

#include <hiredis/hiredis.h>

#include <sofia-sip/sip_protos.h>

#include <memory>

using namespace std;

bool sUseSyslog;

struct DumpListener : public RegistrarDbListener {
public:
	virtual void onRecordFound(Record *r) {
		cout << *r << endl;
	}
	virtual void onError() {
		cout << "error" << endl;
	}
	virtual void onInvalid() {
		cout << "invalid" << endl;
	}
};

static void usage(const char *app) {
	cout << app << " -h host -p port --verbose -a auth -s serializer sip_uri " << endl;
}
int main(int argc, char **argv) {
	sUseSyslog = false;
	bool debug=false;
	RedisParameters params;
	params.port=6379;
	params.timeout = 2000;
	string serializer_name = "protobuf";
	string curl;

	if (argc < 5) {	usage(argv[0]); return -1; }
	for (int i=1; i < argc; ++i) {
		bool finished = i == argc -1;
		if (0 == strcasecmp("--help", argv[i]) ||
			(0 == strcasecmp("-h", argv[i]) && finished)) {
			usage(argv[0]);
			return -1;
		} else if (0 == strcmp("--debug", argv[i])) {
			debug=true;
		} else if (0 == strcmp("-h", argv[i]) && !finished) {
			params.domain = argv[++i];
		} else if (0 == strcmp("-p", argv[i]) && !finished) {
			params.port = atoi(argv[++i]);
		} else if (0 == strcmp("-a", argv[i]) && !finished) {
			params.auth = argv[++i];
		} else if (0 == strcmp("-s", argv[i]) && !finished) {
			serializer_name = argv[++i];
			if (serializer_name != "protobuf" && serializer_name != "c" && serializer_name != "json") {
				cerr << "invalid serializer : " << serializer_name << endl;
				return -1;
			}
		} else if (finished) {
			curl = argv[i];
		} else {
			usage(argv[0]);
			return -1;
		}
	}
	flexisip::log::preinit(sUseSyslog, debug);
	flexisip::log::initLogs(sUseSyslog, debug);
	flexisip::log::updateFilter("%Severity% >= debug");

	Record::sLineFieldNames = {"line"};
	Record::sMaxContacts = 10;

	auto serializer = unique_ptr<RecordSerializer>(RecordSerializer::create(serializer_name));
	auto registrardb = new RegistrarDbRedisSync("localhost", serializer.get(), params);

	su_home_t home;
	su_home_init(&home);
	auto url = url_format(&home,curl.c_str());
	auto listener = make_shared<DumpListener>();
	registrardb->fetch(url, listener);
	
	su_home_destroy(&home);
	
}