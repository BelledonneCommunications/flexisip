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
		if (r) cout << *r << endl;
	}
	virtual void onError() {
		cout << "error" << endl;
	}
	virtual void onInvalid() {
		cout << "invalid" << endl;
	}
};

static void usage(const char *app) {
	cout << app << " -h host -p port --debug -a auth -s serializer sip_uri " << endl;
}

struct CTArgs {
	bool debug;
	RedisParameters redis;
	string serializer;
	string url;

	CTArgs() {
		debug = false;
		redis.port=6379;
		redis.timeout = 2000;
		redis.domain = "sip";
		serializer = "protobuf";
	}

	void parse(int argc, char **argv) {
		#define EQ0(i, name) (strcmp(name, argv[ i ]) == 0)
		#define EQ1(i, name) (strcmp(name, argv[ i ]) == 0 && argc > i)
		for (int i = 1; i < argc; ++i) {
			if (EQ0(i, "--debug")) {
				debug = true;
			} else if (EQ0(i, "--help") || EQ0(i, "-h")) {
				usage(*argv);
				exit(0);
			}  else if (EQ1(i, "-p")) {
				redis.port = atoi(argv[++i]);
			}  else if (EQ1(i, "-h")) {
				redis.domain = argv[++i];
			}  else if (EQ1(i, "-a")) {
				redis.auth = argv[++i];
			} else if (EQ1(i, "-s")) {
				serializer = argv[++i];
				if (serializer != "protobuf" && serializer != "c" && serializer != "json") {
					cerr << "invalid serializer : " << serializer << endl;
					exit(-1);
				}
			} else {
				url = argv[i++];
				if (argc > i) {
					cerr << "? arg" << i << " " << argv[i] << endl;
					usage(*argv);
					exit(-1);
				}
			}
		}
		if (url.empty()) {
			cerr << "specify aor" << endl;
			usage(*argv);
			exit(-1);
		}
	}
};


int main(int argc, char **argv) {
	sUseSyslog = false;
	CTArgs args; args.parse(argc, argv);

	flexisip::log::preinit(sUseSyslog, args.debug);
	flexisip::log::initLogs(sUseSyslog, args.debug);
	flexisip::log::updateFilter("%Severity% >= debug");

	Record::sLineFieldNames = {"line"};
	Record::sMaxContacts = 10;

	auto serializer = unique_ptr<RecordSerializer>(RecordSerializer::create(args.serializer));
	auto registrardb = new RegistrarDbRedisSync("localhost", serializer.get(), args.redis);

	su_home_t home;
	su_home_init(&home);
	auto url = url_format(&home,args.url.c_str());
	auto listener = make_shared<DumpListener>();
	registrardb->fetch(url, listener);
	
	su_home_destroy(&home);
	
}