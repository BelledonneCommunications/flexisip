/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include <fstream>
#include <iostream>
#include <sstream>

#include <belr/abnf.h>
#include <belr/grammarbuilder.h>

#ifdef HAVE_CONFIG_H
#include "flexisip-config.h"
#endif

#include "utils/digest.hh"
#include "utils/string-utils.hh"

#include "authdb.hh"

using namespace ::belr;
using namespace std;

namespace flexisip {

void FileAuthDb::declareConfig(GenericStruct* mc) {
	ConfigItemDescriptor items[] = {
	    {String, "file-path",
	     "Path of the file in which user credentials are stored.\n"
	     "The file must start with 'version:1' as the first line, and then contains lines in the form of:\n"
	     "user@domain clrtxt:clear-text-password md5:md5-password sha256:sha256-password ;\n"
	     "For example: \n"
	     "bellesip@sip.linphone.org clrtxt:secret ;\n"
	     "bellesip@sip.linphone.org md5:97ffb1c6af18e5687bf26cdf35e45d30 ;\n"
	     "bellesip@sip.linphone.org clrtxt:secret md5:97ffb1c6af18e5687bf26cdf35e45d30 "
	     "sha256:d7580069de562f5c7fd932cc986472669122da91a0f72f30ef1b20ad6e4f61a3 ;",
	     ""},

	    // Deprecated paramters
	    {String, "datasource",
	     "Odbc connection string to use for connecting to database. "
	     "ex1: DSN=myodbc3; where 'myodbc3' is the datasource name. "
	     "ex2: DRIVER={MySQL};SERVER=host;DATABASE=db;USER=user;PASSWORD=pass;OPTION=3; for a DSN-less connection. "
	     "ex3: /etc/flexisip/passwd; for a file containing user credentials in clear-text, md5 or sha256. "
	     "The file must start with 'version:1' as the first line, and then contains lines in the form of:\n"
	     "user@domain clrtxt:clear-text-password md5:md5-password sha256:sha256-password ;\n"
	     "For example: \n"
	     "bellesip@sip.linphone.org clrtxt:secret ;\n"
	     "bellesip@sip.linphone.org md5:97ffb1c6af18e5687bf26cdf35e45d30 ;\n"
	     "bellesip@sip.linphone.org clrtxt:secret md5:97ffb1c6af18e5687bf26cdf35e45d30 "
	     "sha256:d7580069de562f5c7fd932cc986472669122da91a0f72f30ef1b20ad6e4f61a3 ;",
	     ""},
	    config_item_end};
	mc->addChildrenValues(items);
	auto* datasourceParam = mc->get<ConfigString>("datasource");
	datasourceParam->setDeprecated(
	    {"2020-01-31", "2.0.0",
	     "This parameter has been renamed into 'file-path' and has no effect if the latter is set.\n"
	     "Please use 'file-path' instead of this parameter."});
	mc->get<ConfigString>("file-path")->setFallback(*datasourceParam);
}

void FileAuthDb::parsePasswd(const vector<passwd_algo_t>& srcPasswords,
                             const std::string& user,
                             const std::string& domain,
                             std::vector<passwd_algo_t>& destPasswords) {
	destPasswords.reserve(srcPasswords.size());
	for (const auto& passwd : srcPasswords) {
		if (passwd.algo == "md5") destPasswords.emplace_back(StringUtils::toLower(passwd.pass), "MD5");
		else if (passwd.algo == "sha256") destPasswords.emplace_back(StringUtils::toLower(passwd.pass), "SHA-256");
		else if (passwd.algo == "clrtxt") {
			// Creates pass-md5, pass-sha256 if there is clrtxt pass
			auto input = user + ":" + domain + ":" + passwd.pass;
			destPasswords.clear();
			destPasswords.emplace_back(passwd.pass, "CLRTXT");
			destPasswords.emplace_back(Md5().compute<string>(input), "MD5");
			destPasswords.emplace_back(Sha256().compute<string>(input), "SHA-256");
		}
	}
}

FileAuthDb::FileAuthDb() : AuthDbBackend(*ConfigManager::get()->getRoot()) {
	GenericStruct* cr = ConfigManager::get()->getRoot();
	GenericStruct* ma = cr->get<GenericStruct>("module::Authentication");

	mLastSync = 0;
	mFileString = ma->get<ConfigString>("file-path")->read();

	sync();
}

void FileAuthDb::getUserWithPhoneFromBackend(const std::string& phone,
                                             const std::string& domain,
                                             AuthDbListener* listener) {
	AuthDbResult res = AuthDbResult::PASSWORD_NOT_FOUND;
	if (mLastSync == 0) {
		sync();
	}
	std::string user;
	if (getCachedUserWithPhone(phone, domain, user) == VALID_PASS_FOUND) {
		res = AuthDbResult::PASSWORD_FOUND;
	}
	if (listener) listener->onResult(res, user);
}

void FileAuthDb::getPasswordFromBackend(const std::string& id,
                                        const std::string& domain,
                                        const std::string& authid,
                                        AuthDbListener* listener) {
	AuthDbResult res = AuthDbResult::PASSWORD_NOT_FOUND;
	time_t now = getCurrentTime();

	if (difftime(now, mLastSync) >= mCacheExpire) {
		sync();
	}

	string key(createPasswordKey(id, authid));

	vector<passwd_algo_t> passwd;
	if (getCachedPassword(key, domain, passwd) == VALID_PASS_FOUND) {
		res = AuthDbResult::PASSWORD_FOUND;
	}
	if (listener) listener->onResult(res, passwd);
}

shared_ptr<belr::Parser<shared_ptr<FileAuthDbParserElem>>> FileAuthDb::setupParser() {
	string grammarFile = string(BELR_GRAMMARS_DIR) + "/authdb-file-grammar";
	shared_ptr<Grammar> grammar = make_shared<Grammar>(grammarFile);

	if (grammar->load(grammarFile) == -1) {
		LOGF("Could not load grammar for authdb-file from '%s'", grammarFile.c_str());
		return nullptr;
	}

	Parser<shared_ptr<FileAuthDbParserElem>>* parser = new Parser<shared_ptr<FileAuthDbParserElem>>(grammar);

	parser->setHandler("password-file", make_fn<FileAuthDbParserRoot>())
	    ->setCollector("version-number", make_sfn(&FileAuthDbParserRoot::setVersion))
	    ->setCollector("auth-line", make_sfn(&FileAuthDbParserRoot::addAuthLine));

	parser->setHandler("auth-line", make_fn<FileAuthDbParserUserLine>())
	    ->setCollector("user", make_sfn(&FileAuthDbParserUserLine::setUser))
	    ->setCollector("domain", make_sfn(&FileAuthDbParserUserLine::setDomain))
	    ->setCollector("pass-algo", make_sfn(&FileAuthDbParserUserLine::addPassword))
	    ->setCollector("user-id", make_sfn(&FileAuthDbParserUserLine::setUserId))
	    ->setCollector("phone", make_sfn(&FileAuthDbParserUserLine::setPhone));

	parser->setHandler("pass-algo", make_fn<FileAuthDbParserPassword>())
	    ->setCollector("algo", make_sfn(&FileAuthDbParserPassword::setAlgo))
	    ->setCollector("password", make_sfn(&FileAuthDbParserPassword::setPassword));
	return shared_ptr<Parser<shared_ptr<FileAuthDbParserElem>>>(parser);
}

/*
   File parsing using belr with custom grammar for authdb file
*/
void FileAuthDb::sync() {
	LOGD("Syncing password file");
	GenericStruct* cr = ConfigManager::get()->getRoot();
	GenericStruct* ma = cr->get<GenericStruct>("module::Authentication");
	list<string> domains = ma->get<ConfigStringList>("auth-domains")->read();

	mLastSync = getCurrentTime();

	if (mFileString.empty()) {
		LOGF("'file' authentication backend was requested but no path specified in 'file-path'.");
		return;
	}

	auto parser = setupParser();
	if (!parser) {
		LOGF("Failed to create authdb file parser.");
		return;
	}
	LOGD("Opening file %s", mFileString.c_str());

	std::ifstream ifs(mFileString);
	if (!ifs.is_open()) {
		LOGF("Failed to open authdb file %s", mFileString.c_str());
		return;
	}
	stringstream sstr;
	sstr << ifs.rdbuf();
	string fileContent = sstr.str();

	if (sstr.bad() || sstr.fail()) {
		LOGF("Failed to read from authdb file '%s'", mFileString.c_str());
		return;
	}

	size_t parsedSize = 0;
	shared_ptr<FileAuthDbParserElem> ret = parser->parseInput("password-file", fileContent, &parsedSize);

	shared_ptr<FileAuthDbParserRoot> pwdFile = dynamic_pointer_cast<FileAuthDbParserRoot>(ret);
	if (pwdFile == nullptr) {
		LOGF("Failed to parse authdb file.");
		return;
	}
	if (parsedSize < fileContent.size()) {
		LOGF("Parsing of Authdb file ended prematurely at char %d.", (int)parsedSize);
		return;
	}

	// Only version == 1 is supported
	if (pwdFile->getVersion() != "1") {
		LOGF("Version '%s' is not supported for file %s", pwdFile->getVersion().c_str(), mFileString.c_str());
		return;
	}

	LOGD("AuthDb file succesfully parsed: \n%s", fileContent.c_str());

	auto authLines = pwdFile->getAuthLines();
	for (auto it = authLines.begin(); it != authLines.end(); ++it) {
		vector<passwd_algo_t> destPasswords;
		shared_ptr<FileAuthDbParserUserLine> userLine = *it;

		// Handle spaces in user name (encoded as %20 in authdb-file). See also 'createPasswordkey'
		string unescapedUser = urlUnescape(userLine->getUser());

		// user-id defaults to user name if unspecified
		if (userLine->getUserId().empty()) {
			userLine->setUserId(userLine->getUser());
		}
		cacheUserWithPhone(userLine->getPhone(), userLine->getDomain(), userLine->getUser());
		parsePasswd(userLine->getPasswords(), unescapedUser, userLine->getDomain(), destPasswords);

		if (find(domains.begin(), domains.end(), userLine->getDomain()) != domains.end()) {
			string key(createPasswordKey(userLine->getUser(), userLine->getUserId()));
			cachePassword(key, userLine->getDomain(), destPasswords, mCacheExpire);
		} else if (find(domains.begin(), domains.end(), "*") != domains.end()) {
			string key(createPasswordKey(userLine->getUser(), userLine->getUserId()));
			cachePassword(key, userLine->getDomain(), destPasswords, mCacheExpire);
		} else {
			LOGW("Domain '%s' is not handled by Authentication module", userLine->getDomain().c_str());
		}
	}
	LOGD("Syncing done");
}

} // namespace flexisip
