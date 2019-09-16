/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2010-2015  Belledonne Communications SARL, All rights reserved.

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU Affero General Public License as
	published by the Free Software Foundation, either version 3 of the
	License, or (at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU Affero General Public License for more details.

	You should have received a copy of the GNU Affero General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <fstream>
#include <iostream>
#include <sstream>

#include <belr/abnf.h>
#include <belr/grammarbuilder.h>

#ifdef HAVE_CONFIG_H
#include "flexisip-config.h"
#endif

#include "authdb.hh"
#include "utils/digest.hh"

using namespace::belr;
using namespace std;

namespace flexisip {

void FileAuthDb::parsePasswd(const vector<passwd_algo_t> &srcPasswords, const string &user, const string &domain, vector<passwd_algo_t> &destPasswords) {
	// Creates pass-md5, pass-sha256 if there is clrtxt pass
	for (const auto &passwd : srcPasswords) {
		if (passwd.algo == "clrtxt") {
			passwd_algo_t clrtxt, md5, sha256;
			clrtxt.pass = passwd.pass;
			clrtxt.algo = "CLRTXT";
			destPasswords.push_back(clrtxt);

			string input;
			input = user+":"+domain+":"+clrtxt.pass;

			md5.pass = Md5().compute<string>(input);
			md5.algo = "MD5";
			destPasswords.push_back(md5);

			sha256.pass = Sha256().compute<string>(input);
			sha256.algo = "SHA-256";
			destPasswords.push_back(sha256);
			return;
		}
	}
	for (const auto &passwd : srcPasswords) {
		if (passwd.algo == "md5") {
			passwd_algo_t md5;
			md5.pass = passwd.pass;
			md5.algo = "MD5";
			destPasswords.push_back(md5);
		}
		if (passwd.algo == "sha256") {
			passwd_algo_t sha256;
			sha256.pass = passwd.pass;
			sha256.algo = "SHA-256";
			destPasswords.push_back(sha256);
		}
	}
}

FileAuthDb::FileAuthDb() {
	GenericStruct *cr = GenericManager::get()->getRoot();
	GenericStruct *ma = cr->get<GenericStruct>("module::Authentication");

	mLastSync = 0;
	mFileString = ma->get<ConfigString>("datasource")->read();
	sync();
}

void FileAuthDb::getUserWithPhoneFromBackend(const std::string &phone, const std::string &domain, AuthDbListener *listener) {
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

void FileAuthDb::getPasswordFromBackend(const std::string &id, const std::string &domain,
					const std::string &authid, AuthDbListener *listener) {
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

	Parser<shared_ptr<FileAuthDbParserElem>> *parser = new Parser<shared_ptr<FileAuthDbParserElem>>(grammar);

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
	GenericStruct *cr = GenericManager::get()->getRoot();
	GenericStruct *ma = cr->get<GenericStruct>("module::Authentication");
	list<string> domains = ma->get<ConfigStringList>("auth-domains")->read();

	mLastSync = getCurrentTime();

	if (mFileString.empty()) {
		LOGF("'file' authentication backend was requested but no path specified in datasource.");
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

	if (parsedSize < fileContent.size()) {
		LOGF("Failed to parse authdb file. Parsing unexpectedly stopped at char: %d", (int)parsedSize);
		return;
	}
	shared_ptr<FileAuthDbParserRoot> pwdFile = dynamic_pointer_cast<FileAuthDbParserRoot>(ret);

	//Only version == 1 is supported
	if (pwdFile->getVersion() != "1") {
		LOGF("Version '%s' is not supported for file %s", pwdFile->getVersion().c_str(), mFileString.c_str());
		return;
	}

	auto authLines = pwdFile->getAuthLines();
	for (auto it = authLines.begin(); it != authLines.end(); ++it) {
		vector<passwd_algo_t> destPasswords;
		shared_ptr<FileAuthDbParserUserLine> userLine = *it;

		//Handle spaces in user name (encoded as %20 in authdb-file). See also 'createPasswordkey'
		string unescapedUser = urlUnescape(userLine->getUser());

		//user-id defaults to user name if unspecified
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
