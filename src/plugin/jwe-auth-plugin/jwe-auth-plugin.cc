/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2010-2018  Belledonne Communications SARL, All rights reserved.

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

#include <array>
#include <dirent.h>
#include <fstream>
#include <unordered_map>

extern "C" {
	#include <jose/jose.h>
}

#include <flexisip/agent.hh>
#include <flexisip/module-auth.hh>
#include <flexisip/plugin.hh>

// =============================================================================

using namespace std;
using namespace flexisip;

namespace {
	constexpr int JweAuthPluginVersion = 1;
	constexpr char JweAuthPluginName[] = "JWE Authentification plugin";
	constexpr char JwkFileExtension[] = "jwk";
}

// =============================================================================
// Generic helpers.
// =============================================================================

template<typename... T>
static constexpr auto makeArray(T &&...values) -> array<
	typename decay<typename common_type<T...>::type>::type,
	sizeof...(T)
> {
	return array<
		typename decay<typename common_type<T...>::type>::type,
		sizeof...(T)
	>{ {forward<T>(values)...} };
}

static bool endsWith(const string &str, const string &suffix) {
	const string::size_type strSize = str.size();
	const string::size_type suffixSize = suffix.size();
	return strSize >= suffixSize && str.compare(strSize - suffixSize, suffixSize, suffix) == 0;
}

static vector<char> readFile(const string &path, bool *error = nullptr) {
	vector<char> buf;

	fstream stream(path, ios_base::in);
	if (stream.is_open()) {
		stream.exceptions(ios::failbit);
		try {
			stream.seekg(0, ios::end);
			const fstream::pos_type len(stream.tellg());

			stream.seekg(0, ios::beg);
			buf.resize(len);
			stream.read(buf.data(), len);

			if (error) *error = false;
			return buf;
		} catch (const ios_base::failure &e) {
			SLOGW << "Unable to read properly file (I/O error): `" << e.what() << "`.";
		} catch (const exception &e) {
			SLOGW << "Unable to read properly file: `" << e.what() << "`.";
		}
	} else
		SLOGW << "Unable to open: `" << path << "`.";

	if (error) *error = true;
	return buf;
}

static list<string> listFiles(const string &path, const string &suffix) {
	list<string> files;

	DIR *dirp = opendir(path.c_str());
	if (!dirp) {
		SLOGW << "Unable to open directory: `" << path << "` (" << strerror(errno) << ").";
		return files;
	}

	dirent *dirent;
	const string dotSuffix = "." + suffix;
	for (;;) {
		errno = 0;
		if (!(dirent = readdir(dirp))) {
			if (errno)
				SLOGW << "Unable to read directory: `" << path << "` (" << strerror(errno) << ").";
			break;
		}

		string file(dirent->d_name);
		if (file != "." && file != ".." && endsWith(file, dotSuffix))
			files.push_back(move(file));
	}

	closedir(dirp);

	return files;
}

// =============================================================================
// JSON helpers.
// =============================================================================

// Note:
// jwe => JSON Web Encryption
// jwk => JSON Web Key
// jwt => JSON Web Token

static json_t *convertToJson(const char *text, size_t len) {
	json_error_t error;
	json_t *root = json_loadb(text, len, 0, &error);
	if (root)
		return root;

	SLOGW << "Unable to convert to json, error line " << error.line << ": `" << error.text << "`.";
	return nullptr;
}

static bool isB64(const char *text, size_t len) {
	for (size_t i = 0; i < len; ++i)
		if (text[i] && !strchr(JOSE_B64_MAP, text[i]))
			return false;
	return true;
}

// =============================================================================
// JWE/JWT parser.
// =============================================================================

static json_t *parseJwe(const char *text) {
	const auto parts = makeArray("protected", "encrypted_key", "iv", "ciphertext", "tag");
	const size_t nParts = parts.size();

	json_auto_t *jwe = json_object();
	for (size_t i = 0, j = 0; j < nParts; ++j) {
		const char *separator = strchr(&text[i], '.');

		size_t len;
		if (separator)
			len = separator - &text[i];
		else if (j + 1 == nParts)
			len = strlen(&text[i]);
		else
			goto error;

		if (!isB64(&text[i], len))
			goto error;

		if (json_object_set_new(jwe, parts[j], json_stringn(&text[i], len)) < 0)
			goto error;

		i += len + 1;
	}

	return json_incref(jwe);

error:
	SLOGW << "Unable to parse JWE correctly.";
	return nullptr;
}

static json_t *decryptJwe(const char *text, const json_t *jwk) {
	json_auto_t *jwe = parseJwe(text);
	if (!jwe)
		return nullptr;

	size_t len = 0;
	char *jwtText = static_cast<char *>(jose_jwe_dec(nullptr, jwe, nullptr, jwk, &len));
	if (!jwtText)
		return nullptr;

	json_t *jwt = convertToJson(jwtText, len);
	free(jwtText);
	return jwt;
}

// =============================================================================
// Checkers.
// =============================================================================

static const char *checkJwtTime(json_t *jwt, int *timeout) {
	const time_t currentTime = time(nullptr);
	bool attrChecked = false;
	json_t *attrValue;

	*timeout = numeric_limits<int>::max();

	// 1. Check optional "exp" attr.
	if ((attrValue = json_object_get(jwt, "exp"))) {
		json_int_t expValue;

		if (json_typeof(attrValue) != JSON_INTEGER)
			return "Invalid exp attr, must be an integer";

		if (json_unpack(attrValue, "I", &expValue) < 0)
			return "Unable to extract exp attr";

		if (time_t(expValue) < currentTime)
			return "exp has expired";

		attrChecked = true;
		*timeout = int(time_t(expValue) - currentTime);
	}

	// 2. Not in the JSON Web Token RFC. Check Specific optional "exp_in" attr.
	if ((attrValue = json_object_get(jwt, "exp_in"))) {
		json_int_t expInValue;

		if (json_typeof(attrValue) != JSON_INTEGER)
			return "Invalid exp_in attr, must be an integer";

		if (json_unpack(attrValue, "I", &expInValue) < 0)
			return "Unable to extract exp_in attr";

		json_int_t iatValue;
		if (json_unpack(jwt, "{s:I}", "iat", &iatValue) < 0)
			return "Unable to extract iat attr, must be an integer and exists";

		if (time_t(iatValue) + expInValue < currentTime)
			return "exp_in has expired";

		attrChecked = true;
		*timeout = min(*timeout, int(time_t(iatValue) + expInValue - currentTime));
	}

	if (!attrChecked)
		return "exp and/or exp_in attr must exists";

	return nullptr;
}

// -----------------------------------------------------------------------------

static bool checkJwtAttrFromSipHeader(json_t *jwt, const sip_t *sip, const char *attrName, const char *sipHeaderName) {
	char *value = nullptr;
	bool soFarSoGood = false;
	if (json_unpack(jwt, "{s:s}", attrName, &value) == 0) {
		sip_unknown_t *header = ModuleToolbox::getCustomHeaderByName(sip, sipHeaderName);
		if (header && header->un_value)
			soFarSoGood = !strcmp(value, header->un_value);
	}
	return soFarSoGood;
}

// =============================================================================
// Plugin.
// =============================================================================

class JweAuth;

struct JweContext {
	~JweContext() {
		su_timer_destroy(timer);
	}

	JweAuth *self = nullptr;
	string key;
	su_timer_t *timer = nullptr;
	bool consumed = false;
};

class JweAuth : public Module {
public:
	JweAuth(Agent *agent) : Module(agent) {}

private:
	json_t *decryptJwe(const char *text) const;

	void onDeclare(GenericStruct *moduleConfig) override;
	void onLoad(const GenericStruct *moduleConfig) override;
	void onUnload() override;

	void onRequest(shared_ptr<RequestSipEvent> &ev) override;
	void onResponse(shared_ptr<ResponseSipEvent> &ev) override;

	void insertJweContext(string &&jweKey, const shared_ptr<JweContext> &jweContext, int timeout);
	static void removeJweContext(su_root_magic_t *magic, su_timer_t *timer, su_timer_arg_t *arg);

	list<json_t *> mJwks;

	string mJweCustomHeader;
	string mOidCustomHeader;
	string mAudCustomHeader;
	string mReqActCustomHeader;

	list<pair<const char *, const char *>> mCustomHeadersToCheck;

	unordered_map<string, shared_ptr<JweContext>> mJweContexts;
	std::weak_ptr<Authentication> mAuthModule;
};

namespace {
	ModuleInfo<JweAuth> JweAuthInfo(
		"JweAuth",
		"This module offers the possibility to use JSON Web Encryption tokens.",
		{ "Authentication" },
		ModuleInfoBase::ModuleOid::Plugin
	);
}

FLEXISIP_DECLARE_PLUGIN(JweAuthInfo, JweAuthPluginName, JweAuthPluginVersion);

// -----------------------------------------------------------------------------

json_t *JweAuth::decryptJwe(const char *text) const {
	for (const json_t *jwk : mJwks) {
		json_t *jwt = ::decryptJwe(text, jwk);
		if (jwt)
			return jwt;
	}
	return nullptr;
};

void JweAuth::onDeclare(GenericStruct *moduleConfig) {
	ConfigItemDescriptor configs[] = { {
		String, "jwks-dir",
		"Path to the directory where JSON Web Key (JWK) can be found."
		" Any JWK must be put into a file with the `.jwk` suffix.",
		"/etc/flexisip/jwk/"
	}, {
		String, "jwe-custom-header", "The name of the JWE token custom header.", "X-token-jwe"
	}, {
		String, "oid-custom-header", "The name of the oid custom header.", "X-token-oid"
	}, {
		String, "aud-custom-header", "The name of the aud custom header.", "X-token-aud"
	}, {
		String, "req-act-custom-header", "The name of the request action custom header.", "X-token-req_act"
	}, config_item_end };
	moduleConfig->addChildrenValues(configs);
}

void JweAuth::onLoad(const GenericStruct *moduleConfig) {
	const string jwksDirectory = moduleConfig->get<ConfigString>("jwks-dir")->read();
	for (const string &file : listFiles(jwksDirectory, JwkFileExtension)) {
		bool error;
		const string path(jwksDirectory + "/" + file);
		const vector<char> buf(readFile(path, &error));
		if (!error) {
			json_t *jwk = convertToJson(buf.data(), buf.size());
			if (jwk) {
				SLOGI << "Registering JWK `" << path << "`";
				mJwks.push_back(jwk);
			}
		}
	}

	mJweCustomHeader = moduleConfig->get<ConfigString>("jwe-custom-header")->read();
	mOidCustomHeader = moduleConfig->get<ConfigString>("oid-custom-header")->read();
	mAudCustomHeader = moduleConfig->get<ConfigString>("aud-custom-header")->read();
	mReqActCustomHeader = moduleConfig->get<ConfigString>("req-act-custom-header")->read();

	mCustomHeadersToCheck = {
		{ "oid", mOidCustomHeader.c_str() },
		{ "aud", mAudCustomHeader.c_str() },
		{ "req_act", mReqActCustomHeader.c_str() }
	};
	mAuthModule = dynamic_pointer_cast<Authentication>(getAgent()->findModule("Authentication"));
}

void JweAuth::onUnload() {
	for (json_t *jwk : mJwks)
		json_decref(jwk);
}

void JweAuth::onRequest(shared_ptr<RequestSipEvent> &ev) {
	const sip_t *sip = ev->getSip();
	const sip_method_t method = sip->sip_request->rq_method;
	if (method != sip_method_invite && method != sip_method_message)
		return;

	if (auto authModule = mAuthModule.lock()){
		// Allow requests coming from trusted peers.
		if (authModule->isTrustedPeer(ev)) return;
	}else{
		LOGE("Authentication module not found, trusted peers are unknown.");
	}
	
	const char *error = nullptr;
	shared_ptr<JweContext> jweContext;
	const sip_unknown_t *header;
	
	if (!(header = ModuleToolbox::getCustomHeaderByName(sip, mOidCustomHeader.c_str())) || !header->un_value)
		error = "Unable to find oid incoming subject header";
	else if (!ev->findIncomingSubject(header->un_value))
		error = "Unable to match oid";
	else if (!(header = ModuleToolbox::getCustomHeaderByName(sip, mJweCustomHeader.c_str())) || !header->un_value)
		error = "No JWE token";
	else {
		string jweKey(header->un_value);

		auto it = mJweContexts.find(jweKey);
		if (it == mJweContexts.end()) {
			int timeout;
			json_auto_t *jwt = decryptJwe(header->un_value);
			if (!jwt)
				error = "Unable to decrypt JWE";
			else if (!(error = checkJwtTime(jwt, &timeout))) {
				for (const auto &data : mCustomHeadersToCheck)
					if (!checkJwtAttrFromSipHeader(jwt, sip, data.first, data.second)) {
						error = "JWT check attrs failed";
						break;
					}

				if (!error) {
					jweContext = make_shared<JweContext>();
					insertJweContext(move(jweKey), jweContext, timeout);
				}
			}
		} else {
			jweContext = it->second;
			if (jweContext->consumed)
				error = "JWE already consumed";
		}
	}

	if (error) {
		SLOGW << "Rejecting request because: `" << error << "`.";
		ev->reply(403, error, SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
	} else {
		shared_ptr<IncomingTransaction> incomingTransaction = ev->createIncomingTransaction();
		incomingTransaction->setProperty(getModuleName(), jweContext);
	}
}

void JweAuth::onResponse(shared_ptr<ResponseSipEvent> &ev) {
	int status = ev->getMsgSip()->getSip()->sip_status->st_status;
	if (status == 401 || status == 407)
		return;

	shared_ptr<IncomingTransaction> incomingTransaction(dynamic_pointer_cast<IncomingTransaction>(ev->getIncomingAgent()));
	if (!incomingTransaction)
		return;

	shared_ptr<JweContext> jweContext(incomingTransaction->getProperty<JweContext>(getModuleName()));
	if (jweContext)
		jweContext->consumed = true;
}

void JweAuth::insertJweContext(string &&jweKey, const shared_ptr<JweContext> &jweContext, int timeout) {
	auto* timer = su_timer_create(mAgent->getRoot()->getTask(), 0);
	jweContext->self = this;
	jweContext->key = jweKey;
	jweContext->timer = timer;

	mJweContexts.insert({ move(jweKey), jweContext });

	if (timeout > 0) {
		timeout *= 1000;
		if (timeout < 0)
			timeout = numeric_limits<int>::max();
	}
	su_timer_set_interval(timer, removeJweContext, jweContext.get(), timeout);
}

void JweAuth::removeJweContext(su_root_magic_t *, [[maybe_unused]] su_timer_t *timer, su_timer_arg_t *arg) {
	JweContext *jweContext = static_cast<JweContext *>(arg);
	su_timer_destroy(jweContext->timer);
	jweContext->timer = nullptr;
	jweContext->self->mJweContexts.erase(jweContext->key);
}
