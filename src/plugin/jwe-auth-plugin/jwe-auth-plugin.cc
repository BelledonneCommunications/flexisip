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

#include <dirent.h>
#include <fstream>
#include <unordered_map>

extern "C" {
	#include <jose/jose.h>
}

#include "agent.hh"
#include "plugin.hh"

// =============================================================================

using namespace std;

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
	>{ forward<T>(values)... };
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

template<typename T>
struct TypeToJsonFormat {};

template<>
struct TypeToJsonFormat<int> {
	static constexpr char value = 'i';
};

template<>
struct TypeToJsonFormat<json_int_t> {
	static constexpr char value = 'I';
};

template<typename T>
static T extractJsonValue(json_t *jwt, const char *attrName, bool *error = nullptr) {
	constexpr char format[] = { '{', 's', ':', TypeToJsonFormat<T>::value, '}', '\0' };

	T value{};
	if (json_unpack(jwt, format, attrName, &value) < 0) {
		SLOGW << "Unable to unpack value: `" << attrName << "`.";
		if (error) *error = true;
	} else if (error)
		*error = false;

	return value;
}

template<typename T>
static T extractJsonOptionalValue(json_t *jwt, const char *attrName, const T &defaultValue, bool *error = nullptr) {
	constexpr char format[] = { TypeToJsonFormat<T>::value, '\0' };

	T value(defaultValue);
	json_t *valueObject;
	if (json_unpack(jwt, "{s?o}", attrName, &valueObject) < 0) {
		SLOGW << "Unable to unpack optional object: `" << attrName << "`.";
		if (error) *error = true;
	} else if (valueObject && json_unpack(valueObject, format, &value) < 0) {
		SLOGW << "Unable to unpack existing value: `" << attrName << "`.";
		if (error) *error = true;
	} else if (error)
		*error = false;

	return value;
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
	if (!jwtText) {
		SLOGW << "Unable to decrypt JWE.";
		return nullptr;
	}

	json_t *jwt = convertToJson(jwtText, len);
	free(jwtText);
	return jwt;
}

static bool checkJwtTime(json_t *jwt, int *timeout = nullptr) {
	const time_t currentTime = time(nullptr);
	bool error;

	if (timeout)
		*timeout = numeric_limits<int>::max();

	// Check optional "exp" attr.
	const json_int_t expValue = extractJsonOptionalValue<json_int_t>(jwt, "exp", -1, &error);
	if (error)
		return false;
	if (expValue != -1 && time_t(expValue) < currentTime) {
		SLOGW << "JWT (exp) has expired.";
		return false;
	}
	if (timeout)
		*timeout = int(time_t(expValue) - currentTime);

	// Not in the JSON Web Token RFC. Check Specific optional "exp_in" attr.
	const int expInValue = extractJsonOptionalValue<int>(jwt, "exp_in", -1, &error);
	if (error)
		return false;
	if (expInValue != -1) {
		json_int_t iatValue = extractJsonValue<int>(jwt, "iat", &error);
		if (error) {
			SLOGW << "`exp_in` can be used only if `iat` exists.";
			return false;
		}
		if (time_t(iatValue) + expInValue < currentTime) {
			SLOGW << "JWT (exp_in) has expired.";
			return false;
		}
		if (timeout)
			*timeout = min(*timeout, int(time_t(iatValue) + expInValue - currentTime));
	}

	return true;
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
	~JweAuth() { onUnload(); }

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

	static ModuleInfo<JweAuth> sInfo;
};

ModuleInfo<JweAuth> JweAuth::sInfo(
	"JweAuth",
	"This module offers the possibility to use JSON Web Encryption tokens.",
	ModuleInfoBase::ModuleOid::Plugin
);

FLEXISIP_DECLARE_PLUGIN(JweAuth, JweAuthPluginName, JweAuthPluginVersion);

// -----------------------------------------------------------------------------

static bool checkJwtAttrFromSipHeader(json_t *jwt, const sip_t *sip, const char *attrName, const char *sipHeaderName) {
	char *value = nullptr;
	bool soFarSoGood = false;
	if (json_unpack(jwt, "{s:s}", attrName, &value) == 0) {
		sip_unknown_t *header = ModuleToolbox::getCustomHeaderByName(sip, sipHeaderName);
		if (header && header->un_value)
			soFarSoGood = !strcmp(value, header->un_value);
	}

	if (!soFarSoGood)
		SLOGW << "`" << attrName << "` value not equal to `" << sipHeaderName << "`.";

	free(value);
	return soFarSoGood;
}

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
		String, "jwe-custom-header", "The name of the JWE token custom header.", "X-token"
	}, {
		String, "oid-custom-header", "The name of the oid custom header.", "X-token-oid"
	}, {
		String, "aud-custom-header", "The name of the aud custom header.", "X-token-aud"
	}, {
		String, "req-act-custom-header", "The name of the request action custom header.", "X-token-req_act"
	}, {
		config_item_end
	} };
	moduleConfig->addChildrenValues(configs);
}

void JweAuth::onLoad(const GenericStruct *moduleConfig) {
	const string jwksDirectory = moduleConfig->get<ConfigString>("jwks-dir")->read();
	for (const string &file : listFiles(jwksDirectory, JwkFileExtension)) {
		bool error;
		const vector<char> buf(readFile(jwksDirectory + "/" + file, &error));
		if (!error) {
			json_t *jwk = convertToJson(buf.data(), buf.size());
			if (jwk)
				mJwks.push_back(jwk);
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
}

void JweAuth::onUnload() {
	for (json_t *jwk : mJwks)
		json_decref(jwk);
}

void JweAuth::onRequest(shared_ptr<RequestSipEvent> &ev) {
	const char *error = nullptr;
	const sip_t *sip = ev->getSip();
	shared_ptr<JweContext> jweContext;

	const sip_unknown_t *header = ModuleToolbox::getCustomHeaderByName(sip, mOidCustomHeader.c_str());
	if (!header || !header->un_value || !ev->findIncomingSubject(header->un_value))
		error = "Unable to find oid incoming subject";
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
			else if (!checkJwtTime(jwt, &timeout))
				error = "JWT check time failed";
			else {
				for (const auto &data : mCustomHeadersToCheck)
					if (!checkJwtAttrFromSipHeader(jwt, sip, data.first, data.second))
						error = "JWT check attrs failed";

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
		ev->reply(400, error, SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
	} else {
		shared_ptr<IncomingTransaction> incomingTransaction = ev->createIncomingTransaction();
		incomingTransaction->setProperty(getModuleName(), jweContext);
	}
}

void JweAuth::onResponse(shared_ptr<ResponseSipEvent> &ev) {
	if (ev->getMsgSip()->getSip()->sip_status->st_status != 407)
		static_pointer_cast<IncomingTransaction>(
			ev->getIncomingAgent()
		)->getProperty<JweContext>(getModuleName())->consumed = true;
}

void JweAuth::insertJweContext(string &&jweKey, const shared_ptr<JweContext> &jweContext, int timeout) {
	su_timer_t *timer = su_timer_create(su_root_task(mAgent->getRoot()), 0);
	jweContext->self = this;
	jweContext->key = jweKey;
	jweContext->timer = timer;

	mJweContexts.insert({ move(jweKey), jweContext });
	su_timer_set_interval(timer, removeJweContext, jweContext.get(), timeout * 1000);
}

void JweAuth::removeJweContext(su_root_magic_t *, su_timer_t *timer, su_timer_arg_t *arg) {
	JweContext *jweContext = static_cast<JweContext *>(arg);
	su_timer_destroy(jweContext->timer);
	jweContext->timer = nullptr;
	jweContext->self->mJweContexts.erase(jweContext->key);
}
