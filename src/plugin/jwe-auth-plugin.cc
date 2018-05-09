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

#include <array>
#include <cstring>
#include <dirent.h>
#include <fstream>
#include <iostream>
#include <list>
#include <string>
#include <vector>

extern "C" {
	#include <jose/jose.h>
}

#include "plugin.hh"

using namespace std;

// TODO: Remove me.
namespace {
	static const string JwksPath = "/home/rabhamon/jwks/";
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
			fstream::pos_type len(stream.tellg());

			stream.seekg(0, ios::beg);
			buf.resize(len);
			stream.read(buf.data(), len);

			if (error) *error = false;
			return buf;
		} catch (const ios_base::failure &e) {
			cerr << "Unable to read properly file (I/O error): `" << e.what() << "`." << endl;
		} catch (const exception &e) {
			cerr << "Unable to read properly file: `" << e.what() << "`." << endl;
		}
	} else
		cerr << "Unable to open: `" << path << "`." << endl;

	if (error) *error = true;
	return buf;
}

static list<string> listFiles(const string &path, const string &suffix) {
	list<string> files;
	dirent *dirent;

	DIR *dirp = opendir(path.c_str());
	if (!dirp) {
		cerr << "Unable to open directory: `" << path << "` (" << strerror(errno) << ")." << endl;
		return files;
	}

	const string dotSuffix = "." + suffix;
	for (;;) {
		errno = 0;
		if (!(dirent = readdir(dirp))) {
			if (errno)
				cerr << "Unable to read directory: `" << path << "` (" << strerror(errno) << ")." << endl;
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
// JWT parser.
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

	cerr << "Unable to convert to json, error line " << error.line << ": `" << error.text << "`." << endl;
	return nullptr;
}

static bool isB64(const char *text, size_t len) {
	for (size_t i = 0; i < len; ++i)
		if (text[i] && !strchr(JOSE_B64_MAP, text[i]))
			return false;
	return true;
}

static json_t *parseJwe(const char *text) {
	const auto parts = makeArray("protected", "encrypted_key", "iv", "ciphertext", "tag");
	const size_t nParts = parts.size();

	json_auto_t *jwe = json_object();
	for (size_t i = 0, j = 0; j < nParts; j++) {
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
	cerr << "Unable to parse JWE correctly." << endl;
	return nullptr;
}

static json_t *decryptJwe(const char *text, const json_t *jwk) {
	json_auto_t *jwe = parseJwe(text);
	if (!jwe)
		return nullptr;

	size_t len = 0;
	char *jwtText = static_cast<char *>(jose_jwe_dec(NULL, jwe, NULL, jwk, &len));
	if (!jwtText) {
		cerr << "Unable to decrypt JWE." << endl;
		return nullptr;
	}

	json_t *jwt = convertToJson(jwtText, len);
	free(jwtText);
	return jwt;
}

// =============================================================================
// Check specific JWT attributes.
// =============================================================================

struct JwtAttrChecker {
	const char *name;
	bool (*predicate)(const char *value);
};

bool check(const char *value) {
	return false;
};

static bool checkJwt(json_t *jwt) {
	const auto attrs = makeArray<JwtAttrChecker>(
		JwtAttrChecker{ "oid", check },
		JwtAttrChecker{ "aud", check },
		JwtAttrChecker{ "rnd", check },
		JwtAttrChecker{ "iat", check },
		JwtAttrChecker{ "exp_in", check }
	);
	for (auto &attr : attrs) {
		char *value;
		if (json_unpack(jwt, "{s:s}", attr.name, &value) < 0) {
			attr.predicate(value);
			free(value);
		}
		return false;
	}

	return false;
}

// =============================================================================
// Plugin.
// =============================================================================

class JweAuth {
public:
	JweAuth ();
	~JweAuth ();

	bool isValid(const string &jwe);

private:
	list<json_t *> mJwks;
};

JweAuth::JweAuth() {
	for (const string &file : listFiles(JwksPath, "jwk")) {
		bool error;
		const vector<char> buf(readFile(JwksPath + "/" + file, &error));
		if (!error) {
			json_t *jwk = convertToJson(buf.data(), buf.size());
			if (jwk)
				mJwks.push_back(jwk);
		}
	}
}

JweAuth::~JweAuth() {
	for (json_t *jwk : mJwks)
		json_decref(jwk);
}

bool JweAuth::isValid(const string &text) {
	for (const json_t *jwk : mJwks) {
		json_auto_t *jwt = decryptJwe(text.c_str(), jwk);
		if (jwt) {
			cout << json_dumps(jwt, 0) << endl;
			return checkJwt(jwt);
		}
	}

	return false;
}

// -----------------------------------------------------------------------------

int main(int argc, char *argv[]) {
	return argc > 1 && JweAuth().isValid(argv[1]);
}
