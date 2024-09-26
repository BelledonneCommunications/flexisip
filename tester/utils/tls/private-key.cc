/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include <flexisip/logmanager.hh>
#include <openssl/pem.h>

#include "private-key.hh"

using namespace std;

namespace flexisip::tester {

TlsPrivateKey::TlsPrivateKey() {

#if OPENSSL_VERSION_MAJOR >= 3
	mKey = EVP_RSA_gen(2048);
#else
	mKey = EVP_PKEY_new();
	auto* rsa = RSA_new();
	auto* bne = BN_new();
	BN_set_word(bne, RSA_F4);
	RSA_generate_key_ex(rsa, 2048, bne, nullptr);
	EVP_PKEY_assign_RSA(mKey, rsa);
	BN_free(bne);
#endif
}

TlsPrivateKey::~TlsPrivateKey() {
	if (mKey) EVP_PKEY_free(mKey);
}

void TlsPrivateKey::writeToFile(const filesystem::path& keyPath) const {
	FILE* f = fopen(keyPath.c_str(), "wb");
	if (!PEM_write_PrivateKey(f, mKey, nullptr, //  cipher used to encrypt the key
	                          nullptr,          // passphrase
	                          0,                // passphrase length
	                          nullptr,          // callback used to request the passphrase
	                          nullptr           // data for callback
	                          )) {
		SLOGE << "Error while writing private key to " << keyPath;
	}
	fclose(f);
}

} // namespace flexisip::tester