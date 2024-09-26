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
#include <openssl/x509.h>

#include "certificate.hh"
#include "private-key.hh"

using namespace std;

namespace flexisip::tester {

TlsCertificate::TlsCertificate(const TlsPrivateKey& pKey, const long validitySeconds) {
	auto* key = pKey.getKey();
	mX509 = X509_new();
	ASN1_INTEGER_set(X509_get_serialNumber(mX509), 1);
	long certificateValidityStartOffset = 0;
	if (validitySeconds < 0) certificateValidityStartOffset = 2 * validitySeconds;

	X509_gmtime_adj(X509_get_notBefore(mX509), certificateValidityStartOffset);
	X509_gmtime_adj(X509_get_notAfter(mX509), validitySeconds);
	X509_set_pubkey(mX509, key);
	X509_NAME* name = X509_get_subject_name(mX509);
	X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)"FR", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)"BC", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"localhost", -1, -1, 0);
	X509_set_issuer_name(mX509, name);
	X509_sign(mX509, key, EVP_sha256());
}

TlsCertificate::~TlsCertificate() {
	X509_free(mX509);
}

void TlsCertificate::openAndWriteCertificate(const std::filesystem::path& filePath,
                                             const std::string&& openingMode) const {
	SLOGD << "Writing certificate to " << filePath;
	auto* f = fopen(filePath.c_str(), openingMode.c_str());
	PEM_write_X509(f, mX509);
	fclose(f);
}

void TlsCertificate::appendToFile(const std::filesystem::path& filePath) const {
	openAndWriteCertificate(filePath, "ab");
}

void TlsCertificate::writeToFile(const std::filesystem::path& filePath) const {
	openAndWriteCertificate(filePath, "wb");
}

} // namespace flexisip::tester