/*
 * Flexisip, a flexible SIP proxy server with media capabilities.
 * Copyright (C) 2021  Belledonne Communications SARL, All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include <regex>
#include <vector>

#include <flexisip/auth/authentifier.hh>

namespace flexisip {

class TlsClientAuthentifier : public Authentifier {
public:
	template <typename T>
	TlsClientAuthentifier(T &&clientCerts) : Authentifier{}, mTrustedClientCertificates{std::forward<T>(clientCerts)} {}

	bool trustDomainCertificates() const noexcept {return mTrustDomainCertificates;}
	void trustDomainCertificates(bool val) noexcept {mTrustDomainCertificates = val;}

	bool rejectWrongClientCertificates() const noexcept {return mRejectWrongClientCertificates;}
	void rejectWrongClientCertificates(bool val) noexcept {mRejectWrongClientCertificates = val;}

	bool requiredSubjectCheckSet() const noexcept {return mRequiredSubjectCheckSet;}
	void requiredSubjectCheckSet(bool val) noexcept {mRequiredSubjectCheckSet = val;}

	void verify(const std::shared_ptr<AuthStatus> &as) override;

private:
	const char *findIncomingSubjectInTrusted(const std::shared_ptr<RequestSipEvent> &ev, const std::string& fromDomain);
	bool tlsClientCertificatePostCheck(const std::shared_ptr<RequestSipEvent> &ev);

	std::vector<std::string> mTrustedClientCertificates{};
	std::regex mRequiredSubject{};
	bool mTrustDomainCertificates{false};
	bool mRejectWrongClientCertificates{false};
	bool mRequiredSubjectCheckSet{false};
};

}
