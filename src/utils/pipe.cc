/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2025 Belledonne Communications SARL, All rights reserved.

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

#include "pipe.hh"

#include <cstring>
#include <ostream>
#include <stdexcept>
#include <system_error>
#include <variant>

#include <unistd.h>

#include "flexisip/logmanager.hh"
#include "utils/sys-err.hh"
#include "utils/variant-utils.hh"

using namespace std;

namespace flexisip {
namespace pipe {

Descriptor::Descriptor(RawPipeDesc desc) : mDesc(desc) {
}
Descriptor::Descriptor(Descriptor&& other) : mDesc(exchange(other.mDesc, -1)) {
}
Descriptor& Descriptor::operator=(Descriptor&& other) {
	swap(mDesc, other.mDesc);
	return *this;
}
Descriptor::~Descriptor() {
	if (mDesc < 0) return;
	if (::close(mDesc) < 0) {
		SLOGE << "Failed to close " << *this << ": " << SysErr();
	}
}
std::optional<SysErr> Descriptor::duplicateTo(RawPipeDesc other) {
	if (::dup2(mDesc, other) == -1) {
		return SysErr();
	}
	return {};
}

Ready::Ready(RawPipeDesc ends[2]) : readEnd{ends[0]}, writeEnd{ends[1]} {
}
ReadOnly::ReadOnly(Ready&& pipe) : Descriptor(std::move(pipe.readEnd)) {
}

variant<string, TimeOut, SysErr> ReadOnly::readUntilDataReceptionOrTimeout(size_t size,
                                                                           chrono::microseconds timeoutMs) const {
	fd_set fileDescriptorSet;
	FD_ZERO(&fileDescriptorSet);
	FD_SET(mDesc, &fileDescriptorSet);

	const auto timeoutS = chrono::duration_cast<chrono::seconds>(timeoutMs);
	struct timeval timeout;
	timeout.tv_sec = timeoutS.count();
	timeout.tv_usec = (timeoutMs - timeoutS).count();

	int ret = select(mDesc + 1, &fileDescriptorSet, NULL, NULL, &timeout);
	if (ret == 0) return TimeOut{timeoutMs};
	if (ret < 0) return SysErr();

	string buffer(size, '\0');
	auto byteCount = ::read(mDesc, buffer.data(), buffer.size());
	buffer.resize(byteCount);
	return buffer;
}

variant<string, SysErr> ReadOnly::readUntilDataReception(size_t size) const {
	string buffer(size, '\0');
	auto byteCount = ::read(mDesc, buffer.data(), buffer.size());
	if (byteCount < 0) return SysErr();
	buffer.resize(byteCount);
	return buffer;
}

WriteOnly::WriteOnly(Ready&& pipe) : Descriptor(std::move(pipe.writeEnd)) {
}

optional<SysErr> WriteOnly::write(const string& data) {
	if (::write(mDesc, data.data(), data.size()) < 0) {
		return SysErr();
	}
	return {};
}

variant<Ready, SysErr> open() {
	RawPipeDesc ends[2];
	if (::pipe(ends) < 0) return SysErr();
	return Ready(ends);
}

ostream& operator<<(ostream& stream, const Descriptor& desc) {
	return stream << "pipe::Descriptor(" << desc.mDesc << ")";
}

ostream& operator<<(ostream& stream, const Closed&) {
	return stream << "pipe::Closed()";
}

ostream& operator<<(ostream& stream, const Ready& pipe) {
	return stream << "pipe::Ready{readEnd: " << pipe.readEnd << ", writeEnd: " << pipe.writeEnd << "}";
}

ostream& operator<<(ostream& stream, const ReadOnly& pipe) {
	return stream << "pipe::ReadOnly(" << pipe.mDesc << ")";
}
ostream& operator<<(ostream& stream, ReadOnly&& pipe) {
	stream << "pipe::ReadOnly(" << pipe.mDesc << ", data:\n";
	stream << StreamableVariant(pipe.readUntilDataReceptionOrTimeout(0xFFFF)) << "\n";
	return stream << ")";
}

ostream& operator<<(ostream& stream, const WriteOnly& pipe) {
	return stream << "pipe::WriteOnly(" << pipe.mDesc << ")";
}

} // namespace pipe

ostream& operator<<(ostream& stream, const TimeOut& timeout) {
	return stream << "TimeOut(" << timeout.duration.count() << "μs)";
}

} // namespace flexisip