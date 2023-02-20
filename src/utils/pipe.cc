/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <cstring>
#include <ostream>
#include <stdexcept>
#include <system_error>
#include <variant>

#include <unistd.h>

#include "flexisip/logmanager.hh"
#include "pipe.hh"
#include "utils/sys-err.hh"

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
ReadOnly::ReadOnly(Ready&& pipe) : Descriptor(move(pipe.readEnd)) {
}

variant<string, TimeOut, SysErr> ReadOnly::read(size_t size, chrono::microseconds timeoutMs) {
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

WriteOnly::WriteOnly(Ready&& pipe) : Descriptor(move(pipe.writeEnd)) {
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

ostream& operator<<(ostream& stream, const WriteOnly& pipe) {
	return stream << "pipe::WriteOnly(" << pipe.mDesc << ")";
}

} // namespace pipe

ostream& operator<<(ostream& stream, const TimeOut& timeout) {
	return stream << "pipe::TimeOut(" << timeout.duration.count() << "μs)";
}

} // namespace flexisip
