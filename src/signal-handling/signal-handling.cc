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

#include "flexisip/signal-handling/signal-handling.hh"

#include <unistd.h>

#include <cstring>
#include <stdexcept>
#include <unordered_map>
#include <vector>

namespace {

constexpr const auto read_ = read;

} // namespace

namespace flexisip {

namespace signal_handling {

std::unordered_map<SigNum, PipeDescriptor> PipedSignal::sSignalToPipe{};

PipedSignal::PipedSignal(std::vector<SigNum>&& signals) : mSignals(std::move(signals)) {
	if (pipe(mPipe.array) == -1) {
		throw std::runtime_error{"Failed to create communication pipe for Unix signal handler"};
	}

	const static auto signalHandler = []() {
		struct sigaction sigact;
		memset(&sigact, 0, sizeof(sigact));
		sigact.sa_flags = SA_SIGINFO;
		// This lambda MUST be signal-safe
		// https://en.cppreference.com/w/cpp/utility/program/signal#Signal_handler
		sigact.sa_sigaction = [](SigNum signum, [[maybe_unused]] siginfo_t* _info,
		                         [[maybe_unused]] void* _ucontext) noexcept {
			[[maybe_unused]] auto _ = write(sSignalToPipe[signum], SignalData{signum}.bytes, sizeof(SignalData));
			// We would like to print something if the write fails, but a safe signal handler cannot lock anything
			// (including stdout)
		};
		return sigact;
	}();

	for (auto signum : mSignals) {
		// Set map entry first, so it is valid before the handler is registered
		sSignalToPipe[signum] = mPipe.fd.write;
		sigaction(signum, &signalHandler, nullptr);
	}
}
PipedSignal::~PipedSignal() {
	const static auto defaultHandler = []() {
		struct sigaction sigact;
		memset(&sigact, 0, sizeof(sigact));
		sigact.sa_handler = SIG_DFL;
		return sigact;
	}();

	for (auto signum : mSignals) {
		const auto binding = sSignalToPipe.find(signum);
		if (binding == sSignalToPipe.end()) continue; // We have been shadowed by another binding
		sigaction(signum, &defaultHandler, nullptr);
		sSignalToPipe.erase(binding); // Unbind map entry last so it is always valid for the handler
	}
	for (auto fd : mPipe.array) {
		close(fd);
	}
}

ssize_t PipedSignal::read(SignalData& data) {
	return read_(mPipe.fd.read, data.bytes, sizeof(data.bytes));
}

} // namespace signal_handling

} // namespace flexisip