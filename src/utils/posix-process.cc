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

#include <chrono>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <system_error>
#include <thread>
#include <variant>

#include <sys/wait.h>
#include <unistd.h>

#include "flexisip-config.h"
#include "utils/pipe.hh"
#include "utils/sys-err.hh"
#include "utils/variant-utils.hh"

#include "posix-process.hh"

using namespace std;

namespace flexisip {
namespace process {

Process::Process(function<void()>&& f)
    : mState([&f]() -> State {
	      class Child {
		  public:
		      pipe::ReadOnly mStdin;
		      pipe::WriteOnly mStdout;
		      pipe::WriteOnly mStderr;
	      };

	      auto forked = visit(
	          [](auto&& in, auto&& out, auto&& err) -> variant<SysErr, Child, Running> {
		          if constexpr (is_same_v<decay_t<decltype(in)>, SysErr>) return in;
		          else if constexpr (is_same_v<decay_t<decltype(out)>, SysErr>) return out;
		          else if constexpr (is_same_v<decay_t<decltype(err)>, SysErr>) return err;
		          else {
			          auto pid = ::fork();
			          if (pid < 0) return SysErr();

			          // Forking dupes all descriptors, which means e.g. the write end of stdin will be held by both the
			          // parent and the child, so if the parent closes it, the child would not detect it.
			          // We have to close the (ir)relevent descs in the parent and the child

			          if (0 < pid) return Running(std::move(in), std::move(out), std::move(err), pid);

			          return Child{std::move(in), std::move(out), std::move(err)};
		          }
	          },
	          pipe::open(), pipe::open(), pipe::open());
	      // This 2-step init ensures that the destructors of the appropriate descriptors are called on the child
	      return visit(
	          [&f](auto&& forked) -> State {
		          if constexpr (is_same_v<decay_t<decltype(forked)>, Child>) {
			          if (auto error = forked.mStdin.duplicateTo(STDIN_FILENO)) {
				          cerr << "Failed to bind child's stdin to parent's pipe: " << *error;
				          ::exit(EXIT_FAILURE);
			          }
			          if (auto error = forked.mStdout.duplicateTo(STDOUT_FILENO)) {
				          cerr << "Failed to bind child's stdout to parent's pipe: " << *error;
				          ::exit(EXIT_FAILURE);
			          }
			          if (auto error = forked.mStderr.duplicateTo(STDERR_FILENO)) {
				          cerr << "Failed to bind child's stderr to parent's pipe: " << *error;
				          ::exit(EXIT_FAILURE);
			          }

			          // TODO: Either change the 'f' function prototype to 'noexcept' or use a try catch around the
			          //  function call to avoid calling the destructors by mistake, see below.
			          //  An example is available in function 'callAndStopMain' of the mainTester.
			          f();

			          /* From fork()'s manual:
			           * "The child process is created with a single thread […] including the states of mutexes,
			           * condition variables, and other pthreads objects"
			           * Meaning destructors waiting on shared state are very likely to deadlock, so we cannot just
			           * ::exit() as usual.
			           */
			          // TODO: Replace 'excel' and 'exit' calls with '_exit' to be able to pass the exit value to the
			          //  parent process without calling the destructors. See function 'callAndStopMain'  of the
			          //  mainTester for an example.
			          ::execl(DUMMY_EXEC, DUMMY_EXEC, nullptr);
			          throw runtime_error{"unreachable"};
		          } else {
			          return std::move(forked);
		          }
	          },
	          std::move(forked));
      }()) {
}

void Process::_wait(int noHang) {
	try {
		auto& process = std::get<Running>(mState);
		int wStatus = 0;
		auto wPid = ::waitpid(process.mPid, &wStatus, noHang);
		if (wPid < 0) {
			mState = SysErr();
			return;
		}
		if (wPid == 0) return; // Still Running
		if (WIFEXITED(wStatus)) {
			mState = ExitedNormally(std::move(process), static_cast<uint8_t>(WEXITSTATUS(wStatus)));
			return;
		}
		mState = Unexpected();
	} catch (std::bad_variant_access const&) {
		return;
	}
}

State& Process::state() {
	_wait(WNOHANG);
	return mState;
}

// TODO: The timeout mechanism is an inaccurate semi-busy loop.
// A better timeout could be implemented with a self-pipe trick
std::variant<Unexpected, TimeOut, ExitedNormally, SysErr> Process::wait(chrono::milliseconds timeout) && {
	class EscapeHatch {};
	constexpr auto step = 100ms;
	for (auto _ = 0ms; _ < timeout; _ += step) {
		_wait(WNOHANG);
		try {
			return visit(
			    [](auto&& state) -> std::variant<Unexpected, TimeOut, ExitedNormally, SysErr> {
				    if constexpr (is_same_v<decay_t<decltype(state)>, Running>) {
					    throw EscapeHatch{};
				    } else {
					    return std::move(state);
				    }
			    },
			    std::move(mState));
		} catch (const EscapeHatch&) {
			this_thread::sleep_for(step);
		}
	}

	auto& state = std::get<Running>(mState);
	cerr << "Timed out waiting for " << *this << "\n";
	if (auto* out = get_if<pipe::ReadOnly>(&state.mStdout))
		cerr << "stdout: " << StreamableVariant(out->readUntilDataReceptionOrTimeout(0xFFFF)) << "\n";
	if (auto* err = get_if<pipe::ReadOnly>(&state.mStderr))
		cerr << "stderr: " << StreamableVariant(err->readUntilDataReceptionOrTimeout(0xFFFF)) << "\n";
	return TimeOut{timeout};
}

optional<SysErr> Running::signal(SigNum sig) {
	if (::kill(mPid, sig) < 0) return SysErr();
	return {};
}

ostream& operator<<(ostream& stream, const Process& process) {
	return stream << "Process{mState: " << StreamableVariant(process.mState) << "}";
}
ostream& operator<<(ostream& stream, Process&& process) {
	return stream << "Process{mState: " << StreamableVariant(std::move(process.state())) << "}";
}

ostream& operator<<(ostream& stream, const ExitedNormally& state) {
	return stream << "process::ExitedNormally{mExitCode: " << int(state.mExitCode)
	              << ", mStdout: " << StreamableVariant(state.mStdout)
	              << ", mStderr: " << StreamableVariant(state.mStderr) << "}";
}
ostream& operator<<(ostream& stream, ExitedNormally&& state) {
	return stream << "process::ExitedNormally{mExitCode: " << int(state.mExitCode)
	              << ", mStdout: " << StreamableVariant(std::move(state.mStdout))
	              << ", mStderr: " << StreamableVariant(std::move(state.mStderr)) << "}";
}

ostream& operator<<(ostream& stream, const Running& state) {
	return stream << "process::Running{mPid: " << state.mPid << ", mStdin: " << StreamableVariant(state.mStdin)
	              << ", mStdout: " << StreamableVariant(state.mStdout)
	              << ", mStderr: " << StreamableVariant(state.mStderr) << "}";
}
ostream& operator<<(ostream& stream, Running&& state) {
	return stream << "process::Running{mPid: " << state.mPid << ", mStdin: " << StreamableVariant(state.mStdin)
	              << ", mStdout: " << StreamableVariant(std::move(state.mStdout))
	              << ", mStderr: " << StreamableVariant(std::move(state.mStderr)) << "}";
}

ostream& operator<<(ostream& stream, const Unexpected&) {
	return stream << "process::Unexpected()";
}

} // namespace process
} // namespace flexisip