#pragma once

#include "hijacker/hijacker.hpp" // IWYU pragma: export
#include "hijacker/spawner.hpp" // IWYU pragma: export
void do_jailbreak() const;
class ScopedSuspender {
	Hijacker *hijacker;

	public:
		ScopedSuspender(Hijacker *hijacker) : hijacker(hijacker) { hijacker->suspend(); }
		ScopedSuspender(const ScopedSuspender&) = delete;
		ScopedSuspender(ScopedSuspender&&) = delete;
		ScopedSuspender &operator=(const ScopedSuspender&) = delete;
		ScopedSuspender &operator=(ScopedSuspender&&) = delete;
		~ScopedSuspender() { hijacker->resume(); }
};
