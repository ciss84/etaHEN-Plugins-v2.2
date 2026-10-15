#include "utils.hpp"
#include <notify.hpp>
#include <signal.h>
#include <string>
#include <ps5/kernel.h>

extern "C"
{
	int sceSystemServiceGetAppIdOfRunningBigApp();
	int sceSystemServiceGetAppTitleId(int app_id, char *title_id);
	int32_t sceKernelPrepareToSuspendProcess(pid_t pid);
	int32_t sceKernelSuspendProcess(pid_t pid);
	int32_t sceKernelPrepareToResumeProcess(pid_t pid);
	int32_t sceKernelResumeProcess(pid_t pid);
}

void sig_handler(int signo)
{
  printf_notification("Plugin Loader v1.07 crashed with signal %d     ", signo);
	printBacktraceForCrash();
	exit(-1);
}

bool Get_Running_App_TID(std::string &title_id, int &BigAppid)
{
	char tid[255];
	BigAppid = sceSystemServiceGetAppIdOfRunningBigApp();
	if (BigAppid < 0) return false;

	memset(tid, 0, sizeof(tid));
	if (sceSystemServiceGetAppTitleId(BigAppid, &tid[0]) != 0)
		return false;

	title_id = std::string(tid);
	return true;
}

bool IsProcessRunning(pid_t pid)
{
	int bappid = 0;
	return (_sceApplicationGetAppId(pid, &bappid) >= 0);
}

uintptr_t kernel_base = 0;

int main()
{
	plugin_log("=== PLUGIN LOADER v1.07 WITH AGGRESSIVE MODE ===");
	plugin_log("This version attempts injection even if process checks fail");

	payload_args_t *args = payload_get_args();
	kernel_base = args->kdata_base_addr;

	struct sigaction new_SIG_action;
	new_SIG_action.sa_handler = sig_handler;
	sigemptyset(&new_SIG_action.sa_mask);
	new_SIG_action.sa_flags = 0;

	for (int i = 0; i < 12; i++)
		sigaction(i, &new_SIG_action, NULL);

	plugin_log("Plugin Loader v1.07 ready - monitoring games");
	printf_notification("Plugin Loader v1.07 started     \nBy @84Ciss ");

	int last_attempted_appid = -1;  // Track last appid we attempted (successful or not)

	while(1)
	{
		// Reload config at each iteration to pick up changes
		GameInjectorConfig config = parse_injector_config();
		plugin_log("Config loaded - %zu games configured", config.games.size());

		int appid = 0;
		std::string tid;
		const char* detected_tid = nullptr;

		// Wait for game to launch
		while(true)
		{
			if (!Get_Running_App_TID(tid, appid))
			{
				usleep(500000);
				continue;
			}

			// Skip if this is the same appid we just attempted
			if (appid == last_attempted_appid)
			{
				usleep(500000);
				continue;
			}

			// Check if it's a game (CUSA/SCUS/PPSA)
			if (tid.rfind("CUSA") != std::string::npos ||
				tid.rfind("SCUS") != std::string::npos ||
				tid.rfind("PPSA") != std::string::npos)
			{
				detected_tid = tid.c_str();
				break;
			}

			usleep(500000);
		}

		plugin_log("========================================");
		plugin_log("Game detected: %s (appid: %d)", detected_tid, appid);
		plugin_log("========================================");

		// Mark this appid as attempted immediately to prevent retry loops
		last_attempted_appid = appid;

		// Check if we have config for this game
		auto it = config.games.find(detected_tid);
		if (it == config.games.end())
		{
			plugin_log("No config for %s - skipping", detected_tid);
			// Wait for game to close (or appid to change)
			int current_appid = appid;
			while(true)
			{
				int check_appid = 0;
				std::string check_tid;
				if (!Get_Running_App_TID(check_tid, check_appid) || check_appid != current_appid)
				{
					break;
				}
				sleep(5);
			}
			last_attempted_appid = -1;  // Reset when game closes
			continue;
		}

		std::vector<PRXConfig> &prx_list = it->second;
		plugin_log("Found %zu PRX to inject for %s", prx_list.size(), detected_tid);

		// CRITICAL FIX: Find the real PID (not appid!)
		// appid is the application ID, we need to find the process ID
		plugin_log("Searching for real PID (appid=%d)...", appid);
		int bappid = 0;
		pid_t pid = 0;
		
		for (int retry = 0; retry < 10 && pid == 0; retry++) {
			for (size_t j = 0; j <= 9999; j++) {
				if (_sceApplicationGetAppId(j, &bappid) < 0)
					continue;
				if (appid == bappid) {
					pid = j;
					plugin_log("Real PID found: %d (retry %d)", pid, retry);
					break;
				}
			}
			if (pid == 0) {
				usleep(50000); // Wait 50ms before retry
			}
		}
		
		if (pid == 0) {
			plugin_log("ERROR: Failed to find real PID after 10 retries");
			last_attempted_appid = -1;
			continue;
		}

		plugin_log("PID: %d (converted from appid: %d)", pid, appid);

		// Wait for process initialization with diagnostic logging
		plugin_log("Waiting 2 seconds for process initialization...");
		
		int alive_count = 0;
		int dead_count = 0;
		for (int i = 0; i < 5; i++)
		{
			usleep(100000); // Wait 100ms
			bool running = IsProcessRunning(pid);
			if (running)
				alive_count++;
			else
				dead_count++;
		}
		
		plugin_log("Process check results: %d/20 alive, %d/20 dead", alive_count, dead_count);
		
		// AGGRESSIVE MODE: Try injection anyway if we got ANY alive signals
		if (alive_count == 0)
		{
			plugin_log("WARNING: Process appears completely dead, but will try injection anyway");
		}
		else
		{
			plugin_log("Process seems alive (%d/20 checks passed) - proceeding", alive_count);
		}

		// Create hijacker - with retry logic
		plugin_log("Creating hijacker for PID %d...", pid);
		UniquePtr<Hijacker> executable = Hijacker::getHijacker(pid);
		
		if (!executable)
		{
			plugin_log("First hijacker attempt failed, waiting 1s and retrying...");
			sleep(1);
			executable = Hijacker::getHijacker(pid);
		}
		
		if (!executable)
		{
			plugin_log("FAILED to create Hijacker for pid %d after retries", pid);
			plugin_log("This game instance will be skipped until appid changes");
			
			// Wait for this game instance to close (appid to change)
			plugin_log("Waiting for appid to change...");
			int current_appid = appid;
			int wait_count = 0;
			while(wait_count < 60)  // Wait max 5 minutes
			{
				int check_appid = 0;
				std::string check_tid;
				if (!Get_Running_App_TID(check_tid, check_appid) || check_appid != current_appid)
				{
					plugin_log("Game closed or appid changed");
					break;
				}
				sleep(5);
				wait_count++;
			}
			last_attempted_appid = -1;  // Reset when game closes
			continue;
		}

		plugin_log("Hijacker created successfully!");

		uint64_t text_base = executable->getEboot()->imagebase();
		plugin_log("Process attached - text_base: 0x%llx", text_base);

		// Suspend game
		plugin_log("Suspending game...");
	  sceKernelPrepareToSuspendProcess(pid);
	  sceKernelSuspendProcess(pid);
		usleep(500000);

    // Inject all PRX
    int success_count = 0;
    for (const auto& prx : prx_list)
    {
      plugin_log("Injecting: %s", prx.path.c_str());

    if (HookGame(executable, text_base, prx.path.c_str(), false, prx.frame_delay))
    {
        plugin_log("SUCCESS: %s injected", prx.path.c_str());
        success_count++;
        
        // RESUME pour laisser ce PRX se charger
        plugin_log("Resuming game to load %s...", prx.path.c_str());
        sceKernelPrepareToResumeProcess(pid);
        sceKernelResumeProcess(pid);
        
        // Attends que le PRX se charge (~2-3 secondes)
        sleep(3);
        
        // Re-suspend pour la prochaine injection
        if (&prx != &prx_list.back()) { // Si pas le dernier
            plugin_log("Re-suspending for next injection...");
            sceKernelPrepareToSuspendProcess(pid);
            sceKernelSuspendProcess(pid);
            usleep(2500000);
        }
      }
      else
      {
          plugin_log("FAILED: %s", prx.path.c_str());
      }
    }

    plugin_log("All injections complete");

		// Resume game
		plugin_log("Resuming game...");
	  usleep(500000);
	  sceKernelPrepareToResumeProcess(pid);
	  sceKernelResumeProcess(pid);

		plugin_log("========================================");
		plugin_log("Injection complete: %d/%zu PRX loaded",
				   success_count, prx_list.size());
		plugin_log("========================================");

		printf_notification("%d/%zu PRX injected into %s",
							success_count, prx_list.size(), detected_tid);

		// Wait for game to close (monitor appid changes)
		plugin_log("Waiting for game to close (monitoring appid %d)...", appid);
		int current_appid = appid;
		int monitor_count = 0;
		while(monitor_count < 720)  // Monitor for max 1 hour (720 * 5s)
		{
			int check_appid = 0;
			std::string check_tid;
			if (!Get_Running_App_TID(check_tid, check_appid) || check_appid != current_appid)
			{
				plugin_log("Game closed or appid changed (was %d, now %d)", current_appid, check_appid);
				break;
			}
			sleep(5);
			monitor_count++;
		}

		plugin_log("Game closed - ready for next launch");
		last_attempted_appid = -1;  // Reset tracker when game closes
	}

	return 0;
}