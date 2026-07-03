#include "utils.hpp"
#include <cstdio>
#include <cstring>
#include <nid.hpp>
#include <fcntl.h>
#include <string>

void write_log(const char* text)
{
	int text_len = strlen(text);
	int fd = open("/data/PluginLoader/PluginLoader.log", O_WRONLY | O_CREAT | O_APPEND, 0777);
	if (fd < 0)
	{
		return;
	}
	write(fd, text, text_len);
	close(fd);
}

void plugin_log(const char* fmt, ...)
{
	char msg[0x1000]{};
	va_list args;
	va_start(args, fmt);
	int msg_len = vsnprintf(msg, sizeof(msg), fmt, args);
	va_end(args);

	if (msg_len > 0 && msg[msg_len-1] == '\n')
	{
		write_log(msg);
	}
	else
	{
	     strcat(msg, "\n");
	     write_log(msg);
	}
}

extern "C" int sceSystemServiceGetAppIdOfRunningBigApp();
extern "C" int sceSystemServiceGetAppTitleId(int app_id, char* title_id);

bool Is_Game_Running(int &BigAppid, const char* title_id)
{
	char tid[256]{};
	BigAppid = sceSystemServiceGetAppIdOfRunningBigApp();
	if (BigAppid < 0)
	{
		return false;
	}

	if (sceSystemServiceGetAppTitleId(BigAppid, &tid[0]) != 0)
	{
		return false;
	}

	tid[255] = '\0';

    if(std::string(tid) == std::string(title_id))
	{
	   plugin_log("%s is running, appid 0x%X", title_id, BigAppid);
       return true;
	}

	return false;
}

bool HookGame(UniquePtr<Hijacker> &hijacker, uint64_t alsr_b, const char* prx_path,
              bool auto_load, int frame_delay, uintptr_t* out_stuff_addr)
{
  static uintptr_t first_stuffAddr = 0;
  static bool already_hooked = false;
  static pid_t last_pid = 0;

  plugin_log("[HookGame] PRX: %s | auto_load: %d | frame_delay: %d", prx_path, auto_load, frame_delay);

  pid_t current_pid = hijacker->getPid();
  if (current_pid != last_pid) {
    plugin_log("[HookGame] === NEW GAME PROCESS: PID %d → %d, reset state ===", last_pid, current_pid);
    already_hooked = false;
    first_stuffAddr = 0;
    last_pid = current_pid;
  }

  GameBuilder builder = auto_load ? BUILDER_TEMPLATE_AUTO : BUILDER_TEMPLATE;
  size_t shellcode_size = auto_load ? GameBuilder::SHELLCODE_SIZE_AUTO : GameBuilder::SHELLCODE_SIZE;

  GameStuff stuff{*hijacker};

  // ── Recuperer scePadReadState depuis libScePad.sprx EN PREMIER ──────────
  UniquePtr<SharedLib> lib = hijacker->getLib("libScePad.sprx");
  stuff.scePadReadState = hijacker->getFunctionAddress(lib.get(), nid::scePadReadState);

  // ── Diagnostic adresses critiques ────────────────────────────────────────
  plugin_log("[HookGame] scePadReadState addr         : 0x%llx", stuff.scePadReadState);
  plugin_log("[HookGame] sceKernelLoadStartModule addr : 0x%llx", stuff.sceKernelLoadStartModule);
  plugin_log("[HookGame] sceKernelDlsym addr           : 0x%llx", stuff.sceKernelDlsym);
  plugin_log("[HookGame] debugout addr                 : 0x%llx", stuff.debugout);

  if (stuff.sceKernelLoadStartModule == 0) {
    plugin_log("[HookGame] FATAL: sceKernelLoadStartModule == 0 ! NID introuvable dans libkernel.");
    plugin_log("[HookGame] module_start NE SERA JAMAIS APPELE.");
    return false;
  }

  if (stuff.scePadReadState == 0) {
    plugin_log("[HookGame] FATAL: scePadReadState introuvable dans libScePad.sprx");
    return false;
  }

  if (stuff.scePadReadState == 0) {
    plugin_log("[HookGame] FAILED: scePadReadState introuvable dans libScePad.sprx");
    return false;
  }

  stuff.ASLR_Base = alsr_b;
  strncpy(stuff.prx_path, prx_path, sizeof(stuff.prx_path) - 1);
  stuff.prx_path[sizeof(stuff.prx_path) - 1] = '\0';
  stuff.frame_delay = frame_delay;
  stuff.frame_counter = 0;
  stuff.loaded = 0;
  stuff.game_hash = 0;

  auto meta = hijacker->getEboot()->getMetaData();
  const auto &plttab = meta->getPltTable();
  auto index = meta->getSymbolTable().getSymbolIndex(nid::scePadReadState);

  plugin_log("[HookGame] PLT symbol index pour scePadReadState: %u", index);

  for (const auto &plt : plttab) {
    if (ELF64_R_SYM(plt.r_info) == index) {
      uintptr_t hook_adr = hijacker->getEboot()->imagebase() + plt.r_offset;

      plugin_log("[HookGame] PLT entry trouvee: r_offset=0x%llx | hook_adr=0x%llx", plt.r_offset, hook_adr);

      if (already_hooked && first_stuffAddr != 0) {
        plugin_log("[HookGame] Hook existant pour PID %d — UPDATE GameStuff @ 0x%llx", current_pid, first_stuffAddr);
        hijacker->write(first_stuffAddr, stuff);
        plugin_log("[HookGame] GameStuff UPDATE OK: %s", stuff.prx_path);
        if (out_stuff_addr) *out_stuff_addr = first_stuffAddr;
        return true;
      }

      plugin_log("[HookGame] Creation du PREMIER hook pour PID %d", current_pid);

      auto code = hijacker->getTextAllocator().allocate(shellcode_size);
      auto stuffAddr = hijacker->getDataAllocator().allocate(sizeof(GameStuff));

      plugin_log("[HookGame] Shellcode alloue @ 0x%llx (size: %zu)", code, shellcode_size);
      plugin_log("[HookGame] GameStuff alloue  @ 0x%llx (size: %zu)", stuffAddr, sizeof(GameStuff));
      plugin_log("[HookGame] PLT hook: 0x%llx → shellcode 0x%llx", hook_adr, code);

      builder.setExtraStuffAddr(stuffAddr);

      uint8_t shellcode_buffer[256];
      memset(shellcode_buffer, 0, sizeof(shellcode_buffer));
      memcpy(shellcode_buffer, builder.shellcode, shellcode_size);

      hijacker->write(code, shellcode_buffer);
      hijacker->write(stuffAddr, stuff);
      hijacker->write<uintptr_t>(hook_adr, code);

      already_hooked = true;
      first_stuffAddr = stuffAddr;

      if (out_stuff_addr) *out_stuff_addr = stuffAddr;

      plugin_log("[HookGame] SUCCESS: hook installe, shellcode pret");
      plugin_log("[HookGame] NOTE: connected check SUPPRIME (FW10 fix) — chargement des le 1er scePadReadState valide");
      return true;
    }
  }

  plugin_log("[HookGame] FAILED: scePadReadState introuvable dans la PLT table");
  return false;
}

GameInjectorConfig parse_injector_config()
{
	GameInjectorConfig config;

	int fd = open("/data/PluginLoader/PluginLoader.ini", O_RDONLY);
	if (fd < 0)
	{
		plugin_log("No PluginLoader.ini found at /data/PluginLoader/PluginLoader.ini");
		return config;
	}

	char buffer[8192];
	int bytes_read = read(fd, buffer, sizeof(buffer) - 1);
	close(fd);

	if (bytes_read <= 0)
	{
		plugin_log("Failed to read PluginLoader.ini");
		return config;
	}
	buffer[bytes_read] = '\0';

	plugin_log("Config file read: %d bytes", bytes_read);

	std::string current_tid = "";
	char* ptr = buffer;
	char* line_start = ptr;

	while (ptr < buffer + bytes_read)
	{
		if (*ptr == '\n' || *ptr == '\r' || ptr >= buffer + bytes_read - 1)
		{
			size_t line_len = ptr - line_start;
			if (ptr >= buffer + bytes_read - 1 && *ptr != '\n' && *ptr != '\r')
				line_len++;

			std::string line(line_start, line_len);

			size_t start = line.find_first_not_of(" \t\r");
			size_t end   = line.find_last_not_of(" \t\r");

			if (start != std::string::npos && end != std::string::npos)
				line = line.substr(start, end - start + 1);
			else
				line = "";

			if (!line.empty() && line[0] != ';' && line[0] != '#')
			{
				if (line[0] == '[' && line[line.length()-1] == ']')
				{
					current_tid = line.substr(1, line.length()-2);
					plugin_log("Config: section [%s]", current_tid.c_str());
				}
				else if (!current_tid.empty() && line.find("fakelib") == 0)
				{
					size_t eq = line.find('=');
					if (eq != std::string::npos)
					{
						std::string val = line.substr(eq + 1);
						size_t vs = val.find_first_not_of(" \t");
						if (vs != std::string::npos) val = val.substr(vs);
						bool enabled = !(val == "false" || val == "0");
						config.fakelib_enabled[current_tid] = enabled;
						plugin_log("Config: [%s] fakelib = %s", current_tid.c_str(), enabled ? "true" : "false");
					}
				}
				else if (!current_tid.empty())
				{
					size_t colon_pos = line.find(':');
					std::string prx_file;
					int frame_delay = 60;

					if (colon_pos != std::string::npos)
					{
						prx_file   = line.substr(0, colon_pos);
						frame_delay = atoi(line.substr(colon_pos + 1).c_str());
					}
					else
					{
						prx_file = line;
					}

					std::string full_path = "/data/PluginLoader/" + prx_file;

					PRXConfig prx;
					prx.path        = full_path;
					prx.frame_delay = frame_delay;
					config.games[current_tid].push_back(prx);

					plugin_log("Config: [%s] -> %s (delay: %d frames)",
							   current_tid.c_str(), full_path.c_str(), frame_delay);
				}
			}

			if (*ptr == '\r' && ptr + 1 < buffer + bytes_read && *(ptr + 1) == '\n')
				ptr += 2;
			else if (*ptr == '\n' || *ptr == '\r')
				ptr++;
			else
				ptr++;

			line_start = ptr;
		}
		else
		{
			ptr++;
		}
	}

	plugin_log("Config parsing done: %zu game(s)", config.games.size());
	return config;
}