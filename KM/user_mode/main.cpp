#include <windows.h>
#include <stdint.h>
#include <string>

#include "communication.h"
#include <iostream>
#include <TlHelp32.h>
#include <thread>

uintptr_t test_ptr = 0x50;

DWORD GetProcessID(const std::wstring processName)
{
	PROCESSENTRY32 processInfo;
	processInfo.dwSize = sizeof(processInfo);

	HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (processesSnapshot == INVALID_HANDLE_VALUE)
	{
		return 0;
	}

	Process32First(processesSnapshot, &processInfo);
	if (!processName.compare(processInfo.szExeFile))
	{
		CloseHandle(processesSnapshot);
		return processInfo.th32ProcessID;
	}

	while (Process32Next(processesSnapshot, &processInfo))
	{
		if (!processName.compare(processInfo.szExeFile))
		{
			CloseHandle(processesSnapshot);
			return processInfo.th32ProcessID;
		}
	}

	CloseHandle(processesSnapshot);
	return 0;
}

int pid3;

namespace utils
{
	auto getuworld(uintptr_t pointer) -> uintptr_t
	{
		uintptr_t uworld_addr = communication->read_physical_memory< uintptr_t >(pointer + 0x60);

		unsigned long long uworld_offset;

		if (uworld_addr > 0x10000000000)
		{
			uworld_offset = uworld_addr - 0x10000000000;
		}
		else {
			uworld_offset = uworld_addr - 0x8000000000;
		}

		return pointer + uworld_offset;
	}


	inline static bool isguarded(uintptr_t pointer) noexcept
	{
		static constexpr uintptr_t filter = 0xFFFFFFF000000000;
		uintptr_t result = pointer & filter;
		return result == 0x8000000000 || result == 0x10000000000;
	}
}



auto cachethread() -> void
{
	auto guardedregion = communication->guarded_region();
	printf("guardedregion: 0x%p\n", guardedregion);

	while (true)
	{
		auto uworld = utils::getuworld(guardedregion);
		printf("uworld: 0x%p\n", uworld);

		auto ulevel = communication->read_physical_memory< uintptr_t >(uworld + 0x38);
		printf("ulevel: 0x%p\n", ulevel);

		auto gamestate = communication->read_physical_memory< uintptr_t >(uworld + 0x140);
		printf("gamestate: 0x%p\n", gamestate);

		Sleep(2000);
	}
}

//void main(int argc, char* argv[])
void main()
{
	/*
	if (argc > 1)
	{
		if (!strcmp( argv[argc - 1], "--test" ))
		{
			if (!communication->initialize( ))
			{
				printf( "driver not loaded.\n" );
				Sleep( 3000 );
				return;
			}
			printf( "driver loaded.\n" );
			Sleep( 3000 );
			return;
		}

		printf( "Unknown arguments given:\n" );
		for (int i = 0; i < argc; i++)
		{
			printf( "arg[%i] = %s\n", i, argv[i] );
		}
		Sleep( 15000 );
		return;
	}
	*/
	if (!communication->initialize( ))
	{
		printf( "failed to initialize the driver.\n" );
		std::cin.get( );
	}
	


	pid3 = GetProcessID(L"VALORANT-Win64-Shipping.exe");

	if (!communication->attach(pid3))
	{
		printf( "failed to attatch to the process\n" );
		std::cin.get( );
	}
	std::thread(cachethread).detach();
	
	 
	printf( "finished operation\n" );
}