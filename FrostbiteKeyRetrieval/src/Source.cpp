/*
	FrostbiteKeyRetrieval
	does what it says, dumps the public key from frostbite games that use secure signing.
	So far this has worked in Battlefield 3, 4 CTE, I don't have any other's installed to test
	
	Sorry for all of the mess, I was just trying to get something that worked x86/x64 to prepare for Rime

	PSA: Once you acquire the key please do not share it, it is EA_DICE's property and sharing it is illegal.
	This tool is here to make sure everyone only get their own key.

	Use it, piracy isn't nice.
	By: kiwidog (http://kiwidog.me)
*/

#include <string>
#include <memory>
#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>

#if defined(_WIN64)
#define ALIGNMENT 8
#elif defined(_WIN32)
#define ALIGNMENT 4
#endif
HANDLE GetProcessByPartialName(std::wstring p_Name, std::wstring& p_ProcessName)
{
	unsigned long s_ProcessIds[1024], s_ProcessCount;

	if (!EnumProcesses(s_ProcessIds, sizeof(s_ProcessIds), &s_ProcessCount))
	{
		printf("Could not enumerate processes.\n");
		return nullptr;
	}

	for (unsigned long i = 0; i < s_ProcessCount; ++i)
	{
		auto l_ProcessId = s_ProcessIds[i];
		if (!l_ProcessId)
			continue;

		auto l_Process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, l_ProcessId);
		if (!l_Process)
		{
			printf("Could not open process for information pid: %d (%x).\n", l_ProcessId, GetLastError());
			continue;
		}

		wchar_t s_ProcessNameChars[MAX_PATH];
		SecureZeroMemory(s_ProcessNameChars, sizeof(s_ProcessNameChars));

		if (!GetModuleFileNameEx(l_Process, nullptr, s_ProcessNameChars, sizeof(s_ProcessNameChars)))
		{
			printf("Could not get the process name (%x).\n", GetLastError());
			CloseHandle(l_Process);
		}

		std::wstring s_ProcessName(s_ProcessNameChars);

		if (s_ProcessName.find(p_Name) == std::string::npos)
		{
			CloseHandle(l_Process);
			continue;
		}

		p_ProcessName = std::wstring(s_ProcessName.begin(), s_ProcessName.end());
		return l_Process;
	}

	return nullptr;
}

int main(int argc, char* argv[])
{
	if (argc < 2)
		return -1;
	try
	{
		// FrostbiteKeyRetrieval <exe name>
		std::string s_CmdProcessName(argv[1]);
		std::wstring s_ProcessName(s_CmdProcessName.begin(), s_CmdProcessName.end());

		std::wstring s_ProcessPath;
		auto s_ProcessHandle = GetProcessByPartialName(s_ProcessName, s_ProcessPath);
		if (!s_ProcessHandle)
			return -2;

		auto s_ProcessId = GetProcessId(s_ProcessHandle);
		auto s_Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, s_ProcessId);
		MODULEENTRY32 s_Module;
		SecureZeroMemory(&s_Module, sizeof(s_Module));
		s_Module.dwSize = sizeof(s_Module);

		auto s_ModuleSize = static_cast<unsigned long>(0);
		void* s_ModuleBase = nullptr;
		Module32First(s_Snapshot, &s_Module);
		do
		{
			std::wstring l_ModulePath(s_Module.szExePath);
			if (l_ModulePath.find(s_ProcessPath) == std::string::npos)
				continue;

			printf("Module Name: %S\n", s_Module.szExePath);
			printf("Base Address: 0x%p\n", s_Module.modBaseAddr);
			printf("Base Size: 0x%x\n\n", s_Module.modBaseSize);

			s_ModuleSize = s_Module.modBaseSize;
			s_ModuleBase = s_Module.modBaseAddr;
			break;

		} while (Module32Next(s_Snapshot, &s_Module));

		CloseHandle(s_Snapshot);

		if (!s_ModuleBase || !s_ModuleSize)
		{
			CloseHandle(s_ProcessHandle);
			printf("Could not get the module for dumping.\n");
			return -3;
		}

		auto s_Memory = std::make_shared<void*>(malloc(s_ModuleSize));
		SecureZeroMemory(*s_Memory, s_ModuleSize);

#if defined(_WIN64)
		auto s_BytesRead = static_cast<size_t>(0);
#elif defined(_WIN32)
		auto s_BytesRead = static_cast<unsigned long>(0);
#endif
		auto s_Result = ReadProcessMemory(s_ProcessHandle, s_ModuleBase, *s_Memory, s_ModuleSize, &s_BytesRead);
		if (!s_Result)
		{
			CloseHandle(s_ProcessHandle);
			printf("Could not read process memory (%d).\n", GetLastError());
			return -4;
		}

		CloseHandle(s_ProcessHandle);

#if defined(_WIN64)
		printf("%llx bytes dumped.\n", s_BytesRead);
#elif defined(_WIN32)
		printf("%x bytes dumped.\n", s_BytesRead);
#endif

		auto s_StartPosition = reinterpret_cast<char*>(*s_Memory);
		auto s_EndPosition = s_StartPosition + s_ModuleSize;
		auto s_Success = false;
		for (auto s_CurrentPosition = s_StartPosition; s_CurrentPosition < s_EndPosition; s_CurrentPosition += 4)
		{
			//printf("Searching %x out of %x bytes, please wait...\n", s_EndPosition - s_CurrentPosition, s_EndPosition - s_StartPosition);

			auto l_Current = *reinterpret_cast<unsigned long*>(s_CurrentPosition);
			if (l_Current == 0x31415352) // 'RSA1'
			{
				FILE* s_File = nullptr;
				fopen_s(&s_File, "pub.bin", "wb");
				if (!s_File)
				{
					free(*s_Memory);
					s_Memory = nullptr;
					printf("Could not write public key file.\n");
					return -5;
				}

				auto s_Written = fwrite(s_CurrentPosition, 1, 0x11B, s_File);

#if defined(_WIN64)
				printf("%llx bytes written to public key file.\n", s_Written);
#elif defined(_WIN32)
				printf("%x bytes written to public key file.\n", s_Written);
#endif

				fclose(s_File);
				s_Success = true;
				break;
			}
		}

		free(*s_Memory);
		s_Memory = nullptr;

		printf(s_Success ? "encryption key(s) dumped.\n" : "encryption key(s) not found.\n");
	}
	catch (...)
	{

	}

	return 0;
}