#include <cstdio>
#include <vector>

#include "minwin.hpp"

// Callback struct
PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION callback = { 0 };
bool flag = false;

std::vector<uintptr_t> hooked = {};

uintptr_t hook(uintptr_t R10, uintptr_t RAX/* ... */) {
	// This flag is there for prevent recursion
	if (!flag) {
		flag = true;

		uint8_t buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME] = { 0 };
		const auto symbol_info = (PSYMBOL_INFO)buffer;
		symbol_info->SizeOfStruct = sizeof(SYMBOL_INFO);
		symbol_info->MaxNameLen = MAX_SYM_NAME;
		uintptr_t displacement;

		// MSDN: Retrieves symbol information for the specified address.
		const auto result = SymFromAddr(GetCurrentProcess(), R10, &displacement, symbol_info);

		// Deny access if function is hooked
		if (result && std::find(hooked.begin(), hooked.end(), symbol_info->Address) != std::end(hooked)) {
			// Print what we know
			printf("[+] function: %s\n\treturn value: 0x%llx\n\treturn address: 0x%llx\n", symbol_info->Name, RAX, R10);
			RAX = STATUS_ACCESS_DENIED;
		}

		flag = false;
		return RAX;
	}

	return RAX;
}


int main()
{
	SymSetOptions(SYMOPT_UNDNAME);
	SymInitialize(GetCurrentProcess(), nullptr, TRUE);

	// Reserved is always 0
	callback.Reserved = 0;
	// x64 = 0, x86 = 1
	callback.Version = CALLBACK_VERSION;
	// Set our asm callback handler
	callback.Callback = medium;

	// Add hook for NtQVM
	hooked.push_back((uintptr_t)GetProcAddress(GetModuleHandleA("ntdll"), "NtQueryVirtualMemory"));

	// Setup the hook
	NtSetInformationProcess(GetCurrentProcess(), (PROCESS_INFORMATION_CLASS)0x28, &callback, sizeof(callback));
	printf("[+] hooked\n");

	// Run hooked function to test the hook
	MEMORY_BASIC_INFORMATION region = {nullptr};
	const auto status = NtQueryVirtualMemory(GetCurrentProcess(), GetModuleHandle(nullptr), MemoryBasicInformation, &region, sizeof(region), nullptr);
	
	// Check if unaffected functions don't crash
	NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)0, nullptr, 0, nullptr);

	callback.Callback = nullptr;

	// Remove callback
	NtSetInformationProcess(GetCurrentProcess(), (PROCESS_INFORMATION_CLASS)0x28, &callback, sizeof(callback));

	printf("[+] unhooked\n");
	// Print spoofed status
	printf("[+] NtQVM status: 0x%04X\n", status);
	getchar();
}
