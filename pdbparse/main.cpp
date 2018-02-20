//example: parse the wow64 and win32 (if x64) ntdlls for ApiSetResolveToHost and LdrpHandleTlsData which are not exported but present in the pdb, then output their addresses

#include <iostream>
#include <iomanip>
#include "pdbparse.hpp"

//helper function to parse a module
static module_t get_module_info(std::string_view path, bool is_wow64)
{
	//read raw bytes
	const auto file = CreateFileA(path.data(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);

	if (!file || file == INVALID_HANDLE_VALUE)
		return module_t();

	//get file size
	const auto file_size = GetFileSize(file, nullptr);

	if (!file_size)
		return module_t();

	//allocate dll bytes and read it
	auto module_on_disk = std::make_unique<uint8_t[]>(file_size);
	ReadFile(file, reinterpret_cast<LPVOID>(module_on_disk.get()), file_size, nullptr, nullptr);

	//set image headers
	auto dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(module_on_disk.get());
	auto image_headers = reinterpret_cast<void*>(module_on_disk.get() + dos_header->e_lfanew);

	auto image_headers32 = reinterpret_cast<IMAGE_NT_HEADERS32*>(image_headers);
	auto image_headers64 = reinterpret_cast<IMAGE_NT_HEADERS64*>(image_headers);

	CloseHandle(file);

	//map sections
	IMAGE_SECTION_HEADER *sections_array = nullptr;
	int section_count = 0;

	std::unique_ptr<uint8_t[]> module_in_memory = nullptr;
	if (is_wow64)
	{
		module_in_memory = std::make_unique<uint8_t[]>(image_headers32->OptionalHeader.SizeOfImage);
		sections_array = reinterpret_cast<IMAGE_SECTION_HEADER*>(image_headers32 + 1);
		section_count = image_headers32->FileHeader.NumberOfSections;
	}
	else
	{
		module_in_memory = std::make_unique<uint8_t[]>(image_headers64->OptionalHeader.SizeOfImage);
		sections_array = reinterpret_cast<IMAGE_SECTION_HEADER*>(image_headers64 + 1);
		section_count = image_headers64->FileHeader.NumberOfSections;
	}

	for (int i = 0; i < section_count; i++)
	{
		//"This section's contents shouldn't be put in the final EXE file. These sections are used by the compiler/assembler to pass information to the linker."
		if (sections_array[i].Characteristics & 0x800)
			continue;

		//if it's uninitialized data (.bss) we can just set it to zero since its data doesnt exist on disk
		if (sections_array[i].Characteristics & 0x80)
		{
			memset(module_in_memory.get() + sections_array[i].VirtualAddress, 0, sections_array[i].SizeOfRawData);
			continue;
		}

		memcpy_s(module_in_memory.get() + sections_array[i].VirtualAddress, sections_array[i].SizeOfRawData, module_on_disk.get() + sections_array[i].PointerToRawData, sections_array[i].SizeOfRawData);
	}

	return module_t(0, module_on_disk, module_in_memory, dos_header, path, image_headers);
}

static void output_function_address(std::string_view function_name, const module_t &module_info, bool is_wow64)
{
	const auto function_address = pdb_parse::get_address_from_symbol(function_name, module_info, is_wow64);

	if (function_address)
		std::cout << function_name << " found: 0x" << std::setfill('0') << std::setw(16) << std::hex << function_address << std::endl;
	else
		std::cout << function_name << " not found!" << std::endl;
};

int main(int argc, char **argv)
{
	std::cout << "x86 ntdll:" << std::endl;

	auto ntdll32 = get_module_info("C:\\Windows\\SysWOW64\\ntdll.dll", true);

	//if the OS is x86-based, this will be stored in system32
	if (!ntdll32)
		ntdll32 = get_module_info("C:\\Windows\\System32\\ntdll.dll", true);

	output_function_address("ApiSetResolveToHost", ntdll32, true);
	output_function_address("LdrpHandleTlsData", ntdll32, true);

	if constexpr(sizeof(void*) != 4)
	{
		std::cout << "\nx64 ntdll:" << std::endl;

		const auto ntdll64 = get_module_info("C:\\Windows\\System32\\ntdll.dll", false);

		output_function_address("ApiSetResolveToHost", ntdll64, false);
		output_function_address("LdrpHandleTlsData", ntdll64, false);
	}

	std::cin.get();

	return 0;
}