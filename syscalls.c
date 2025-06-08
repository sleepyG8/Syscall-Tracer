#include <windows.h>

/*
                        ========================================
                        =                                      =
                        =          Syscall Tracer              =
                        =              Sleepy                  =
                        =               2025                   =
                        =                                      =
                        ========================================

*/

char* getLocalExports(char* dll, char* function) {

//Usual PE stuff
//Get the dll handle
HMODULE hMod = LoadLibraryEx(dll, NULL, 0);
if (!hMod) {
    printf("Error Loading ntdll\n");
    return NULL;
}

//getting dos header
PIMAGE_DOS_HEADER dh = (PIMAGE_DOS_HEADER)hMod;
if (dh->e_magic != IMAGE_DOS_SIGNATURE) {
    printf("Error getting the dos header\n");
    return NULL;
}

//nt headers 
PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)dh + dh->e_lfanew);
if (nt->Signature != IMAGE_NT_SIGNATURE) {
    printf("Error getting the nt headers\n");
    return NULL;
}

//setting oh as the enumerated nt value
PIMAGE_OPTIONAL_HEADER oh = &nt->OptionalHeader;

//notice IMAGE_DIRECTORY_ENTRY_EXPORT this is needed onlu for exports but needs this order
PIMAGE_DATA_DIRECTORY exportDataDir = &oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

//setting export directory struct location
PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)oh->ImageBase + exportDataDir->VirtualAddress);

//===================================================================
//             This starts the syscall table exporting
//===================================================================

//Must set ordinals to get the location of the syscall stub
DWORD* functionRVAs = (DWORD*)((BYTE*)oh->ImageBase + exportDir->AddressOfFunctions);
WORD* ordinals = (WORD*)((BYTE*)oh->ImageBase + exportDir->AddressOfNameOrdinals);
int ordinalnum = -1;

DWORD* nameRVAs = (DWORD*)((BYTE*)oh->ImageBase + exportDir->AddressOfNames);

char *retAddress;
//loop 
for (size_t i = 0; i < exportDir->NumberOfNames; i++) {

    char* functionName = (char*)oh->ImageBase + nameRVAs[i];

    if (strcmp(functionName, function) == 0) {

    printf("Function: %s\n", (char*)oh->ImageBase + nameRVAs[i]);
    printf("address: 0x%p\n", (char*)oh->ImageBase + nameRVAs[i]);
    //printf("ordinals: %i\n", ordinals[i]);
    ordinalnum = ordinals[i];

    BYTE* func = (BYTE*)oh->ImageBase + functionRVAs[ordinalnum] + (BYTE)oh->ImageBase;

    //The 4th byte is usally where the syscall number lives
    printf("syscall: \033[32m%02X\033[0m\n", func[4]);

    /*
    Used for testing but I left in case you want it 
    for (int j=0; j < 20; j++) {
    printf("%02X ", func[j]);        
    }
    printf("\n");
    */

    retAddress = (char*)oh->ImageBase + nameRVAs[i];
    }

}
return retAddress;
}

int main(int argc, char* argv[]) {

if (argc < 2) {
    printf("Usage %s <function in ntdll>", argv[0]);
}

if (getLocalExports("ntdll.dll", argv[1]) == NULL) {
    printf("Error getting the syscall number\n");
}

}
