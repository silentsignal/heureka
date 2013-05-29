#include "heurekadll.h"
#include<Windows.h>

namespace heurekadll{
	void Heureka(){
		MessageBox(NULL, L"HeurekaDLL!",L"Heureka",MB_OK);
	}


}

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,  // handle to DLL module
    DWORD fdwReason,     // reason for calling function
    LPVOID lpReserved )  // reserved
{
    // Perform actions based on the reason for calling.
    if (fdwReason == DLL_PROCESS_ATTACH)
            heurekadll::Heureka();
    return TRUE;  // Successful DLL_PROCESS_ATTACH.
}