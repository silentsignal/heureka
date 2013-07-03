#pragma comment(lib, "winhttp.lib")
#include "heurekadll.h"
#include<iostream>
#include<Windows.h>
#include<winhttp.h>
#include<Strsafe.h>

namespace heurekadll{

	void Heureka(){
		MessageBox(NULL, L"HeurekaDLL!",L"Heureka",MB_OK);
	}


}
using namespace std;

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,  // handle to DLL module
    DWORD fdwReason,     // reason for calling function
    LPVOID lpReserved )  // reserved
{
    // Perform actions based on the reason for calling.
    if (fdwReason == DLL_PROCESS_ATTACH){
		heurekadll::Heureka();
	}
    return TRUE;  // Successful DLL_PROCESS_ATTACH.
}