#include<iostream>
#include<Windows.h>
#include<ctime>

// compilation setup
#define SHELLCODE 1
#define ALLOC_RWX_CALL 1
#define WRITE_LOG 1

// namespace setup
using namespace std;

// Constant dependencies
#if SHELLCODE==1 
static unsigned char shellcode[]="\xd9\xeb\x9b\xd9\x74\x24\xf4\x31\xd2\xb2\x77\x31\xc9\x64\x8b"
"\x71\x30\x8b\x76\x0c\x8b\x76\x1c\x8b\x46\x08\x8b\x7e\x20\x8b"
"\x36\x38\x4f\x18\x75\xf3\x59\x01\xd1\xff\xe1\x60\x8b\x6c\x24"
"\x24\x8b\x45\x3c\x8b\x54\x28\x78\x01\xea\x8b\x4a\x18\x8b\x5a"
"\x20\x01\xeb\xe3\x34\x49\x8b\x34\x8b\x01\xee\x31\xff\x31\xc0"
"\xfc\xac\x84\xc0\x74\x07\xc1\xcf\x0d\x01\xc7\xeb\xf4\x3b\x7c"
"\x24\x28\x75\xe1\x8b\x5a\x24\x01\xeb\x66\x8b\x0c\x4b\x8b\x5a"
"\x1c\x01\xeb\x8b\x04\x8b\x01\xe8\x89\x44\x24\x1c\x61\xc3\xb2"
"\x08\x29\xd4\x89\xe5\x89\xc2\x68\x8e\x4e\x0e\xec\x52\xe8\x9f"
"\xff\xff\xff\x89\x45\x04\xbb\x7e\xd8\xe2\x73\x87\x1c\x24\x52"
"\xe8\x8e\xff\xff\xff\x89\x45\x08\x68\x6c\x6c\x20\x41\x68\x33"
"\x32\x2e\x64\x68\x75\x73\x65\x72\x88\x5c\x24\x0a\x89\xe6\x56"
"\xff\x55\x04\x89\xc2\x50\xbb\xa8\xa2\x4d\xbc\x87\x1c\x24\x52"
"\xe8\x61\xff\xff\xff\x68\x6f\x78\x58\x20\x68\x61\x67\x65\x42"
"\x68\x4d\x65\x73\x73\x31\xdb\x88\x5c\x24\x0a\x89\xe3\x68\x58"
"\x20\x20\x20\x68\x65\x6b\x61\x21\x68\x48\x65\x75\x72\x31\xc9"
"\x88\x4c\x24\x08\x89\xe1\x31\xd2\x52\x53\x51\x52\xff\xd0\x31"
"\xc0\x50\xff\x55\x08"; // MsgBox from MSF
#endif

// utility functions
void print_status(const char *status){
	cout << "[+] " << status << endl;
}

void print_error(const char *status){
	cout << "[!] " << status << endl;
}

// test functions
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

// end of test functions - program entry point 
int main(int argc,char **argv){
	// set everything up
	setvbuf(stdout, NULL, _IONBF, 0);
	
	// test functions

	#if WRITE_LOG==1
	write_log();
	#endif

	#if SHELLCODE==1 && ALLOC_RWX_CALL==1
	alloc_rwx_call();
	#endif
	
	// clean up and exit
	return 1;
}