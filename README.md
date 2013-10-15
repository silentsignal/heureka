Heureka
=======

A very suspicious piece of software - to test the effectiveness of heuristic AV engines/HIPS's/other magic.

After the Hacktivity I was pointed to [Matousec's toolkit](http://www.matousec.com/projects/security-software-testing-suite-64/) that basically has the same purpose as Heureka. This project will probably be abandoned.

Tasks
----- 

Tasks are model implementations of typical malware behaviour. They can be seen as micro-modules that can be switched on and off in order to find out if a product detects some specific behaviour.

* Evasion	
  * VirtualAlloc() WX
    * Execute code 
    * Encrypt/Decrypt 
      * XOR obfuscation 
      * Some standard algorithm, maybe RC4 [TODO]
      * Key derived from environment variables [TODO]
  * Detect virtualization [TODO]
  * Turn off AV [TODO]
  * Environment-based behaviour [TODO]
    * Current time
    * Environment variables (see Encryption)
    * CWD, ARGV, username
  * Digital signatures [TODO] 
* Data Acquisition
  * DLL injection 
    * Registry 
	* Hooks 
    * Key logging
	* CreateRemoteThread
    * Reflective DLL injection [TODO]
  * Look for office documents, PDFs
  * Install browser extensions [TODO]
    * Firefox
    * Chrome 
  * Get SYSTEM [TODO]
  * Cached domain credentials dump [TODO]
  * Dump LSA secrets [TODO]
  * GINA DLL [TODO]
    * Wlx* exports 
* Communication
  * Turn off Windows firewall [TODO]
  * Save log to %TEMP%
  * Communicate via HTTP 
    * Through configured proxy
    * Encrypted connection (HTTPS) [TODO]
    * ICMP tunneling [TODO]
    * DNS tunneling [TODO]
  * Connect back shell [TODO]
* Persistence
  * Set autostart 
    * Registry
    * Startup folder [TODO]
  * SvcHost DLL [TODO]
  * Download, store and execute [TODO]
  * Register service [TODO]
  * Set up WBEM scripts [TODO]
  * Change hosts file
  * Change DNS [TODO]
    

## Notes

The purpose of this software is to test the behavior-based capabilities of anti-virus/HIDS/other software, not to evade detection, so the tasks performed by heureka should not aim evasion but the realistic yet harmless implementation of real-world tactics. However, it should be noted that some evasion techniques can also be indicators of malicious behaviour, and they should be implemented as well.

Shellcode can be arbitrarily complex and can perform unpredictable actions. Typical shellcode behaviour should be implemented in Tasks. If shellcode injection/decoding/etc. is needed, it is recommended to use some simple, harmless code (like the MsgBox provided). 
  
Feature Requirements
--------------------

* Native executable (PE)
  * Easily convertable to DLL [TODO]
* Configurable / Modular
  * Command line [TODO]
  * Source code

Coding Guidelines
-----------------

* Task functions return void
* Output should be provided through the `print_XXX()` functions
* Task function should clean up after themselves (memory, file handles etc.)
  
References
----------

* <http://kb.eset.nl/esetkb/index?page=content&id=SOLN127>
* <https://www.symantec.com/avcenter/reference/heuristc.pdf>
* <http://www.symantec.com/connect/articles/heuristic-techniques-av-solutions-overview>
* <https://www.sans.org/reading_room/whitepapers/malicious/about-heuristics_141>
* <http://www.f-secure.com/export/system/fsgalleries/white-papers/f-secure_deepguard_whitepaper-06-11-2006.pdf>
* <http://www.symantec.com/connect/blogs/malware-using-fake-certificate-evade-detection>
