Heureka
=======

A very suspicious piece of software - to test the effectiveness of heuristic AV engines/HIPS's/other magic.

Tasks
----- 

Tasks are model implementations of typical malware behaviour. They can be seen as micro-modules that can be switched on and off in order to find out if a product detects some specific behaviour.
	
  * VirtualAlloc() WX
    * Generate + Execute code (NOPs? More complex?)
  * DLL injection 
    * Registry [TODO]
	* Hooks [TODO]
	* CreateRemoteThread
    * Reflective DLL injection [TODO]
  * Turn off Windows firewall [TODO]
  * Save log to %TEMP%
  * Encrypt/Decrypt [TODO]
    * XOR obfuscation 
    * Some standard algorithm, maybe RC4 
    * Key derived from environment variables 
  * Comminicate with .cn, .ru [TODO] 
    * Through configured proxy (HTTP(S))
    * ICMP tunneling
    * DNS tunneling
  * Set autostart 
    * Registry
    * Startup folder [TODO]
  * Detect virtualization [TODO]
  * Turn off AV [TODO]
  * Set up WBEM scripts [TODO]
  * Look for office documents, PDFs [TODO]
  * Environment-based behaviour [TODO]
    * Current time
    * Environment variables (see Encryption)
    * CWD, ARGV, username
  * Change hosts file [TODO]
  * Change DNS [TODO]
  * Connect back shell [TODO]
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
