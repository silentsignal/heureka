Heureka
=======

A very suspicious piece of software - to test the effectiveness of heuristic AV engines/HIPS's/other magic

Tasks
----- 

The purpose of this software is to test the behavior-based capabilities of anti-virus/HIDS/other software, not to evade detection, so the tasks performed by heureka should not aim evasion but the realistic yet harmless implementation of real-world tactics.
	
  * VirtualAlloc() WX
    * Generate + Execute code (NOPs? More complex?)
  * Save log to %TEMP% [TODO]
  * Encrypt/Decrypt [TODO]
    * XOR obfuscation 
    * Some standard algorithm, maybe RC4 
    * Key derived from environment variables 
  * Comminicate with .cn, .ru [TODO] 
    * Through configured proxy (HTTP(S))
    * ICMP ?
    * DNS ?
  * Set autostart [TODO]
    * Registry
    * Startup folder
  * Look for office documents, PDFs [TODO]

Feature Requirements
--------------------

* Native executable (PE)
  * Easily convertable to DLL [TODO]
* Configurable / Modular
  * Command line [TODO]
  * Source code

References
----------

* <http://kb.eset.nl/esetkb/index?page=content&id=SOLN127>
* <https://www.symantec.com/avcenter/reference/heuristc.pdf>
* <http://www.symantec.com/connect/articles/heuristic-techniques-av-solutions-overview>
* <https://www.sans.org/reading_room/whitepapers/malicious/about-heuristics_141>
* <http://www.f-secure.com/export/system/fsgalleries/white-papers/f-secure_deepguard_whitepaper-06-11-2006.pdf>