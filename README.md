Heureka
=======

A very suspicious piece of software - to test the effectiveness of heuristic AV engines/HIPS's/other magic

Tasks
-----

  * VirtualAlloc() WX
    * Generate + Execute code (NOPs? More complex?)
  * Save log to %TEMP%
  * Encrypt/Decrypt
    * XOR obfuscation
    * Some standard algorithm (RC4?)
    * Key derived from environment variables?
  * Comminicate with .cn, .ru
    * Through configured proxy (HTTP(S))
    * ICMP ?
    * DNS ?
  * Set autostart
    * Registry
    * Startup folder
  * Look for office documents, PDFs
  * Long iterations (defeating execution simulation)

Feature Requirements
--------------------

* Native executable (PE)
  * Easily convertable to DLL ?
* Configurable / Modular
  * Command line
  * Source code

References
----------

http://kb.eset.nl/esetkb/index?page=content&id=SOLN127
https://www.symantec.com/avcenter/reference/heuristc.pdf
http://www.symantec.com/connect/articles/heuristic-techniques-av-solutions-overview
https://www.sans.org/reading_room/whitepapers/malicious/about-heuristics_141
http://www.f-secure.com/export/system/fsgalleries/white-papers/f-secure_deepguard_whitepaper-06-11-2006.pdf