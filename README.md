sosi
======

sosi provides an implementation of ISO/IEC 8326/8327, which are identical to ITU standards X.215 and X.225, defined at 

 https://www.itu.int/rec/T-REC-X.215-199511-I

and 

 https://www.itu.int/rec/T-REC-X.225-199511-I.

Documentation
-------------

...

License
-------

See the COPYING file.

Conformance
-------
As stated in X.225 Section 9.1 (Static conformance requirements)

"A system claiming conformance to this Recommendation | International Standard shall exhibit external
behaviour consistent with having implemented an SPM for the kernel functional unit together with either 
or both of the half-duplex and the duplex functional units."

In accordance to the above statement, sosi implements only the kernel, half duplex and duplex functional
units. This means that the SPDUs supported and implemented by sosi are:

* CN  - CONNECT
* OA  - OVERFLOW ACCEPT 
* CDO - CONNECT DATA OVERFLOW 
* AC  - ACCEPT
* RF  - REFUSE
* FN  - FINISH
* DN  - DISCONNECT
* AB  - ABORT
* AA  - ABORT ACCEPT
* DT  - DATA TRANSFER
* PR  - PREPARE
* GT  - GIVE TOKENS
* PT  - PLEASE TOKENS

Author
-------

Daniele Pala <pala.daniele@gmail.com>

Known bugs/limitations
-------

WIP.

