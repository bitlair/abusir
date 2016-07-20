Abusir package
==============

Protects the network from rogue Router Advertisements. Allows the NOC to respond to rogue router advertisements, but in the meantime cancel out the settings, so that clients don't end up with bad MTUs, bad DNS search lists, bad recursive DNS or bad prefixes.

- To prevent MTU changes, it announces the correct MTU again.
- To prevent bad prefixes, it announces the prefix with a valid and preferred lifetime of 0.
- To prevent bad recursive DNS servers, it announces them with valid lifetime of 0.
- To prevent bad DNS search lists, it announces them with valid lifetime of 0.
- To prevent DoS by setting a reachable timer lower than the retransmit timer

Still to do:
- Guard other-config/managed flags (Need to test if this is necessary).


What's in the name
-------------------
Abusir prevents RA Abuse. Abusir is a platform in Egypt with temples for the sun god Ra. Praying to the god Ra at Abusir may work to restore the proper RA settings on the network. 
