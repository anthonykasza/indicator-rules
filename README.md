Indicator Rules
===============
This package provides a means of creating rules which are applied to connection records. It is an extension to the Intel framework.
If a connection record matches criteria in a rule, a notice is raised.

Rules can consist of a group of indicators, a group or rules, or groups of both. 
Rules include logical operations which are applied across a rule's indicators, nested rules, or both,

See example/ for how this package can be used. Try running:
```
bro example.bro -Cr sample.pcap
```
