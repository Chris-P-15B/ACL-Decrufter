# ACL Decrufter
(c) 2022, Chris Perkins.


Parses IOS XE, NX-OS or EOS ACL output from show access-list command & attempts to de-cruft it by removing Access Control Entries (ACE) covered by an earlier deny, permit/deny with overlapping networks and/or merging permit/deny for adjacent networks.

Caveats:
1) IPv4 only & understands only a subset of ACL syntax (e.g. no object-groups), ignores remarks.
2) Attempts to minimise the number of ACEs, which may break the logic for chains of deny & permit statements. Test your results!


Version History:
* v0.3 - Added outputing to subnet mask & wildcard mask notations.
* v0.2 - Minor fixes.
* v0.1 - Initial development release.

# Pre-Requisites
* Python 3.7+

# Usage
Command line parameters, for those with spaces enclose the parameter in "":

* filename - path to a text file containing the show access-list output for a single ACL
* verbose - enables optional output of the intermediate ACL de-crufting stages

For example:

_python ACL_decrufter.py test-ACL.txt verbose_