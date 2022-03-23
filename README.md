# ACL Decrufter
(c) 2022, Chris Perkins


Parses IOS XE, NX-OS or EOS ACL output from show access-list command & attempts to de-cruft it by removing Access Control Entries (ACE) covered by an earlier deny, permit/deny with overlapping networks and/or merging permit/deny for adjacent networks.

Caveats:
1) IPv4 only & understands only a subset of ACL syntax, ignores remarks.
2) Attempts to minimise the number of ACEs, which may break the logic for chains of deny & permit statements. Test your results!


Version History:
* v0.1 - Initial development release.
