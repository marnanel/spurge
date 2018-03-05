I'm in the middle of bringing spurge up to modern packaging standards.


----


SPURGE v0.5.0 - VERY BRIEF RELEASE NOTES

This is a complete rewrite of spurge v0.30 in Python.
To get started, type "make install" as root.

What's been gained:
~~~~~~~~~~~~~~~~~~~
 - An installation script.
 - A man page.
 - The code is now much simpler and easier to work with.

What's been lost:
~~~~~~~~~~~~~~~~~
These features were in v0.30, but not this version.
They will all be included in v0.6.0:

 - The ordinary user command ELOG.
 - The editor commands EDLK, EDUL, EDIT, EDIX, EDCF, EDAB and MOTS.
 - rDNS lookup in logging.

The test suite is under construction. It should be ready for the next
version.

Before the system is ready for v1.0.0, the commands ALVL, DIFF and UDBM
must be implemented, which never worked in v0.30; so must email notification,
the "eligible" option in the config files, and a lot of documentation.
