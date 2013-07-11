burpsuite-extensions
====================

BurpSuite Pro Python Extension

Some examples for implementing your custom burpsuite scanner issues through the jython extension.

CustomScanner.py:
This basically is a python version of the CustomScannerChecks example from http://blog.portswigger.net/2012/12/sample-burp-suite-extension-custom_20.html
(with some other tweeks)
After working it out a python version of it, I thought others might benefit.

IssueCreator.py
Let's you add an item from repeater or proxy history as a Scanner issue.  A context menu will show "Add as Scanner Issue" and
will then open a (horrible looking) window to write up your issue and then add it to scanner.
The main motivation for this one was after working on something in repeater to the point where it is a positive finding you now
can log it to keep track of it.
The gui needs work but it's a starting point.

- @luxcupitor
