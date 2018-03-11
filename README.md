# security-evtx-analyzer
These scripts help to check lateral movement activity by adversaries.
We can get information like "logontime/logofftime", "get privilege?", "do explicit credential use logon"? on each LUID(so called logon ID) which assigned by Windowsauthentication package.
The output formt is Microsoft Excel(.xlsx) so that we can easily do further analysis and reporting to the customer.

## how to use
1. dump Security.evtx to xml format
 - `evtx_dump.py Security.evtx > Security.xml`
2. do logon analysis
 - `logon-analyzer.py Security.xml`

## Dependency
pip install python-evtx pandas openpyxl XlsxWriter
