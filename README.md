# evtx-analyzer
These scripts help to check lateral movement activity by adversaries.
The output formt is Microsoft Excel(.xlsx) so that we can easily do further analysis and reporting to the customer.



## how to use
1. dump Security.evtx to xml format
 - `evtx_dump.py Security.evtx > Security.xml`
2. do analysis
 - `analyzer.py <xml file> <module name>`
 - `analyzer.py Security.xml logon`
 - `analyzer.py Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx rdpclient`

## Dependency
pip install python-evtx pandas openpyxl XlsxWriter

## analysis modules
### logon
We can get information below on each LUID(so called logon ID) which assigned by Windows authentication package from Security.evtx.
* "logontime/logofftime"
* "get privilege?"
* "do explicit credential use logon"? 
* etc...

### rdpclient
We can get information below on each Correlation ActivityID which assigned to each rdp connection attempt from Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx.
* ConnectTime
* logon success time
* target server ip
* disconnect reason
* etc...
