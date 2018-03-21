#!/usr/bin/env python
import Evtx.Evtx as evtx
import Evtx.Views as e_views
import os
import sys
import pandas as pd
import argparse
import xmltodict
from collections import OrderedDict
import pandas.io.formats.excel
from datetime import datetime


def timediff(strtime1, strtime2, strptime="%Y-%m-%d %H:%M:%S.%f"):
    if pd.isna(strtime1) or pd.isna(strtime2):
        return "NULL"
    else:
        return datetime.strptime(strtime2, strptime) - datetime.strptime(strtime1, strptime)

def readuntil(fobj, string):
    data = ""
    cnt = 0
    while True:
        byte = fobj.read(1)
        if byte == "":
            return ""
        else:
            data += byte
        if string in data:
            return data

        
def main():
    parser = argparse.ArgumentParser(
        description="Parse logon event combined with correspond logoff event.")
    parser.add_argument("xml", type=str,
                        help="Path to the Windows event log xml")
    args = parser.parse_args()
    listDict4624 = [] 
    listTargetAttr4624 = ['LogonType', 'TargetUserName', 'TargetDomainName', 
                            'IpAddress', 'IpPort', 'WorkstationName', 'ProcessName',
                            'AuthenticationPackageName', 'TransmittedServices',
                            'LmPackageName', 'KeyLength', 'SubjectUserName',
                            'SubjectUserSid', 'SubjectDomainName', 'SubjectLogonId',
                            'TargetUserSid', 'ProcessId', 'LogonProcessName',
                            'TargetLogonId']
    fobj =  open(args.xml,"r")
    while True:
        try:
            event = readuntil(fobj, "</Event>")
            if event == "":
                break
        except:
            break
        try:
            event = event[event.find("<Event "):]
        except:
            print "There is </Event> but not <Event>. Conitnue to next"
            continue
        record = xmltodict.parse(event)

        dictTmp = OrderedDict()
        if record["Event"]["System"]["EventID"]["#text"] == "4624":
                dictTmp["Time"]=record["Event"]["System"]["TimeCreated"]["@SystemTime"]
                for data in record["Event"]["EventData"]["Data"]:
                    if data["@Name"] in listTargetAttr4624:
                        if "#text" in data:
                            dictTmp[data["@Name"]] = data["#text"]
                        else:
                            dictTmp[data["@Name"]] = "-"
                listDict4624.append(dictTmp)
        else:
            pass
    
    dfLogon = pd.DataFrame(listDict4624)
    dfLogon.to_csv("4624.csv")


if __name__ == "__main__":
    main()

