#!/usr/bin/env python
import Evtx.Evtx as evtx
import Evtx.Views as e_views
import os
import sys
import xml.etree.ElementTree as et
import pandas as pd
import argparse
from collections import OrderedDict
import pandas.io.formats.excel
from datetime import datetime


def timediff(strtime1, strtime2, strptime="%Y-%m-%d %H:%M:%S.%f"):
    if pd.isna(strtime1) or pd.isna(strtime2):
        return "NULL"
    else:
        delta = datetime.strptime(strtime2, strptime) - datetime.strptime(strtime1, strptime)
        return delta.total_seconds()


def core():
    parser = argparse.ArgumentParser(
        description="Parse logon event combined with correspond logoff event.")
    parser.add_argument("evtx", type=str,
                        help="Path to the Windows EVTX event log file")
    args = parser.parse_args()
    listDict4624 = [] 
    listDict4634 = []
    listDict4672 = []
    listDict4648 = []
    with open(args.evtx,"r") as fobj:
        logs = fobj.read().split("\n\n")
        for record in logs:
            try:
                elem = et.fromstring(record.replace("xmlns=\"","ns=\""))
            except:
                continue
            dictTmp = OrderedDict()
            if elem.findtext(".//EventID") == "4624":
                dictTmp["LogonTime"]=elem.find(".//TimeCreated").get("SystemTime")
                dictTmp["LogonType"]=elem.findtext(".//Data[@Name='LogonType']")
                dictTmp["TargetUserName"]=elem.findtext(".//Data[@Name='TargetUserName']")
                dictTmp["TargetDomainName"]=elem.findtext(".//Data[@Name='TargetDomainName']")
                dictTmp["IpAddress"]=elem.findtext(".//Data[@Name='IpAddress']")
                dictTmp["IpPort"]=elem.findtext(".//Data[@Name='IpPort']")
                dictTmp["WorkstationName"]=elem.findtext(".//Data[@Name='WorkstationName']")
                dictTmp["ProcessName"]=elem.findtext(".//Data[@Name='ProcessName']")
                dictTmp["AuthPackageName"]=elem.findtext(".//Data[@Name='AuthenticationPackageName']")
                dictTmp["TransmittedServices"]=elem.findtext(".//Data[@Name='TransmittedServices']")
                dictTmp["LmPackageName"]=elem.findtext(".//Data[@Name='LmPackageName']")
                dictTmp["KeyLength"]=elem.findtext(".//Data[@Name='KeyLength']")
                dictTmp["SubjectUserName"]=elem.findtext(".//Data[@Name='SubjectUserName']")
                dictTmp["SubjectUserSid"]=elem.findtext(".//Data[@Name='SubjectUserSid']")
                dictTmp["SubjectDomainName"]=elem.findtext(".//Data[@Name='SubjectDomainName']")
                dictTmp["SubjectLogonId"]=elem.findtext(".//Data[@Name='SubjectLogonId']")
                dictTmp["TargetUserSid"]=elem.findtext(".//Data[@Name='TargetUserSid']")
                dictTmp["ProcessId"]=elem.findtext(".//Data[@Name='ProcessId']")
                dictTmp["LogonProcessName"]=elem.findtext(".//Data[@Name='LogonProcessName']")
                dictTmp["LogonId"]=elem.findtext(".//Data[@Name='TargetLogonId']")
                listDict4624.append(dictTmp)
            elif elem.findtext(".//EventID") == "4634":
                dictTmp["LogoffTime"]=elem.find(".//TimeCreated").get("SystemTime")
                dictTmp["LogonId"]=elem.findtext(".//Data[@Name='TargetLogonId']")
                listDict4634.append(dictTmp)
            elif elem.findtext(".//EventID") == "4672":
                dictTmp["PrivEscalateTime"]=elem.find(".//TimeCreated").get("SystemTime")
                dictTmp["LogonId"]=elem.findtext(".//Data[@Name='SubjectLogonId']")
                if int(dictTmp["LogonId"],16) > 0x400:
                    listDict4672.append(dictTmp)
            elif elem.findtext(".//EventID") == "4648":
                dictTmp["TryLogonOtherMachineTime"]=elem.find(".//TimeCreated").get("SystemTime")
                dictTmp["TargetServerName"]=elem.findtext(".//Data[@Name='TargetServerName']")
                dictTmp["TargetInfo"]=elem.findtext(".//Data[@Name='TargetInfo']")
                dictTmp["TargetUserName"]=elem.findtext(".//Data[@Name='TargetUserName']")
                dictTmp["TargetDomainName"]=elem.findtext(".//Data[@Name='TargetDomainName']")
                dictTmp["IpAddress"]=elem.findtext(".//Data[@Name='IpAddress']")
                dictTmp["IpPort"]=elem.findtext(".//Data[@Name='IpPort']")
                dictTmp["ProcessName"]=elem.findtext(".//Data[@Name='ProcessName']")
                dictTmp["ProcessId"]=elem.findtext(".//Data[@Name='ProcessId']")
                dictTmp["SubjectUserName"]=elem.findtext(".//Data[@Name='SubjectUserName']")
                dictTmp["SubjectUserSid"]=elem.findtext(".//Data[@Name='SubjectUserSid']")
                dictTmp["SubjectDomainName"]=elem.findtext(".//Data[@Name='SubjectDomainName']")
                dictTmp["LogonId"]=elem.findtext(".//Data[@Name='SubjectLogonId']")
                if int(dictTmp["LogonId"],16) > 0x400:
                    listDict4648.append(dictTmp)
            else:
                pass

    dfLogon = pd.DataFrame(listDict4624)
    dfLogoff = pd.DataFrame(listDict4634)
    dfGetPriv = pd.DataFrame(listDict4672).groupby("LogonId")["PrivEscalateTime"] \
      .apply( lambda x: "{%s}"%",".join(x)).reset_index()
    dfOut = pd.merge(dfLogon, dfLogoff, on="LogonId", how="left")
    dfOut = pd.merge(dfOut, dfGetPriv, on="LogonId", how="left")
    
    df4648 = pd.DataFrame(listDict4648)
    if len(df4648) != 0:
        dfGetPriv.to_excel("4672.xlsx", sheet_name="Logon-off")
        df4648.to_excel("4648.xlsx", sheet_name="Logon-off")
        df4648 = df4648.groupby("LogonId")["TargetServerName"].count().reset_index()
        df4648.rename(columns={"TargetServerName":"#ExplicitLogonTrial"},inplace=True)
        dfOut = pd.merge(dfOut, df4648, on="LogonId", how="left")
        dfOut["#ExplicitLogonTrial"].fillna("-",inplace=True)

    dfOut["LogonDuration"] = \
      pd.Series([timediff(dfOut["LogonTime"][i], dfOut["LogoffTime"][i]) for i in xrange(0,len(dfOut))])
    col = dfOut.columns.tolist()
    col.remove('LogoffTime') 
    col.insert(1,'LogoffTime')
    col.remove('LogonDuration') 
    col.insert(2,'LogonDuration')
    dfOut.ix[:,col]
    
    return dfOut.ix[:,col]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Parse logon event combined with correspond logoff event.")
    parser.add_argument("evtx", type=str,
                        help="Path to the Windows EVTX event log file")
    args = parser.parse_args()
    result = core()
    outFile = "evtx_analysis_result_"+os.path.splitext(os.path.basename(args.evtx))[0]+".xlsx"
    outFile2 = "evtx_analysis_result_"+os.path.splitext(os.path.basename(args.evtx))[0]+".csv"
    pandas.io.formats.excel.header_style = None
    writer = pd.ExcelWriter(outFile)
    result.to_excel(writer, sheet_name="Logon-off")
    result.to_csv(outFile2)
    workbook = writer.book
    workbook.formats[0].set_font_name('Calibri')
    workbook.formats[0].set_font_size(9)
    workbook.formats[0].set_bold(False)
    workbook.formats[0].set_left(True)
    writer.save()


