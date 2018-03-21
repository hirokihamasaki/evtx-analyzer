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
        try:
            time2 = datetime.strptime(strtime2, strptime)
        except:
            time2 = datetime.strptime(strtime2, "%Y-%m-%d %H:%M:%S")
        try:
            time1 = datetime.strptime(strtime1, strptime)
        except:
            time1 = datetime.strptime(strtime1, "%Y-%m-%d %H:%M:%S")
        delta = time2 - time1
        return delta.total_seconds()


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

def analyze_logon(fobj):
    result_4624 = []
    result_4634 = []
    result_4672 = []
    result_4648 = []
    target_attr_4624 = ['LogonType', 'TargetUserName', 'TargetDomainName', 
                            'IpAddress', 'IpPort', 'WorkstationName', 'ProcessName',
                            'AuthenticationPackageName', 'TransmittedServices',
                            'LmPackageName', 'KeyLength', 'SubjectUserName',
                            'SubjectUserSid', 'SubjectDomainName', 'SubjectLogonId',
                            'TargetUserSid', 'ProcessId', 'LogonProcessName',
                            'TargetLogonId']
    
    target_attr_4634 = ['TargetLogonId']
    
    target_attr_4672 = ['SubjectLogonId']
    
    target_attr_4648 = ['TargetServerName','TargetInfo','TargetUserName','TargetDomainName',
                        'IpAddress','IpPort','ProcessName','ProcessId','SubjectUserName',
                        'SubjectUserSid','SubjectDomainName','SubjectLogonId']

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
            dictTmp["LogonTime"] = record["Event"]["System"]["TimeCreated"]["@SystemTime"]
            
            for data in record["Event"]["EventData"]["Data"]:
                if data["@Name"] in target_attr_4624:
                    if "#text" in data:
                        dictTmp[data["@Name"]] = data["#text"]
                    else:
                        dictTmp[data["@Name"]] = "-"

            result_4624.append(dictTmp)

        elif record["Event"]["System"]["EventID"]["#text"] == "4634":
            dictTmp["LogoffTime"] = record["Event"]["System"]["TimeCreated"]["@SystemTime"]
            
            for data in record["Event"]["EventData"]["Data"]:
                if data["@Name"] in target_attr_4634:
                    if "#text" in data:
                        dictTmp[data["@Name"]] = data["#text"]
                    else:
                        dictTmp[data["@Name"]] = "-"

            result_4634.append(dictTmp)

        elif record["Event"]["System"]["EventID"]["#text"] == "4672":
            dictTmp["PrivEscalateTime(4672)"] = record["Event"]["System"]["TimeCreated"]["@SystemTime"]
            
            for data in record["Event"]["EventData"]["Data"]:
                if data["@Name"] in target_attr_4672:
                    if "#text" in data:
                        dictTmp[data["@Name"]] = data["#text"]
                    else:
                        dictTmp[data["@Name"]] = "-"
            if int(dictTmp['SubjectLogonId'],16) > 0x400: # under 0x500 is system account
                result_4672.append(dictTmp)

        elif record["Event"]["System"]["EventID"]["#text"] == "4648":
            dictTmp["ExplictLogonTime(4648)"] = record["Event"]["System"]["TimeCreated"]["@SystemTime"]
            
            for data in record["Event"]["EventData"]["Data"]:
                if data["@Name"] in target_attr_4648:
                    if "#text" in data:
                        dictTmp[data["@Name"]] = data["#text"]
                    else:
                        dictTmp[data["@Name"]] = "-"

            if int(dictTmp['SubjectLogonId'],16) > 0x400: # under 0x500 is system account
                result_4648.append(dictTmp)

        else:
            pass

    dfLogon = pd.DataFrame(result_4624)
    dfLogoff = pd.DataFrame(result_4634)
    dfGetPriv = pd.DataFrame(result_4672).groupby("SubjectLogonId")["PrivEscalateTime(4672)"] \
                                .apply( lambda x: "{%s}"%",".join(x)).reset_index()

    output = pd.merge(dfLogon, dfLogoff, on="TargetLogonId", how="left")
    output = pd.merge(output, dfGetPriv, left_on="TargetLogonId",right_on="SubjectLogonId", how="left")

    dfExplicitLogon = pd.DataFrame(result_4648)
    if len(dfExplicitLogon) != 0:
        dfExplicitLogon.to_excel("4648.xlsx", sheet_name="4648-explicit-logon")
        dfExplicitLogon = dfExplicitLogon.groupby("SubjectLogonId")["TargetServerName"].count().reset_index()
        dfExplicitLogon.rename(columns={"TargetServerName":"#ExplicitLogonTrial"},inplace=True)
        output = pd.merge(output, dfExplicitLogon, left_on="TargetLogonId", right_on="SubjectLogonId", how="left")
        output["#ExplicitLogonTrial"].fillna("-",inplace=True)

    output["LogonDuration"] = \
      pd.Series([timediff(output["LogonTime"][i], output["LogoffTime"][i]) for i in xrange(0,len(output))])
    output.rename(columns={"TargetLogonId":"LogonId"},inplace=True)
    col = output.columns.tolist()
    col.remove('LogoffTime')
    col.insert(1,'LogoffTime')
    col.remove('LogonDuration')
    col.insert(2,'LogonDuration')
    output.ix[:,col]

    return output.ix[:,col]


def analyze_rdpclient(fobj):
    result = []
    target_attr = ['Value']
    dictTmp = OrderedDict()
    
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
        if record["Event"]["System"]["EventID"]["#text"] == "4624":
            dictTmp["Time"] = record["Event"]["System"]["TimeCreated"]["@SystemTime"]
            dictTmp["Correlation ActivityID"] = record["Event"]["System"]["Correlation"]["@ActivityID"]
            
            for data in record["Event"]["EventData"]["Data"]:
                if data["@Name"] in target_attr:
                    if "#text" in data:
                        dictTmp[data["@Name"]] = data["#text"]
                    else:
                        dictTmp[data["@Name"]] = "-"

            result.append(dictTmp)

        else:
            pass

    dfLogon = pd.DataFrame(result)
    dfLogon.to_csv("rdpclient.csv")


def main():
    parser = argparse.ArgumentParser(
        description="Parse logon event combined with correspond logoff event.")
    parser.add_argument("xml", type=str, help="Path to the Windows event log xml")
    parser.add_argument("module", type=str, help="Analyze module such as logon, rdp, etc..")
    args = parser.parse_args()

    fobj =  open(args.xml,"r")
    if args.module.upper() == "LOGON":
        result = analyze_logon(fobj)
    elif args.module.upper() == "RDPCLIENT":
        result = analyze_rdpclient(fobj)
    else:
        print "Input module {} is not valid".format(args.xml)
        exit()

    outFile = "evtx_analysis_result_"+ args.module +".xlsx"
    pandas.io.formats.excel.header_style = None
    writer = pd.ExcelWriter(outFile)
    result.to_excel(writer, sheet_name=args.module)
    workbook = writer.book
    workbook.formats[0].set_font_name('Calibri')
    workbook.formats[0].set_font_size(9)
    workbook.formats[0].set_bold(False)
    workbook.formats[0].set_left(True)
    writer.save()




if __name__ == "__main__":
    main()

