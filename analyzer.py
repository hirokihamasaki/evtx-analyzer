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
import json
import ipdb
import codecs

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


def watch(fobj):

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
        ipdb.set_trace()
    return False


def dump_EventData_DataArray(fobj, source):

    result = []
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

        try:
            record = xmltodict.parse(event)
            dictTmp = OrderedDict()
            dictTmp["Time"] = record["Event"]["System"]["TimeCreated"]["@SystemTime"]
            dictTmp["Computer"] = record["Event"]["System"]["Computer"]
            try:
                dictTmp["EventID"] = record["Event"]["System"]["EventID"]["#text"]
            except:
                dictTmp["EventID"] = record["Event"]["System"]["EventID"]

            try:
                dictTmp["CorrelationID"] = record["Event"]["System"]["Correlation"]["@ActivityID"]
            except:
                dictTmp["CorrelationID"] = "-"

            try:
                dictTmp["ProcessID"] = record["Event"]["System"]["Execution"]["@ProcessID"]
            except:
                dictTmp["ProcessID"] = "-"

            try:
                dictTmp["ThreadID"] = record["Event"]["System"]["Execution"]["ThreadID"]
            except:
                dictTmp["ThreadID"] = "-"
            
            try:
                dictTmp["Channel"] = record["Event"]["System"]["Channel"]
            except:
                dictTmp["Channel"] = "-"
          
            try:
                dictTmp["Message"] = record["Event"]["RenderingInfo"]["Message"] 
            except:
                dictTmp["Message"] = "-"

            try:
                dictTmp["EventDataName"] = record["Event"]["EventData"]["@Name"]
            except:
                dictTmp["EventDataName"] = "-"


            if record["Event"]["EventData"]:
                if type(record["Event"]["EventData"]["Data"]) != list:
                    data = [record["Event"]["EventData"]["Data"]]
                else:
                    data = record["Event"]["EventData"]["Data"]

                for entry in data:
                    try:
                        dictTmp[entry["@Name"]] = entry["#text"]
                    except Exception as e:
                        print u"[Warning]: the entry has no #text key: {}".format(dict(entry))

            result.append(dictTmp)
           
        except Exception as e: 
            print e
            print u"[Warning]: couldn't parse {}".format(event)
            ipdb.set_trace()

    df = pd.DataFrame(result)
    
    if len(df) != 0:
        df.to_excel("dump{}.xlsx".format(source), index=False)

    return False


def dumpTermServLSandRCMngOpe(fobj, source):

    result = []
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
        try:
            record = xmltodict.parse(event)
            dictTmp = OrderedDict()
            dictTmp["Time"] = record["Event"]["System"]["TimeCreated"]["@SystemTime"]
            dictTmp["Computer"] = record["Event"]["System"]["Computer"]
            try:
                dictTmp["EventID"] = record["Event"]["System"]["EventID"]["#text"]
            except:
                dictTmp["EventID"] = record["Event"]["System"]["EventID"]

            try:
                dictTmp["CorrelationID"] = record["Event"]["System"]["Correlation"]["@ActivityID"]
            except:
                dictTmp["CorrelationID"] = "-"

            try:
                dictTmp["ProcessID"] = record["Event"]["System"]["Execution"]["@ProcessID"]
            except:
                dictTmp["ProcessID"] = "-"

            try:
                dictTmp["ThreadID"] = record["Event"]["System"]["Execution"]["ThreadID"]
            except:
                dictTmp["ThreadID"] = "-"
            
            try:
                dictTmp["Channel"] = record["Event"]["System"]["Channel"]
            except:
                dictTmp["Channel"] = "-"
          
            try:
                dictTmp["Message"] = record["Event"]["RenderingInfo"]["Message"] 
            except:
                dictTmp["Message"] = "-"

            try:
                if type(record["Event"]["UserData"]["EventXML"]) == list:
                    for data in record["Event"]["UserData"]["EventXML"]:
                        for key in data.keys():
                            dictTmp[key] = data[key]
                else:
                    data = record["Event"]["UserData"]["EventXML"]
                    for key in data.keys():
                        dictTmp[key] = data[key]
            except:
                pass

            result.append(dictTmp)
           
        except Exception as e: 
            print e
            ipdb.set_trace()
            print u"[Warning]: couldn't parse {}".format(event)

    df = pd.DataFrame(result)
    if len(df) != 0:
        df.to_excel("dump{}.xlsx".format(source), index=False)

    return False


def dumpSec462X(fobj):
    result_4624 = []
    result_4625 = []

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
        if record["Event"]["System"]["EventID"]["#text"] == "4625":
            dictTmp["Time"] = record["Event"]["System"]["TimeCreated"]["@SystemTime"]
            dictTmp["EventID"] = record["Event"]["System"]["EventID"]["#text"]
            
            for data in record["Event"]["EventData"]["Data"]:
                if "#text" in data:
                    dictTmp[data["@Name"]] = data["#text"]
                else:
                    dictTmp[data["@Name"]] = "-"

            result_4625.append(dictTmp)
        elif record["Event"]["System"]["EventID"]["#text"] == "4624":
            dictTmp["Time"] = record["Event"]["System"]["TimeCreated"]["@SystemTime"]
            dictTmp["EventID"] = record["Event"]["System"]["EventID"]["#text"]
            
            for data in record["Event"]["EventData"]["Data"]:
                if "#text" in data:
                    dictTmp[data["@Name"]] = data["#text"]
                else:
                    dictTmp[data["@Name"]] = "-"

            result_4624.append(dictTmp)
        else:
            pass

    df4624 = pd.DataFrame(result_4624)
    df4625 = pd.DataFrame(result_4625)
    if len(df4624) != 0:
        df4624.to_excel("4624.xlsx", sheet_name="4624")
    if len(df4625) != 0:
        df4625.to_excel("4625.xlsx", sheet_name="4625")

    return False


def analyze_tgt(fobj):
    result_4768 = []
    target_attr_4768 = ['TargetUserName', 'TargetDomainName', 'TargetSid', 'ServiceName', 
                            'ServiceSid', 'TicketOptions', 'Status', 'TicketEncryptionType',
                            'PreAuthType', 'IpAddress', 'IpPort', 'CertIssuerName',
                            'CertSerialNumber', 'CertThumbprint']
    result_4769 = []
    target_attr_4769 = ['TargetUserName', 'TargetDomainName', 'ServiceSid', 'ServiceName', 
                            'TicketOptions', 'Status', 'TicketEncryptionType',
                            'PreAuthType', 'IpAddress', 'IpPort', 'LogonGuid',
                            'TransmittedServices']
    
    
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
        if record["Event"]["System"]["EventID"]["#text"] == "4768" \
          or record["Event"]["System"]["EventID"]["#text"] == "4770":
            dictTmp["Time"] = record["Event"]["System"]["TimeCreated"]["@SystemTime"]
            dictTmp["EventID"] = record["Event"]["System"]["EventID"]["#text"]
            
            for data in record["Event"]["EventData"]["Data"]:
                if data["@Name"] in target_attr_4768:
                    if "#text" in data:
                        dictTmp[data["@Name"]] = data["#text"]
                    else:
                        dictTmp[data["@Name"]] = "-"

            result_4768.append(dictTmp)
        elif record["Event"]["System"]["EventID"]["#text"] == "4769":
            dictTmp["Time"] = record["Event"]["System"]["TimeCreated"]["@SystemTime"]
            dictTmp["EventID"] = record["Event"]["System"]["EventID"]["#text"]
            
            for data in record["Event"]["EventData"]["Data"]:
                if data["@Name"] in target_attr_4769:
                    if "#text" in data:
                        dictTmp[data["@Name"]] = data["#text"]
                    else:
                        dictTmp[data["@Name"]] = "-"

            result_4769.append(dictTmp)
        else:
            pass

    return output
    dfTgt = pd.DataFrame(result_4768)
    dfTgt["TicketEncryptionType"] = dfTgt["TicketEncryptionType"].apply(lambda x: "AES256-CTS-HMAC-SHA1-96" if x == "0x00000012" else "RC4-HMAC"  if x == "0x00000017" else x)
    dfTgt["TargetDomainName"] = dfTgt["TargetDomainName"].apply(lambda x: x+"(not capital)" if x.upper() != x else x)
    dfTgt = dfTgt.sort_values("Time")
    
    dfTgs = pd.DataFrame(result_4769)
    dfTgs["TicketEncryptionType"] = dfTgs["TicketEncryptionType"].apply(lambda x: "AES256-CTS-HMAC-SHA1-96" if x == "0x00000012" else "RC4-HMAC"  if x == "0x00000017" else x)
    dfTgs["TargetDomainName"] = dfTgs["TargetDomainName"].apply(lambda x: x+"(not capital)" if x.upper() != x else x)
    dfTgs = dfTgs.sort_values("Time")

    dfTgtTgs = pd.concat([dfTgt, dfTgs])

    if len(dfTgtTgs) != 0:
        dfTgtTgs.to_excel("4768_4769.xlsx", sheet_name="TGT-TGS-requests")

    output = pd.DataFrame()

    for tgsindex, tgsrow in dfTgs.iterrows():
        print "[-]target tgs: " + tgsrow["Time"] + " " + tgsrow["TargetUserName"]
        target = dfTgt[dfTgt["IpAddress"]==tgsrow["IpAddress"]]
        target = target[target["TargetUserName"].apply(lambda x: str(x).split("@")[0])==tgsrow["TargetUserName"].split("@")[0]]
        #target = target[target["TargetDomainName"].apply(lambda x: str(x).upper.split("(")[0]) ==str(tgsrow["TargetDomainName"]).upper()]

        if len(target) == 0:
            output = output.append(tgsrow)
            continue
         
        target.reset_index(drop=True, inplace=True)
        target = target.sort_values("Time")


        if timediff(target.loc[0]["Time"], tgsrow["Time"]) < 0:
            output = output.append(tgsrow)
        else:
            place = -1
            # find location where (tgs time > previous tgt time) and (tgs time < next tgt time)
            for index, targetrow in target.iterrows():
                if int(index) == len(target) - 1:
                    place = int(index)
                    break
                try:
                    if timediff(target.loc[int(index)+1]["Time"], tgsrow["Time"]) < 0:
                        place = int(index)
                        break
                except:
                    pass
            
            if timediff(target.loc[place]["Time"], tgsrow["Time"]) > 10*60*60:
                try: 
                    print "    [-]found tgt: " + target.loc[place]["Time"] + " " + target.loc[place]["TargetUserName"]
                except:
                    pass
                try: 
                    print "    [-]found tgt previous: " + target.loc[place-1]["Time"] + " " + target.loc[place-1]["TargetUserName"]
                except:
                    pass
                try: 
                    print "    [-]found tgt next: " + target.loc[place+1]["Time"] +" "+ target.loc[place+1]["TargetUserName"]
                except:
                    pass
                output = output.append(tgsrow)
            else:
                pass
            
    return output


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

    return output.ix[:,col]


def analyze_rdpclient(fobj):
    result_1024 = []
    result_1029 = []
    result_1026 = []
    result_1027 = []
    target_attr_1024 = ['Value']
    
    target_attr_1029 = ['TraceMessage']
    
    target_attr_1026 = ['Value']
    
    target_attr_1027 = ['DomainName','SessionId']

    
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
        if record["Event"]["System"]["EventID"]["#text"] == "1024":
            dictTmp["ConnectTime"] = record["Event"]["System"]["TimeCreated"]["@SystemTime"]
            dictTmp["Correlation ActivityID"] = record["Event"]["System"]["Correlation"]["@ActivityID"]
           

            if type(record["Event"]["EventData"]["Data"]) == list:
                for data in record["Event"]["EventData"]["Data"]:
                    if data["@Name"] in target_attr_1024:
                        if "#text" in data:
                            dictTmp[data["@Name"]] = data["#text"]
                        else:
                            dictTmp[data["@Name"]] = "-"
            else:
                if record["Event"]["EventData"]["Data"]["@Name"] in target_attr_1024:
                    if "#text" in record["Event"]["EventData"]["Data"]:
                        dictTmp[record["Event"]["EventData"]["Data"]["@Name"]] = \
                                    record["Event"]["EventData"]["Data"]["#text"]
                    else:
                        dictTmp[record["Event"]["EventData"]["Data"]["@Name"]] = "-"


            result_1024.append(dictTmp)

        elif record["Event"]["System"]["EventID"]["#text"] == "1029":
            dictTmp["Time"] = record["Event"]["System"]["TimeCreated"]["@SystemTime"]
            dictTmp["Correlation ActivityID"] = record["Event"]["System"]["Correlation"]["@ActivityID"]
            
            if type(record["Event"]["EventData"]["Data"]) == list:
                for data in record["Event"]["EventData"]["Data"]:
                    if data["@Name"] in target_attr_1029:
                        if "#text" in data:
                            dictTmp[data["@Name"]] = data["#text"]
                        else:
                            dictTmp[data["@Name"]] = "-"
            else:
                if record["Event"]["EventData"]["Data"]["@Name"] in target_attr_1029:
                    if "#text" in record["Event"]["EventData"]["Data"]:
                        dictTmp[record["Event"]["EventData"]["Data"]["@Name"]] = \
                                    record["Event"]["EventData"]["Data"]["#text"]
                    else:
                        dictTmp[record["Event"]["EventData"]["Data"]["@Name"]] = "-"
                
            
            result_1029.append(dictTmp)

        elif record["Event"]["System"]["EventID"]["#text"] == "1026":
            dictTmp["DisconnectTime"] = record["Event"]["System"]["TimeCreated"]["@SystemTime"]
            dictTmp["Correlation ActivityID"] = record["Event"]["System"]["Correlation"]["@ActivityID"]
           
            
            if type(record["Event"]["EventData"]["Data"]) == list:
                for data in record["Event"]["EventData"]["Data"]:
                    if data["@Name"] in target_attr_1026:
                        if "#text" in data:
                            dictTmp[data["@Name"]] = data["#text"]
                        else:
                            dictTmp[data["@Name"]] = "-"
            else:
                if record["Event"]["EventData"]["Data"]["@Name"] in target_attr_1026:
                    if "#text" in record["Event"]["EventData"]["Data"]:
                        dictTmp[record["Event"]["EventData"]["Data"]["@Name"]] = \
                                    record["Event"]["EventData"]["Data"]["#text"]
                    else:
                        dictTmp[record["Event"]["EventData"]["Data"]["@Name"]] = "-"
            
            if dictTmp["Value"] != "263": 
                result_1026.append(dictTmp)

        elif record["Event"]["System"]["EventID"]["#text"] == "1027":
            dictTmp["SuccessTime"] = record["Event"]["System"]["TimeCreated"]["@SystemTime"]
            dictTmp["Correlation ActivityID"] = record["Event"]["System"]["Correlation"]["@ActivityID"]
            
            if type(record["Event"]["EventData"]["Data"]) == list:
                for data in record["Event"]["EventData"]["Data"]:
                    if data["@Name"] in target_attr_1027:
                        if "#text" in data:
                            dictTmp[data["@Name"]] = data["#text"]
                        else:
                            dictTmp[data["@Name"]] = "-"
            else:
                if record["Event"]["EventData"]["Data"]["@Name"] in target_attr_1027:
                    if "#text" in record["Event"]["EventData"]["Data"]:
                        dictTmp[record["Event"]["EventData"]["Data"]["@Name"]] = \
                                    record["Event"]["EventData"]["Data"]["#text"]
                    else:
                        dictTmp[record["Event"]["EventData"]["Data"]["@Name"]] = "-"
            
            result_1027.append(dictTmp)

        else:
            pass

    dfConnect = pd.DataFrame(result_1024)
    dfConnect.rename(columns={"Value":"TargetServerIP"},inplace=True)
    dfConnect.to_csv("connect.csv")
    dfDisconnect = pd.DataFrame(result_1026)
    dfDisconnect.rename(columns={"Value":"DisconnectReason"},inplace=True)
    dfDisconnect.to_csv("disconnect.csv")
    output = pd.merge(dfConnect, dfDisconnect, on="Correlation ActivityID", how="left")
    
    dfUser = pd.DataFrame(result_1029)
    if len(dfUser) != 0:
        dfUser = dfUser.groupby("Correlation ActivityID")["TraceMessage"] \
                                     .apply( lambda x: "{%s}"%",".join(x)).reset_index()
        dfUser.rename(columns={"TraceMessage":"Base64(SHA1(UserName))"},inplace=True)
        dfUser.to_csv("user.csv")
        output = pd.merge(output, dfUser, on="Correlation ActivityID", how="left")

    dfSuccess = pd.DataFrame(result_1027)
    dfSuccess.to_csv("success.csv")
    if len(dfSuccess) != 0:
        output = pd.merge(output, dfSuccess, on="Correlation ActivityID", how="left")
    

    output["LogonDuration"] = pd.Series([timediff(output["SuccessTime"][i], output["DisconnectTime"][i]) \
                                            for i in xrange(0,len(output))])
    output.fillna("-",inplace=True)
    col = output.columns.tolist()
    col.remove('SuccessTime')
    col.insert(1,'SuccessTime')
    col.remove('DisconnectTime')
    col.insert(2,'DisconnectTime')
    col.remove('LogonDuration')
    col.insert(3,'LogonDuration')
    col.remove('Correlation ActivityID')
    col.insert(len(col),'Correlation ActivityID')

    return output.ix[:,col]


def main():
    choices = ["dump4624x", "dumpRDPTS", "dumpTaskOpe", "dumpLocalSessionMngOpe", "dumpSMBClientConn", "dumpRemoteConnMngOpe", "logon", "rdpclient", "goldenticket", "watch"]
    parser = argparse.ArgumentParser(
        description="Parse logon event combined with correspond logoff event.")
    parser.add_argument("xml", type=str, help="Path to the Windows event log xml")
    parser.add_argument("module", type=str, choices=choices, help="Analyze module such as logon, rdp, etc..")
    parser.add_argument("codecs", type=str, help="utf16 or utf8")
    args = parser.parse_args()

    if args.codecs == "utf8":
        fobj =  open(args.xml,"r")
    elif args.codecs == "utf16":
        fobj = codecs.open(args.xml, "r", "utf-16")
    else:
        print "Error: not supported codecs"
        exit()
    if args.module.lower() == "dump462x":
        result = dumpSec462X(fobj)
    elif args.module.lower() == "dumptaskope":
        result = dump_EventData_DataArray(fobj, "TaskOpe")
    elif args.module.lower() == "dumpsmbclientconn":
        result = dump_EventData_DataArray(fobj, "SMBClientConn")
    elif args.module.lower() == "dumprdpts":
        result = dump_EventData_DataArray(fobj, "RDPTS")
    elif args.module.lower() == "dumplocalsessionmngope":
        result = dumpTermServLSandRCMngOpe(fobj, "LocalSessionMngOpe")
    elif args.module.lower() == "dumpremoteconnmngope":
        result = dumpTermServLSandRCMngOpe(fobj, "RemoteConnMngOpe")
    elif args.module.lower() == "logon":
        result = analyze_logon(fobj)
    elif args.module.lower() == "rdpclient":
        result = analyze_rdpclient(fobj)
    elif args.module.lower() == "goldenticket":
        result = analyze_tgt(fobj)
    elif args.module.lower() == "watch":
        result = watch(fobj)
    else:
        print "Input module {} is not valid".format(args.module)
        exit()

    if result == False:
        return

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

