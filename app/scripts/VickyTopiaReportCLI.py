#Author: Joaldir Rani
#changed
import argparse
from tqdm import tqdm
import time
import pandas as pd
import MitigationTime as mt
import cleanData as cd
import numpy as np
import os 
import shutil
import gc
from crontab import CronTab

import json

import VickyState as state
import EndpointsEventTask as tasks
import EndpointVulnerabilities as vuln
import Endpoint as assets
import PatchsByAssets as patchs
import EndpointPublisherProductVersions as products
import IncidentsEvents as incidents
import EndpointGroups as groups
import DatabaseConnector as db
import updateExternalScore as updExSc
import apprisk as apprisk
import gc

#from urllib.request import urlopen

from datetime import datetime, timedelta
from dateutil.relativedelta import relativedelta

errorList = [] 
def read_secret(secret_name):
    # Validate secret name to prevent path traversal
    if not secret_name or not isinstance(secret_name, str):
        print(f"Invalid secret name type: {type(secret_name)}")
        return None
        
    # Only allow alphanumeric characters, underscores, and hyphens
    if not secret_name.replace('_', '').replace('-', '').isalnum():
        print(f"Invalid secret name format: {secret_name}")
        return None
    
    secret_path = f'/run/secrets/{secret_name}'
    
    # Ensure the resolved path is within the secrets directory
    if not os.path.abspath(secret_path).startswith('/run/secrets/'):
        print(f"Invalid secret path: {secret_path}")
        return None
    
    try:
        with open(secret_path, 'r') as secret_file:
            return secret_file.read().strip()
    except IOError:
        print(f"Unable to read the secret: {secret_name}")
        return None

DEFAULT_QUERY_LIMIT_PER_MINUTE = 55

# Track the last time a query was made
last_query_time = 0

def control_rateold(query_limit=None):
    global last_query_time

        # Use the default rate limit if none is provided
    if query_limit is None:
        query_limit = DEFAULT_QUERY_LIMIT_PER_MINUTE

    # Calculate the time since the last query
    elapsed_time = time.time() - last_query_time

    # If less than a minute has passed since the last query, wait
    if elapsed_time < 60:
        # Calculate the time to sleep based on the desired rate
        sleep_time = max(0, (60 / query_limit) - elapsed_time)
        time.sleep(sleep_time)

    # Update the last query time
    last_query_time = time.time()

def control_rate(query_limit=50):
    global last_query_time

    # Calculate time since the last query and impose sleep if needed
    elapsed_time = time.time() - last_query_time
    if elapsed_time < (60 / query_limit):
        time.sleep((60 / query_limit) - elapsed_time)

    # Update the last query time
    last_query_time = time.time()

parser = argparse.ArgumentParser(description='Args for VikyTopiaReport')
parser.add_argument('-k', '--api-key', dest='apiKey', action='store', required=False, help='Topia API key')
parser.add_argument('-d', '--dashboard', dest='dashboard', action='store', required=False, help='Url dashboard ex. https://xxxx.vicarius.cloud')
parser.add_argument('--allreports', dest='allreports', action='store_true', help='All Reports')
parser.add_argument('-a', '--assetsreport', dest='assetsreport', action='store_true', help='Assets Reports')
parser.add_argument('-t', '--taskreport', dest='tasksreport', action='store_true', help='Task Reports')
parser.add_argument('-v', '--vulnerabilitiesreport', dest='vulnreport', action='store_true', help='Vulnerabilities Reports')
parser.add_argument('-p', '--patchsreport', dest='patchsreport', action='store_true', help='Patchs Versions Reports')
parser.add_argument('-hp', '--hasPatchAppsreport', dest='hasPatchAppsreport', action='store_true', help='Apps by Risk Level with Has_Patch')
parser.add_argument('-i', '--incidentvulnerability', dest='incidentvulreport', action='store_true', help='Vulnerabilities Reports')
parser.add_argument('-e', '--eventlog', dest='eventreport', action='store_true', help='Event Log Report')
parser.add_argument('-x', '--xprotect', dest='impersonationreport', action='store_true', help='xProtect Log Report')
parser.add_argument('-r', '--resetstate', dest='resetstate', action='store_true', help='Reset State')
parser.add_argument('-mt', '--mitigationtime', dest='mitigationtime', action='store_true', help='mitigation time')
parser.add_argument('-cd', '--cleandata', dest='cleandata', action='store_true', help='cleandata') 
parser.add_argument('-u', '--updatestate', dest='updatestate', action='store_true', help='updatestate')
parser.add_argument('-uex', '--updateExternalScore', dest='updateExternalScore', action='store_true', help='updateExternalScore') 
parser.add_argument('--external', dest='external', action='store_true', help='Update KEV + EPSS external vulnerability data')
parser.add_argument('--metabaseTempalateBackup', dest='metabaseTempalateBackup', action='store_true', help='metabaseTempalateBackup')
parser.add_argument('--metabaseTempalateReplace', dest='metabaseTempalateReplace', action='store_true', help='metabaseTempalateReplace') 
parser.add_argument('--createMBUser', dest='createMBUser', action='store_true')
parser.add_argument('-sd', '--start-date', dest='start_date', type=str, help='Start date for the report in YYYY-MM-DD format', default=None)
parser.add_argument('-ed', '--end-date', dest='end_date', type=str, help='End date for the report in YYYY-MM-DD format', default=None)
parser.add_argument('--version', action='version', version='4.0')
parser.add_argument('--refreshTables', dest='refreshTables', action='store_true', help='refreshTables')
parser.add_argument('--difTables', dest='difTables', action='store_true', help='difTables')
parser.add_argument('--activeVulnsTable', dest='activeVulnsTable', action='store_true', help='activeVulnsTable')
parser.add_argument('-tw', '--taskWaiting', dest='tasksWaitingreport', action='store_true', help='Task Waiting Reports')

args = parser.parse_args()

# Get the Credentials

apikey = read_secret('api_key')
organization_domain = read_secret('dashboard_id')
urldashboard = f"https://{organization_domain}.vicarius.cloud"

#Initialization Postgresql
host = "appdb"
port = "5432"
user = read_secret('postgres_user')
password = read_secret('postgres_password')
database = read_secret('postgres_db')
optionalTools = read_secret('optional_tools')

substring = ","
if substring in optionalTools:
    tools = optionalTools.split(',')
else:
    tools = optionalTools
print("####################################")
print("####################################")
print("####################################")
print("Beginning a new Run")
print("####################################")
print("####################################")
print("####################################")

print (f"Dashboard URL is ", {urldashboard})


# Use environment variable with secure default
statepath = os.getenv('STATE_FILE_PATH', '/usr/src/app/reports/state.json')

# Validate the path is within expected boundaries
if not os.path.abspath(statepath).startswith('/usr/src/app/'):
    raise ValueError(f"Invalid state file path: {statepath}")

if os.path.exists(statepath):
    print("Reading state.json from reports")
    dictState = state.getState()
else:
    print("copying state.json to reports ")
    srcpath = os.getenv('STATE_SOURCE_PATH', '/usr/src/app/scripts/state.json')
    
    # Validate source path as well
    if not os.path.abspath(srcpath).startswith('/usr/src/app/'):
        raise ValueError(f"Invalid source path: {srcpath}")
        
    shutil.copyfile(srcpath, statepath)
    print("Reading state.json from reports")
    dictState = state.getState()

#Version Check 
##get latest version 
#textpage = urlopen("https://www.w3.org/TR/PNG/iso_8859-1.txt")
#text = str(textpage.read(), 'utf-8')
#Get the Stats and Reports Names

def getAllEndpointsTasks(fr0m,siz3,maxDate,minDate):
    #print(minDate)
    #print(maxDate)
    if len(str(minDate)) == 19:
        #print("mindate in nanosecond")
        hmindate = datetime.fromtimestamp(int(minDate) / 1000000000).isoformat()
    elif len(str(minDate)) == 16:
        print("mindate in microsecond") 
        hmindate = datetime.fromtimestamp(int(minDate) / 1000000).isoformat()
    elif len(str(minDate)) == 13:
        print("mindate in Milisecond")
        hmindate = datetime.fromtimestamp(int(minDate) / 1000).isoformat()
    elif len(str(minDate)) == 10:
        print("mindate in seconds") 

    if len(str(maxDate)) == 19:
        #print("maxDate in nanosecond")
        hmaxdate = datetime.fromtimestamp(int(maxDate) / 1000000000).isoformat()
    elif len(str(maxDate)) == 16:
        print("maxDate in microsecond") 
        hmaxdate = datetime.fromtimestamp(int(maxDate) / 1000000).isoformat()
    elif len(str(maxDate)) == 13:
        print("maxDate in Milisecond")
        hmaxdate = datetime.fromtimestamp(int(maxDate) / 1000).isoformat()
    elif len(str(maxDate)) == 10:
        print("maxDate in seconds") 

    print("minDate->" + hmindate)
    print("maxDate->" + hmaxdate)

    
    control_rate (50)
    if maxDate is None:
        print("last date quireid")

    else:
        try:
            tasks_list,lastdate = tasks.getTasksEndopintsEvents(apikey,urldashboard,fr0m,siz3,maxDate,minDate)
        except Exception as e:
            #print("lastdate= " + str(lastdate))
            print (f"An exception occurred: {e}")
            print(tasks_list)
            print(lastdate)
            
            tasks_list = ""
            #maxDate = str(lastdate)
            
    try:
        if tasks_list == 0:
            print("No More Events")

        elif len(tasks_list) > 0:
            #writeReport(dictState['reportNameEventsTasks'],strTasks)
            print("Inserting tasks into the DB: " + str(len(tasks_list)))
            db.insert_into_table_tasks(tasks_list, host, port, user, password, database)
            
            maxDate = str(lastdate)
            del tasks_list
            #dictState.update({'lastEndpointsEventTask': lastdate})
            
            #state.setState(dictState)

            getAllEndpointsTasks(fr0m,siz3,maxDate,minDate)
        else:
            print("No More Events")
    except:
        print("Cannot determine task_list value")

def getWaitingEndpoitnTasks():
    two_weeks_ago = datetime.now() - timedelta(days=7)
    timenow = datetime.now()
    timestamp_in_seconds = two_weeks_ago.timestamp()
    timestamp_now_in_seconds = timenow.timestamp()
    # Convert seconds to nanoseconds
    timestamp_in_nanoseconds = int(timestamp_in_seconds * 1e9)
    timestamp_now_in_nanoseconds = int(timestamp_now_in_seconds * 1e9)
    print(f"between {two_weeks_ago} and {timenow} ")
    waitingdf = db.load_tasks_waiting_to_df(two_weeks_ago, host, port, user, password, database)
    print("obtained Waiting Automations")
    #print(waitingdf)
    if len(waitingdf) > 0:

        #print(waitingdf)
        for index, row in waitingdf.iterrows():
            lastdate = timestamp_in_nanoseconds
            #print(row)
            aID = row['automation_id']
            print(f"querying automation: {aID}")
            #dropwaiting tasks
            #db.drop_tasks_waiting_to_df(two_weeks_ago, host, port, user, password, database, aID)
            print("Dropped Waiting Automations")
            query = 0 
            src = 1 
            fr0m = 0 
            siz3 = 500
            while src > 0: 
                try:
                    query += 1
                    print(f"query: {query}")
                    tasks_list, lastdate = tasks.getTasksEndopintsEventsWaiting(apikey,urldashboard,fr0m,siz3,str(timestamp_now_in_nanoseconds),str(lastdate),str(aID))
                    print(lastdate)
                except Exception as e:
                    #print("lastdate= " + str(lastdate))
                    print (f"An exception occurred: {e}")
                    print(tasks_list)
                    print(lastdate)
                    src = 0 
                    tasks_list = ""
                    #maxDate = str(lastdate)
                try:
                    if tasks_list == 0:
                        print("No More Events")
                        src = 0 

                    elif len(tasks_list) > 0:
                        #writeReport(dictState['reportNameEventsTasks'],strTasks)
                        print("Inserting tasks into the DB: " + str(len(tasks_list)))
                        db.update_table_tasks(tasks_list, host, port, user, password, database)
                        
                        timestamp_in_nanoseconds = str(lastdate)
                        del tasks_list
                    else:
                        print("No More Events")
                        src = 0
                except:
                    print("Cannot determine task_list value")
                    src = 0 
    else: 
        print("No Tasks in Waiting")

def getAllEndpoitsold(fr0m,siz3,count,pbar):
    control_rate(20)
    try:
        strEndpoints,strEPStatus = assets.getEndpoints(apikey,urldashboard,fr0m,siz3)
        print("endpoints returned")
    except Exception as e:
        strEndpoints = ""
        print (f"An exception occurred: {e}")
    #print(len(strEndpoints))
    #print(len(strEPStatus))
    if len(strEndpoints) > 0:
        print("Adding Endpoints Table")
        db.insert_into_table_endpoints(strEndpoints,host,port,user,password,database)
        writeReport(dictState['reportAssets'],strEndpoints)
        print("Adding Endpoints Status Table")
        db.insert_into_table_endpointsStatus(strEPStatus,host,port,user,password,database)
        pbar.update(siz3)
        
        #time.sleep(0.25)

        fr0m += siz3

    if fr0m < count:
        dictState.update({'lastEndpoints': fr0m})
        state.setState(dictState)
        control_rate(20)
        getAllEndpoits(fr0m,siz3,count,pbar)
    else:
        pbar.update(siz3)
        time.sleep(0.25)
        
        dictState.update({'lastEndpoints': count})
        state.setState(dictState)     
        pbar.close()
        print("Done!")

def getAllEndpoits(fr0m,siz3,count,firstEID):
    queryCount = 0 
    all_assets = []
    all_assets_status = []
    lastEID = firstEID - 1
    #print(str(firstEID))
    #print(str(lastEID))

    while queryCount < count:
        control_rate(20)
        try:
            
            jsonEndpoints,jsonEPStatus = assets.getEndpoints(apikey,urldashboard,fr0m,siz3,lastEID)
            #print(len(jsonEndpoints))
            #print(jsonEndpoints)
            queryCount += len(jsonEndpoints)

            #all_assets.append(jsonEndpoints)
            #all_assets_status.extend(jsonEPStatus)
            #print("endpoints returned")
            print("Adding Endpoints Table")
            db.insert_into_table_endpoints(jsonEndpoints,host,port,user,password,database)
            #writeReport(dictState['reportAssets'],strEndpoints)
            print("Adding Endpoints Status Table")
            db.insert_into_table_endpointsStatus(jsonEPStatus,host,port,user,password,database)
            lastEID = db.load_endpoints_LEID(host,port,user,password,database)
            print(lastEID)
        except Exception as e:
            strEndpoints = ""
            print (f"An exception occurred: {e}")
        
        print(f"queryCount: {queryCount} < count: {count}")
    
def getAllEndpointsGroup(fr0m,siz3,count,groupName,groupId,assetgroupSRO):
    all_group_assets = []
    all_group_assets.extend(assetgroupSRO)
    while fr0m < count:
        control_rate (50)
        disCount, assets_batch = groups.getAssetsbyGroupID(apikey,urldashboard,groupName,groupId,fr0m,siz3)
        all_group_assets.extend(assets_batch)
        fr0m += siz3
        time.sleep(0.25)  # Optional extra rate-limiting
    return all_group_assets
 
def getAllGroupsSearchs(apikey, urldashboard, siz3, groupscount, initresponse): 
    fr0m = 500
    all_groups = []
    all_groups.extend(initresponse)

    while fr0m < groupscount:
        control_rate(50)
        disCount, groups_batch = groups.getEndpointGroupsID(apikey, urldashboard, fr0m, siz3)
        all_groups.extend(groups_batch)
        fr0m += siz3
        time.sleep(0.25)  # Optional extra rate-limiting
    #print("length of All Groups: " + str(len(all_groups)))
    return all_groups

def getAllEndpoitsExternalAttributes(fr0m,siz3,count,pbar):
    #if fr0m == 0:
        #head = "id,asset,attribute,value\n"
        #writeReport(dictState['reportAssetsAttrributes'],head)
    
    control_rate()
    strEndpointsAttributes,epAttributeOBJ = assets.getEndpoitsExternalAttributes(apikey,urldashboard,fr0m,siz3)
    #writeReport(dictState['reportAssetsAttrributes'],strEndpointsAttributes)
    db.insert_into_table_endpointsAttribute(epAttributeOBJ, host, port, user, password, database)
    pbar.update(siz3)
    #time.sleep(0.25)

    fr0m += siz3

    if fr0m < count:
        #dictState.update({'lastEndpoints': fr0m})
        #state.setState(dictState)
        control_rate()
        getAllEndpoitsExternalAttributes(fr0m,siz3,count,pbar)

    else:
        pbar.update(siz3)
        time.sleep(0.25)
        
        pbar.close()
        print("Done!")

def getAllEndpoitsExploitabilityRiskFactors(fr0m,siz3,count,pbar):
    #if fr0m == 0:
        #head = "id,asset,riskfactorterm,riskfactordescription\n"
        #writeReport(dictState['reportAssetsExploitabilityRiskFactors'],head)
    
    strEndpointsExploitabilityRiskFactors,objEndpointsExploitabilityRiskFactors = assets.getEndpointScoresExploitabilityRiskFactors(apikey,urldashboard,fr0m,siz3)
    #writeReport(dictState['reportAssetsExploitabilityRiskFactors'],strEndpointsAttributes)
    db.insert_into_table_endpointsExploitabilityRiskFactors(objEndpointsExploitabilityRiskFactors, host, port, user, password, database)
    pbar.update(siz3)
    time.sleep(0.25)

    fr0m += siz3

    if fr0m < count:
        getAllEndpoitsExploitabilityRiskFactors(fr0m,siz3,count,pbar)

    else:
        pbar.update(siz3)
        time.sleep(0.25)
        
        pbar.close()
        print("Done!")

def getAllEndpoitsScoresImpactRiskFactors(fr0m,siz3,count,pbar):
    #if fr0m == 0:
        #head = "id,asset,riskfactorterm,riskfactorscore\n"
       # writeReport(dictState['reportAssetsScoresImpactRiskFactors'],head)

    strEndpointScoresImpactRiskFactors,objEndpointScoresImpactRiskFactors = assets.getEndpointScoresImpactRiskFactors(apikey,urldashboard,fr0m,siz3)
    #writeReport(dictState['reportAssetsScoresImpactRiskFactors'],strEndpointsAttributes)
    db.insert_into_table_endpointsImpactFactors(objEndpointScoresImpactRiskFactors, host, port, user, password, database)
    pbar.update(siz3)
    time.sleep(0.25)

    fr0m += siz3

    if fr0m < count:
        getAllEndpoitsScoresImpactRiskFactors(fr0m,siz3,count,pbar)

    else:
        pbar.update(siz3)
        time.sleep(0.25)
        
        pbar.close()
        print("Done!")

def getAllIncidentEventVulnerabilities(fr0m,siz3,incidenttype,minDate,maxDate):
    gc.collect ()
    print(minDate)
    print(maxDate)
    hmindate = datetime.fromtimestamp(int(minDate) / 1000000000).isoformat()
    hmaxdate = datetime.fromtimestamp(int(maxDate) / 1000000000).isoformat()
    print("minDate->" + str(hmindate))
    print("maxDate->" + str(hmaxdate))

    time.sleep(3)

    jresponse = incidents.getIncidentEventsbyType(apikey,urldashboard,fr0m,siz3,incidenttype,minDate,maxDate) 
   
    print(len(jresponse))
    if jresponse is None:
        print("jresponse is none, trying again...")
        time.sleep(60)
        del jresponse
        getAllIncidentEventVulnerabilities(fr0m,siz3,incidenttype,minDate,maxDate)

    elif len(jresponse['serverResponseObject']) > 0:

        strEventsVuln,minDate = incidents.parseIncidentEventsbyType(jresponse)

        minDate = str(minDate)
        
        db.insert_into_table_incident(strEventsVuln, host, port, user, password, database)

        print("foi->" + str(len(jresponse['serverResponseObject'])))
        del strEventsVuln
        del jresponse
        getAllIncidentEventVulnerabilities(fr0m,siz3,incidenttype,minDate,maxDate)
        
    else:
        print("No event")
        del jresponse
    gc.collect()
    
def getAllxProtectEvents(fr0m,siz3,incidenttype,minDate,maxDate,table):
    print(minDate)
    print(maxDate)
    hmindate = datetime.fromtimestamp(int(minDate) / 1000000000).isoformat()
    hmaxdate = datetime.fromtimestamp(int(maxDate) / 1000000000).isoformat()
    print("minDate->" + str(hmindate))
    print("maxDate->" + str(hmaxdate))

    time.sleep(3)

    jresponse = incidents.getxProtectEventsbyType(apikey,urldashboard,fr0m,siz3,incidenttype,minDate,maxDate) 
   

    if jresponse is None:
        print("jresponse é None, tentando novamente em 10 segundos...")
        time.sleep(10)
        getAllxProtectEvents(fr0m,siz3,incidenttype,minDate,maxDate,table)
        
    elif len(jresponse['serverResponseObject']) > 0:

        strEventsVuln,maxDate = incidents.parsexProtectEventsbyType(jresponse)

        maxDate = str(maxDate)
        if table == "incident":
            db.insert_into_table_incident(strEventsVuln, host, port, user, password, database)
        elif table == "events":
            db.insert_into_table_events(strEventsVuln, host, port, user, password, database)
        elif table == "xProtectEvents":
            db.insert_into_table_xProtectEvents(strEventsVuln, host, port, user, password, database)
        else:
            print("Table not found: getAllxProtectEvents")

        print("foi->" + str(len(jresponse['serverResponseObject'])))

        getAllxProtectEvents(fr0m,siz3,incidenttype,minDate,maxDate,table)
        
    else:
        print("No event")
    
def getAllEndpointsProductsVersions(fr0m,siz3,count,pbar):
   # if fr0m == 0:
        #head = "asset,productName,productRawEntryName,productVersion,publisherName,operatingSystemFamilyName,endpointId,productId\n"
       # writeReport(dictState['reportNameProducts'],head)

    strProductsVersions = products.getEndpointPublisherProductVersions(apikey,urldashboard,fr0m,siz3)
    writeReport(dictState['reportNameProducts'],strProductsVersions)
    
    pbar.update(siz3)
    time.sleep(0.25)

    fr0m += siz3

    if fr0m < count:
        getAllEndpointsProductsVersions(fr0m,siz3,count,pbar)

    else:
        pbar.update(siz3)
        time.sleep(0.25)
 
        pbar.close()
        print("Done!")

def getAppsPerRisk(fr0m,siz3):
    db.check_create_table_apps(host, port, user, password, database)
    db.clean_table_apps(host, port, user, password, database)

    lowRiskAppsCount,mediumRiskAppsCount,highRiskAppsCount = apprisk.getallApp(apikey,urldashboard)
    lrac = lowRiskAppsCount
    mrac = mediumRiskAppsCount
    hrac = highRiskAppsCount
    print(lowRiskAppsCount,mediumRiskAppsCount,highRiskAppsCount)
    # Sort counts 
    while lowRiskAppsCount > 500:
        siz3 = 500
        lowriskApps  = apprisk.getAppswithRisk(apikey,urldashboard,"Low",fr0m,siz3)
        db.insert_into_table_apps(lowriskApps, host, port, user, password, database)
        print("500 Low Risk Apps Inserted")
        lowRiskAppsCount = lowRiskAppsCount - siz3
    siz3 = lowRiskAppsCount
    lowriskApps  = apprisk.getAppswithRisk(apikey,urldashboard,"Low",fr0m,siz3)
    db.insert_into_table_apps(lowriskApps, host, port, user, password, database)
    print(str(lowRiskAppsCount) + " Low Risk Apps Inserted")

    while mediumRiskAppsCount > 500:
        siz3 = 500
        medriskApps  = apprisk.getAppswithRisk(apikey,urldashboard,"Medium",fr0m,siz3)
        print("500 Medium Risk Apps Inserted")
        db.insert_into_table_apps(medriskApps, host, port, user, password, database)
        mediumRiskAppsCount = mediumRiskAppsCount - 500
    siz3 = mediumRiskAppsCount
    medriskApps  = apprisk.getAppswithRisk(apikey,urldashboard,"Medium",fr0m,siz3)
    db.insert_into_table_apps(medriskApps, host, port, user, password, database)
    print(str(mediumRiskAppsCount) + " Medium Risk Apps Inserted")

    while highRiskAppsCount > 500:
        siz3 = 500
        highriskApps  = apprisk.getAppswithRisk(apikey,urldashboard,"High",fr0m,siz3)
        db.insert_into_table_apps(highriskApps, host, port, user, password, database)
        print("500 High Risk Apps Inserted")
        highRiskAppsCount = highRiskAppsCount - 500
    siz3 = highRiskAppsCount
    highriskApps  = apprisk.getAppswithRisk(apikey,urldashboard,"High",fr0m,siz3)
    db.insert_into_table_apps(highriskApps, host, port, user, password, database)
    print(str(highRiskAppsCount) + " High Risk Apps Inserted")

    totalAC = lrac + mrac + hrac
    print (str(totalAC) + " Apps inserted")

    #db.insert_into_table_apps

def ReportHasPatchApps():
    getAppsPerRisk(0,10)

def writeReport(reportName,strText):
    try:
        with open(reportName, 'a', encoding='UTF8') as report:
            report.write(strText)
        report.close()
    except:
        print("Somthing wrong with file")

def ReportTaskEvents(start_date=None, end_date=None):
    """Fetches task events from the API and stores them in the database.
    Handles large date ranges by breaking them into manageable chunks.
    
    Args:
        start_date (str, optional): Start date in YYYY-MM-DD format. If not provided, uses the latest 
                                    date from the database or defaults to INITIAL_MIN_DATE.
        end_date (str, optional): End date in YYYY-MM-DD format. If not provided, uses current time.
    """
    # Validate global configuration
    if not all([host, port, user, password, database, apikey, urldashboard]):
        print("ERROR: Missing required configuration for database or API")
        return
        
    # Define constants
    INITIAL_MIN_DATE = int(datetime(2022, 1, 1).timestamp() * 1e9)  # January 1, 2022
    # Define a reasonable chunk size (3 days in nanoseconds by default)
    CHUNK_SIZE = int(timedelta(days=3).total_seconds() * 1e9)
    
    # Ensure the tasks table exists in the database
    db.check_create_table_tasks(host, port, user, password, database)
    
    # Determine end date
    if end_date:
        try:
            maxDate = int(datetime.strptime(end_date, "%Y-%m-%d").timestamp() * 1e9)
            print(f"Using provided end date: {datetime.fromtimestamp(maxDate/1e9).strftime('%Y-%m-%d')}")
        except ValueError as e:
            print(f"Invalid end date format. Please use YYYY-MM-DD. Error: {e}")
            return
    else:
        dateNow = datetime.now()
        maxDate = int(dateNow.timestamp() * 1e9)
        print(f"Using current time as end date: {dateNow.strftime('%Y-%m-%d')}")
    
    # Determine start date with database as source of truth
    if start_date:
        try:
            minDate = int(datetime.strptime(start_date, "%Y-%m-%d").timestamp() * 1e9)
            print(f"Using provided start date: {datetime.fromtimestamp(minDate/1e9).strftime('%Y-%m-%d')}")
        except ValueError as e:
            print(f"Invalid start date format. Please use YYYY-MM-DD. Error: {e}")
            return
    else:
        # Query the database for the most recent task date
        print("Querying database for most recent task date...")
        df = db.load_task_to_df(host, port, user, password, database, str(maxDate))
        
        if df is not None and not df.empty:
            # Database has records - use the latest timestamp as our starting point
            minDate = df['updateatnano'].max()
            
            # Validate that minDate is reasonable (not in the future, not too old)
            min_date_dt = datetime.fromtimestamp(minDate/1e9)
            now = datetime.now()
            
            if min_date_dt > now:
                print(f"WARNING: Database returned a future date: {min_date_dt.strftime('%Y-%m-%d')}")
                print(f"Falling back to initial default date")
                minDate = INITIAL_MIN_DATE
            elif (now - min_date_dt).days > 365:
                print(f"WARNING: Database returned a very old date: {min_date_dt.strftime('%Y-%m-%d')}")
                print(f"This is more than 1 year old, which may be incorrect.")
                # Provide opportunity to continue or use a more recent default
                minDate = int((now - timedelta(days=90)).timestamp() * 1e9)
                print(f"Using 90 days ago as start date instead: {datetime.fromtimestamp(minDate/1e9).strftime('%Y-%m-%d')}")
            else:
                print(f"Starting from latest database record: {min_date_dt.strftime('%Y-%m-%d')}")
        else:
            # No records in database - use the initial default date
            minDate = INITIAL_MIN_DATE
            print(f"No existing records found. Starting from initial date: {datetime.fromtimestamp(minDate/1e9).strftime('%Y-%m-%d')}")
    
    # Double-check that date range is valid
    min_date_dt = datetime.fromtimestamp(minDate/1e9)
    max_date_dt = datetime.fromtimestamp(maxDate/1e9)
    
    if min_date_dt >= max_date_dt:
        print(f"ERROR: Start date ({min_date_dt.strftime('%Y-%m-%d')}) is not before end date ({max_date_dt.strftime('%Y-%m-%d')})")
        print("Using default 30-day range instead")
        min_date_dt = max_date_dt - timedelta(days=30)
        minDate = int(min_date_dt.timestamp() * 1e9)
    
    print(f"Final date range: {min_date_dt.strftime('%Y-%m-%d')} to {max_date_dt.strftime('%Y-%m-%d')}")
    
    # Initialize variables for the main processing loop
    fr0m = 0
    siz3 = 500  # API page size
    
    print(f"Full date range: {datetime.fromtimestamp(minDate/1e9)} to {datetime.fromtimestamp(maxDate/1e9)}")
    
    # Process the date range in chunks - adaptive sizing strategy
    current_min = minDate
    empty_chunks_count = 0
    max_empty_chunks = 3  # After this many empty chunks, we'll increase chunk size
    
    while current_min < maxDate:
        # Calculate the end of the current chunk
        current_max = min(current_min + CHUNK_SIZE, maxDate)
        
        chunk_start = datetime.fromtimestamp(current_min/1e9)
        chunk_end = datetime.fromtimestamp(current_max/1e9)
        print(f"\nProcessing chunk: {chunk_start} to {chunk_end}")
        
        # Get tasks for this time chunk
        try:
            control_rate(50)
            tasks_count = processTaskChunk(fr0m, siz3, str(current_max), str(current_min))
            
            if tasks_count == 0:
                empty_chunks_count += 1
                print(f"No tasks in this time period. Empty chunks in a row: {empty_chunks_count}")
                
                # If multiple consecutive empty chunks, increase chunk size to speed up processing
                if empty_chunks_count >= max_empty_chunks:
                    CHUNK_SIZE = min(CHUNK_SIZE * 2, int(timedelta(days=30).total_seconds() * 1e9))
                    print(f"Increased chunk size to {timedelta(seconds=CHUNK_SIZE/1e9)} after multiple empty chunks")
                    empty_chunks_count = 0
            else:
                empty_chunks_count = 0  # Reset the counter when we find tasks
                print(f"Retrieved {tasks_count} tasks for this time period")
                
                # If we found a lot of tasks, decrease chunk size for more granularity
                if tasks_count > 1000:
                    new_chunk_size = max(CHUNK_SIZE // 2, int(timedelta(days=1).total_seconds() * 1e9))
                    if new_chunk_size != CHUNK_SIZE:
                        CHUNK_SIZE = new_chunk_size
                        print(f"Reduced chunk size to {timedelta(seconds=CHUNK_SIZE/1e9)} due to high task volume")
        
        except Exception as e:
            print(f"Error processing chunk {chunk_start} to {chunk_end}: {e}")
            # If we encounter API errors, reduce chunk size and retry this interval
            if CHUNK_SIZE > int(timedelta(days=1).total_seconds() * 1e9):
                CHUNK_SIZE = int(CHUNK_SIZE * 0.5)
                print(f"Reduced chunk size to {timedelta(seconds=CHUNK_SIZE/1e9)} after error")
                continue  # Retry with smaller chunk size without advancing current_min
            else:
                # If we're already at minimum chunk size, skip this problematic interval
                print(f"Already at minimum chunk size. Skipping problematic interval.")
        
        # Move to the next chunk
        current_min = current_max
    
    print("\nTask event processing complete")

def processTaskChunk(fr0m, siz3, maxDate, minDate):
    """Process a single time chunk for task events.
    Returns the number of tasks processed.
    """
    total_tasks = 0
    
    try:
        control_rate(50)
        tasks_list, lastdate = tasks.getTasksEndopintsEvents(apikey, urldashboard, fr0m, siz3, maxDate, minDate)
        
        if tasks_list == 0 or not tasks_list:
            return 0
        
        total_tasks = len(tasks_list)
        if total_tasks > 0:
            print(f"Inserting {total_tasks} tasks into the DB")
            db.insert_into_table_tasks(tasks_list, host, port, user, password, database)
            del tasks_list
            
            # Process additional pages if necessary
            if total_tasks == siz3:  # If we hit the page size limit, there might be more
                new_fr0m = fr0m + siz3
                total_tasks += processTaskPagination(new_fr0m, siz3, maxDate, minDate)
    except Exception as e:
        print(f"Error in processTaskChunk: {e}")
    
    return total_tasks

def processTaskPagination(fr0m, siz3, maxDate, minDate):
    """Process additional pages of results within the same time chunk.
    Returns the number of additional tasks processed.
    """
    additional_tasks = 0
    
    try:
        control_rate(50)
        tasks_list, lastdate = tasks.getTasksEndopintsEvents(apikey, urldashboard, fr0m, siz3, maxDate, minDate)
        
        if tasks_list == 0 or not tasks_list:
            return 0
            
        page_tasks = len(tasks_list)
        additional_tasks += page_tasks
        
        print(f"Inserting additional {page_tasks} tasks into the DB")
        db.insert_into_table_tasks(tasks_list, host, port, user, password, database)
        del tasks_list
        
        # Recursively process next page if we hit the page size limit
        if page_tasks == siz3:
            new_fr0m = fr0m + siz3
            additional_tasks += processTaskPagination(new_fr0m, siz3, maxDate, minDate)
    except Exception as e:
        print(f"Error in processTaskPagination: {e}")
    
    return additional_tasks

def ReportProdctsVersions():
    productscount = products.getCountEndpointPublisherProductVersions(apikey,urldashboard)
    print("Products -> " + str(productscount))
    fr0m = 0       
    
    if fr0m < productscount:
        deltacount = productscount - fr0m
        with tqdm(total=deltacount,desc="ProductsVersions") as pbar:
            
            getAllEndpointsProductsVersions(fr0m,500,productscount,pbar)
    else:
        print("Done!")

def ReportEndpointsold():
    db.check_create_table_endpoints(host, port, user, password, database)
    db.clean_table_endpoints(host, port, user, password, database)
    
    head = "id,hostname,hash,alive,so,version,substatus,connectedbyproxy,tokengentime,deployed,last_connected,deploymentdate,lastcontactdate\n"
    writeReport(dictState['reportAssets'],head)
    
    control_rate(20)
    endpointcount = assets.getCountEndpoints(apikey,urldashboard)
    print("Endpoints -> " + str(endpointcount))
   
    fr0m = 0
    
    if fr0m < endpointcount:
        deltacount = endpointcount - fr0m
        with tqdm(total=deltacount,desc="Endpoints") as pbar:
            control_rate(20)
            print("ReportEP -> getallEnpoints")
            getAllEndpoits(fr0m,500,endpointcount,pbar)
            print("ReportEP -> getallEnpoints -> Finished")
    else:
        print("Done!")

def ReportEndpoints():
    try:
        # Create table if not exists
        db.check_create_table_endpoints(host, port, user, password, database)
        
        # Get endpoint count first to check if we have data
        control_rate(20)
        endpointcount, firstEID = assets.getCountEndpoints(apikey, urldashboard)
        print("Endpoints -> " + str(endpointcount))
        
        if endpointcount > 0:
            # Only clean the table if we have data to insert
            # This prevents data loss if the API call fails
            db.clean_table_endpoints(host, port, user, password, database)
            
            # Set up parameters
            fr0m = 0 
            size = 500
            
            try:
                # Get all endpoints
                print("Fetching endpoints...")
                getAllEndpoits(fr0m, size, endpointcount, firstEID)
                print("ReportEndpoints -> Completed successfully")
            except Exception as e:
                print(f"Error while getting endpoints: {e}")
                # Don't raise here to avoid incomplete data state
                print("WARNING: Endpoint data may be incomplete due to errors")
        else:
            print("No endpoints found to report")
            
    except Exception as e:
        print(f"Exception occurred in ReportEndpoints: {e}")
        raise

def ReportEndpointsAttributes():
    db.check_create_table_endpointsAttribute(host, port, user, password, database)
    db.clean_table_endpointsAttribute(host, port, user, password, database)
    endpointattribcount = assets.getEndpoitsExternalAttributesCount(apikey,urldashboard)
    #print("EndpointsAttribs -> " + str(endpointattribcount))
    fr0m = 0       
    
    if fr0m < endpointattribcount:
        deltacount = endpointattribcount - fr0m
        with tqdm(total=deltacount,desc="Endpoints") as pbar:
            try:
                control_rate(20) 
                getAllEndpoitsExternalAttributes(fr0m,500,endpointattribcount,pbar)
            except Exception as e:
                print (f"Exception occurred at getAllEndpoitsExternalAttributes: {e}")
    else:
        print("Done!")

def ReportEndpointScores():
    db.check_create_table_endpointsExploitabilityRiskFactors(host, port, user, password, database)
    db.check_create_table_endpointsImpactFactors(host, port, user, password, database)
    db.clean_table_endpointsExploitabilityRiskFactors(host, port, user, password, database)
    db.clean_table_endpointsImpactFactors(host, port, user, password, database)
    
    endpointcount = assets.getCountEndpoints(apikey,urldashboard)
    print("Endpoints -> " + str(endpointcount))
    fr0m = 0       
    
    if fr0m < endpointcount:
        deltacount = endpointcount - fr0m
        with tqdm(total=deltacount,desc="Endpoints") as pbar:            
            getAllEndpoitsScoresImpactRiskFactors(fr0m,500,endpointcount,pbar)
    else:
        print("Done!")

    if fr0m < endpointcount:
        deltacount = endpointcount - fr0m
        with tqdm(total=deltacount,desc="Endpoints") as pbar:            
            getAllEndpoitsExploitabilityRiskFactors(fr0m,500,endpointcount,pbar)
    else:
        print("Done!")    

def ReportIncident(start_date=None, end_date=None):

    # Constants
    INITIAL_MIN_DATE = int(datetime(2022, 1, 1).timestamp() * 1e9)  # Set the initial min date to January 1, 2022
    ONE_MONTH_NANOSECONDS = int(timedelta(days=30).total_seconds() * 1e9)  # Define the duration of one month in nanoseconds
    incident_type="MitigatedVulnerability,DetectedVulnerability"

    def process_in_chunks(minDate, maxDate, db, incident_type):
        current_min_date = minDate
        while current_min_date < maxDate:
            current_max_date = min(current_min_date + ONE_MONTH_NANOSECONDS, maxDate)
            try:
                control_rate(20)
                getAllIncidentEventVulnerabilities(0, 500, incident_type, str(current_min_date), str(current_max_date))
            except Exception as e:
                print("Incident Error 1")
                print(f"Error processing incidents: {e}")
                print
            current_min_date = current_max_date

    def process_all_at_once(minDate, maxDate, db, incident_type):
        try:
            control_rate(20)
            getAllIncidentEventVulnerabilities(0, 500, incident_type, str(minDate), str(maxDate))
        except Exception as e:
            print("Incident Error 2")
            print(f"Error processing incidents: {e}")

    # Ensure the incident table exists in the database
    db.check_create_table_incident(host, port, user, password, database)
    
    if end_date:
        # Get the end date from the arguments
        try:
            maxDate = int(datetime.strptime(end_date, "%Y-%m-%d").timestamp() * 1e9)
        except Exception as e:
            print(f"Invalid end date format. Please use the format YYYY-MM-DD. Error: {e} ")
            print (end_date)
            return
    else:
        # Get the current time in nanoseconds
        currentDate = datetime.now()
        maxDate = int(currentDate.timestamp() * 1e9)

    if start_date:
        # Get the start date from the arguments
        try:
            minDate = int(datetime.strptime(start_date, "%Y-%m-%d").timestamp() * 1e9)
            print ("minDate set from args")
        except ValueError:
            print("Invalid start date format. Please use the format YYYY-MM-DD.")
            return
    else:
        # Load the most recent incident date from the database or use the initial date
        df = db.load_incident_to_df(host, port, user, password, database, maxDate)
        minDate = df['create_at_nano'].max() if df is not None and not df.empty else INITIAL_MIN_DATE
        print("minDate set from DB" if df is not df.empty else "minDate set from INITIAL_MIN_DATE")

    # Process incidents in monthly chunks if the interval is too large
    if (maxDate - minDate) > ONE_MONTH_NANOSECONDS:
        process_in_chunks(minDate, maxDate, db, incident_type)
    else:
        process_all_at_once(minDate, maxDate, db, incident_type)

def ReportIncidientImpersontation():
    db.check_create_table_xProtectEvents(host, port, user, password, database)
    dateNow = datetime.now()
    maxDate = str(int(float(dateNow.timestamp())*1000000000))
    minDate = str(dictState['minDatexProtectLog'])
    incidenttype = "ImpersonationAttempt" #Asset Events, App Events, User Events and System Events

    df = db.load_xProtectEvents_to_df(host, port, user, password, database, minDate)
    if df is not None:
        if df.empty:
            print("minDate Set from state.json")
        else:
            for ind in df.index:
                dbMinDate = df['create_at_nano'][ind]
            if dbMinDate > np.int64(minDate):
                minDate = str(dbMinDate)
                print("minDate Set from DB")
            else:
                print("minDate set from state.json")
    #print(maxDate)
    #print(type(maxDate))
    dictState.update({'minDatexProtectLog': int(maxDate)})
    state.setState(dictState)
    #print("Set max date")
    fr0m = 0
    siz3 = 500

    #set these variables for specific event time interval

    #maxDate = str(1697227198691126350)
    #minDate = str(1698796800000000000)

    getAllxProtectEvents(fr0m,siz3,incidenttype,minDate,maxDate,"xProtectEvents")

def ReportEventLog():
    db.check_create_table_Events(host, port, user, password, database)
    dateNow = datetime.now()
    maxDate = str(int(float(dateNow.timestamp())*1000000000))
    minDate = str(dictState['minDateEventLog'])
    incidenttype = "NewEndpoint,NewPublisherProduct,NewPublisherOperatingSystem,EndpointRemoved" #Asset Events, App Events, User Events and System Events

    df = db.load_Event_to_df(host, port, user, password, database, minDate)
    if df is not None:
        if df.empty:
            print("minDate Set from state.json")
        else:
            for ind in df.index:
                dbMinDate = df['create_at_nano'][ind]
            if dbMinDate > np.int64(minDate):
                minDate = str(dbMinDate)
                print("minDate Set from DB")
            else:
                print("minDate set from state.json")
    #print(maxDate)
    #print(type(maxDate))
    dictState.update({'minDateEventLog': int(maxDate)})
    state.setState(dictState)
    #print("Set max date")
    fr0m = 0
    siz3 = 500

    #set these variables for specific event time interval

    #maxDate = str(1697227198691126350)
    #minDate = str(1698796800000000000)

    getAllIncidentEvents(fr0m,siz3,incidenttype,minDate,maxDate,"events")

def SearchGroupsbyEndpoint(endpoint,dfg):
    # filter the dataframe to only include rows where the "assetname" column contains a certain string
    assetname_filter = dfg['assets'].str.contains(endpoint+'|',regex=False)
    df_filtered = dfg[assetname_filter]

    # extract the "groupname" column from the filtered dataframe
    groupname_series = df_filtered['groupname']

    # convert the groupname series to a list
    groupname_list = groupname_series.tolist()

    # create a string with groups
    my_string = "AllAssets|" + '|'.join(groupname_list)
    
    return my_string

def get_all_endpoints_vulnerabilities(offset, limit, min_date, max_date, endpoint_name, endpoint_hash, jsonresponse, apiCount):
    #print(f"Date Range: {min_date} - {max_date}")
    control_rate(50)
    jresponse = jsonresponse
    try:
        vulnerabilities = vuln.parseEndpointVulnerabilities(apikey, urldashboard, jresponse)
    except Exception as e:
        error_msg = f"Exception occurred while parsing vulnerabilities for {endpoint_name}: {e}"
        print(error_msg)
        errorList.append(error_msg)
        

    print(f"Asset Name: {endpoint_name}. Server Response Count: {apiCount}")
    
    db.insert_into_table_activevulnerabilities(vulnerabilities, host, port, user, password, database)
    del jresponse
    del vulnerabilities
    print(f"Pagination Offset: {offset}")
    if offset >= apiCount:
        print("Pull Complete")
    else:
        while True:
            try:
                control_rate(50)
                jresponse = vuln.getEndpointVulnerabilities(apikey, urldashboard, offset, limit, min_date, max_date, endpoint_name, endpoint_hash)

                server_response_count = jresponse.get('serverResponseCount', 0)
                if server_response_count == 0:
                    print(f"No vulnerabilities found for {endpoint_name} within the specified range.")
                    break

                try:
                    vulnerabilities = vuln.parseEndpointVulnerabilities(apikey, urldashboard, jresponse)
                except Exception as e:
                    error_msg = f"Exception occurred while parsing vulnerabilities for {endpoint_name}: {e}"
                    print(error_msg)
                    errorList.append(error_msg)
                    break

                print(f"Asset Name: {endpoint_name}. Server Response Count: {server_response_count}")
                
                db.insert_into_table_activevulnerabilities(vulnerabilities, host, port, user, password, database)
                del jresponse
                del vulnerabilities

                offset += limit
                if offset >= server_response_count:
                    break

                print(f"Pagination Offset: {offset}")

            except Exception as e:
                error_msg = f"Exception occurred while fetching vulnerabilities for {endpoint_name}: {e}"
                print(error_msg)
                errorList.append(error_msg)
                break

            # Rate control between pagination requests
            control_rate(30)

def ReportVunerabilities():
    """
    Differential vulnerability sync implementation.
    Compares API state vs DB state and only updates what changed.
    """
    df = db.load_endpoints_to_df(host, port, user, password, database)
    print(f"Checking Vulns on Assets: {len(df.index)}")

    # Ensure table exists
    db.check_create_table_activevulnerabilities(host, port, user, password, database)

    for ind in df.index:
        endpointName = df['endpoint_name'][ind]
        endpointHash = df['endpoint_hash'][ind]

        print(f'\n=== Asset {ind + 1}/{len(df.index)} - {endpointName} ===')

        # Phase 1: Get vulnerability IDs from API (lightweight query)
        print(f'[PHASE 1] Fetching vulnerability IDs from API...')
        api_vuln_ids = set()
        from_offset = 0
        page_size = 100

        while True:
            try:
                control_rate(55)
                response = vuln.get_vulnerability_ids_by_endpoint(
                    apikey, urldashboard, endpointHash, from_offset, page_size
                )

                if not response or 'serverResponseObject' not in response:
                    print(f'[ERROR] Failed to fetch vulnerability IDs from API')
                    break

                # Extract IDs from response (keep as integers to match DB schema)
                batch_ids = [int(item.get('aggregationId')) for item in response['serverResponseObject'] if item.get('aggregationId')]
                api_vuln_ids.update(batch_ids)

                # Check if we've fetched all IDs
                total_count = response.get('serverResponseCount', 0)
                if from_offset + page_size >= total_count:
                    break

                from_offset += page_size
                time.sleep(0.5)  # Brief pause between pagination

            except Exception as e:
                error_msg = f"Exception fetching vulnerability IDs for {endpointName}: {e}"
                print(error_msg)
                errorList.append(error_msg)
                break

        print(f'[API] Found {len(api_vuln_ids)} vulnerabilities')

        # Phase 2: Get vulnerability IDs from database
        print(f'[PHASE 2] Fetching vulnerability IDs from database...')
        db_vuln_ids = db.get_vulnerability_ids_by_endpoint_hash(
            host, port, user, password, database, endpointHash
        )
        print(f'[DB] Found {len(db_vuln_ids)} vulnerabilities')

        # Phase 3: Calculate differences (3-way split)
        print(f'[PHASE 3] Calculating differences...')
        ids_to_delete = db_vuln_ids - api_vuln_ids  # In DB but not in API (REMOVED)
        ids_to_insert = api_vuln_ids - db_vuln_ids  # In API but not in DB (NEW)
        ids_to_update = api_vuln_ids & db_vuln_ids  # In both API and DB (EXISTING)

        print(f'[DIFF] Delete: {len(ids_to_delete)} | Insert: {len(ids_to_insert)} | Update: {len(ids_to_update)}')

        # Phase 4: Delete removed vulnerabilities
        if ids_to_delete:
            print(f'[PHASE 4] Deleting {len(ids_to_delete)} removed vulnerabilities...')
            try:
                deleted_count = db.delete_vulnerabilities_by_ids(
                    host, port, user, password, database, endpointHash, ids_to_delete
                )
                print(f'[DELETE] Successfully deleted {deleted_count} vulnerabilities')
            except Exception as e:
                error_msg = f"Exception deleting vulnerabilities for {endpointName}: {e}"
                print(error_msg)
                errorList.append(error_msg)
        else:
            print(f'[PHASE 4] No vulnerabilities to delete')

        # Phase 5: Insert NEW vulnerabilities (no delete needed)
        if ids_to_insert:
            print(f'[PHASE 5] Inserting {len(ids_to_insert)} NEW vulnerabilities...')

            batch_size = 100
            ids_list = list(ids_to_insert)

            for i in range(0, len(ids_list), batch_size):
                batch_ids = ids_list[i:i+batch_size]
                batch_num = (i // batch_size) + 1
                total_batches = (len(ids_list) + batch_size - 1) // batch_size

                print(f'[BATCH {batch_num}/{total_batches}] Fetching NEW vulnerability details...')

                try:
                    control_rate(50)
                    details_response = vuln.get_vulnerability_details_by_ids(
                        apikey, urldashboard, batch_ids, endpointHash
                    )

                    if not details_response or 'serverResponseObject' not in details_response:
                        print(f'[ERROR] Failed to fetch details for batch {batch_num}')
                        continue

                    vulnerabilities = vuln.parse_vulnerability_details(details_response)
                    print(f'[PARSE] Parsed {len(vulnerabilities)} NEW vulnerabilities')

                    # Direct insert (no delete needed - they're new!)
                    if vulnerabilities:
                        db.insert_into_table_activevulnerabilities(
                            vulnerabilities, host, port, user, password, database
                        )
                        print(f'[INSERT] Inserted {len(vulnerabilities)} NEW vulnerabilities')

                    del details_response
                    del vulnerabilities
                    time.sleep(1)

                except Exception as e:
                    error_msg = f"Exception inserting NEW vulnerabilities batch {batch_num} for {endpointName}: {e}"
                    print(error_msg)
                    errorList.append(error_msg)
                    continue
        else:
            print(f'[PHASE 5] No NEW vulnerabilities to insert')

        # Phase 6: Update EXISTING vulnerabilities (transaction-based delete + insert)
        if ids_to_update:
            print(f'[PHASE 6] Updating {len(ids_to_update)} EXISTING vulnerabilities...')

            batch_size = 100
            ids_list = list(ids_to_update)

            for i in range(0, len(ids_list), batch_size):
                batch_ids = ids_list[i:i+batch_size]
                batch_num = (i // batch_size) + 1
                total_batches = (len(ids_list) + batch_size - 1) // batch_size

                print(f'[BATCH {batch_num}/{total_batches}] Updating EXISTING vulnerability details...')

                try:
                    control_rate(50)
                    details_response = vuln.get_vulnerability_details_by_ids(
                        apikey, urldashboard, batch_ids, endpointHash
                    )

                    if not details_response or 'serverResponseObject' not in details_response:
                        print(f'[ERROR] Failed to fetch details for batch {batch_num}')
                        continue

                    vulnerabilities = vuln.parse_vulnerability_details(details_response)
                    print(f'[PARSE] Parsed {len(vulnerabilities)} EXISTING vulnerabilities')

                    # Transaction-based update (atomic delete + insert)
                    if vulnerabilities:
                        success = db.update_vulnerabilities_batch(
                            vulnerabilities, endpointHash, host, port, user, password, database
                        )
                        if success:
                            print(f'[UPDATE] Successfully updated {len(vulnerabilities)} vulnerabilities')
                        else:
                            error_msg = f"Failed to update batch {batch_num} for {endpointName}"
                            print(f'[ERROR] {error_msg}')
                            errorList.append(error_msg)

                    del details_response
                    del vulnerabilities
                    time.sleep(1)

                except Exception as e:
                    error_msg = f"Exception updating EXISTING vulnerabilities batch {batch_num} for {endpointName}: {e}"
                    print(error_msg)
                    errorList.append(error_msg)
                    continue
        else:
            print(f'[PHASE 6] No EXISTING vulnerabilities to update')

        # Phase 7: Verify sync completed successfully
        print(f'[PHASE 7] Verifying sync...')
        try:
            final_db_count = db.get_cve_count_by_endpoint_hash(
                host, port, user, password, database, endpointHash
            )
            expected_count = len(api_vuln_ids)

            if final_db_count != expected_count:
                error_msg = f'Sync verification failed for {endpointName}! Expected={expected_count} Actual={final_db_count}'
                print(f'[WARNING] {error_msg}')
                errorList.append(error_msg)
            else:
                print(f'[VERIFY] ✓ Sync successful! {final_db_count} vulnerabilities in sync')
        except Exception as e:
            error_msg = f"Exception during verification for {endpointName}: {e}"
            print(error_msg)
            errorList.append(error_msg)

        print(f'[COMPLETE] Finished processing {endpointName}')

def getAllPatchsEndpoint(fr0m,siz3,endpointName,endpointSO,endpointHash):

    #Get the string of patchs by Patch and Write in Report
    control_rate (50)
    strEndpointPatchs,tmpPatchs = patchs.getEndpointsPatchs(apikey,urldashboard,fr0m,siz3,endpointName,endpointSO,endpointHash)
    print("patchsString->" + str(tmpPatchs))
    if len(strEndpointPatchs) > 0:
        db.insert_into_table_assetspatchs(strEndpointPatchs, host, port, user, password, database)

   
    if tmpPatchs >= siz3:
        fr0m += siz3
        getAllPatchsEndpoint(fr0m,siz3,endpointName,endpointSO,endpointHash)

def get_all_endpoints_patches(offset, limit, min_date, max_date, endpoint_name, endpoint_hash, jsonresponse, apiCount):
    #(fr0m,siz3,minDate,maxDate,endpointName,endpointHash)
    #print(f"Date Range: {min_date} - {max_date}")
    control_rate(50)
    jresponse = jsonresponse
    try:
        assetPatches = patchs.parseEndpointpatches(jresponse,endpoint_name,endpoint_hash)
    except Exception as e:
        error_msg = f"Exception occurred while parsing vulnerabilities for {endpoint_name}: {e}"
        print(error_msg)
        errorList.append(error_msg)
        

    print(f"Asset Name: {endpoint_name}. Server Response Count: {apiCount}")
    
    db.insert_into_table_assetspatchs(assetPatches, host, port, user, password, database)
    del jresponse
    del assetPatches
    print(f"Pagination Offset: {offset}")
    if offset >= apiCount:
        print("Pull Complete")
    else:
        while True:
            try:
                control_rate(50)
                jresponse = patchs.getEndpointsPatchs(apikey, urldashboard, offset, limit, min_date, max_date, endpoint_name, endpoint_hash)
                server_response_count = jresponse.get('serverResponseCount', 0)
                if server_response_count == 0:
                    print(f"No patchs found for {endpoint_name} within the specified range.")
                    break

                try:
                    assetPatches = patchs.parseEndpointpatches(jresponse,endpoint_name,endpoint_hash)
                except Exception as e:
                    error_msg = f"Exception occurred while parsing patchs for {endpoint_name}: {e}"
                    print(error_msg)
                    errorList.append(error_msg)
                    break

                print(f"Asset Name: {endpoint_name}. Server Response Count: {server_response_count}")
                
                db.insert_into_table_assetspatchs(assetPatches, host, port, user, password, database)

                del jresponse
                del assetPatches

                offset += limit
                if offset >= server_response_count:
                    break

                print(f"Pagination Offset: {offset}")

            except Exception as e:
                error_msg = f"Exception occurred while fetching patches for {endpoint_name}: {e}"
                print(error_msg)
                errorList.append(error_msg)
                break

            # Rate control between pagination requests
            control_rate(30)

def ReportEndpointPatchs_old():
    df = db.load_endpoints_to_df(host, port, user, password, database)
    print("Checking Vulns on Assets: " + str(len(df.index)))
    fr0m = 0
    siz3 = 500

    db.check_create_table_assetspatchs(host, port, user, password, database)
    #db.clean_table_assetspatchs(host, port, user, password, database)
    dateNow = datetime.now()
    minDate = 0000000000000
    maxDate = str(int(float(dateNow.timestamp())*1000))
            
    for ind in df.index:        
        
        endpointName = df['endpoint_name'][ind]
        endpointSO = df['operating_system_name'][ind]
        endpointHash = df['endpoint_hash'][ind]
        #endpointGroups = SearchGroupsbyEndpoint(endpointName,dfg)
        control_rate(55)
        current_patch_count_api,jsonresponse,errors = patchs.getCountEndpointsPatchs(apikey, urldashboard,endpointHash) #vuln.getCountEventsPerAsset(apikey, urldashboard,endpointHash)
        current_patch_count_db = db.get_patch_count_by_endpoint_hash(host, port, user, password, database, endpointHash)#db.get_cve_count_by_endpoint_hash(host, port, user, password, database,endpointHash)
        if errors:
            print(f'Errors: {errors}')
            for error in errors:
                errorList.append(error)
                print("Appending errors to the errorList")
            if "API Rate Limit" or "Return Exception" in errors:
                print("API Rate limit exceeded. Perhaps another api query is running")

        print(f'Asset {ind + 1}/{len(df)} - {endpointName} - Current patch Count - API: {current_patch_count_api} DB: {current_patch_count_db}')
        if (current_patch_count_db != current_patch_count_api):
            print (f'Updating Patches')
            if (current_patch_count_db > 0):
                db.delete_assetpatchs_by_endpoint_hash(host, port, user, password, database,endpointHash)
            #get_all_endpoints_vulnerabilities(fr0m,siz3,minDate,maxDate,endpointName,endpointHash)
            if (current_patch_count_api > 0):
                fr0m = 500
                get_all_endpoints_patches(fr0m,siz3,minDate,maxDate,endpointName,endpointHash,jsonresponse,current_patch_count_api)
            else: 
                print(f'API Patch count is 0, No patches to add')


def ReportEndpointPatchs():
    """Chama PostgreSQL com configurações do CLI"""
    try:
        # Extrair apenas o nome do dashboard do urldashboard
        dashboard = organization_domain
        print(f"\n=== INICIANDO COLETA DE PATCHES ===")
        print(f"Dashboard: {dashboard}")
        print(f"API Key: ********{apikey[-4:] if apikey else 'None'}")
        
        # Configuração do banco de dados
        db_config = {
            'host': host,
            'port': port,
            'user': user,
            'password': password,
            'database': database
        }
        print(f"Database: {host}:{port}/{database}")
        
        # Importar e chamar a função do PostgreSQL
        try:
            from getOSpatchsPostgres import execute_complete_patches_collection
        except ImportError as ie:
            error_msg = f"Erro ao importar getOspatchsPostgres: {str(ie)}"
            print(f"\n{error_msg}")
            errorList.append(error_msg)
            return {'success': False, 'error': error_msg}
        
        print("\nChamando coleta completa de patches...")
        result = execute_complete_patches_collection(
            apikey, 
            dashboard,
            db_config
        )
        
        if result.get('success'):
            print(f"\nColeta concluida com sucesso!")
            print(f"Tempo de execucao: {result.get('execution_time', 0):.2f}s")
            print(f"Requisicoes API: {result.get('api_requests', 0)}")
            if 'stats' in result:
                stats = result['stats']
                print(f"Registros inseridos:")
                print(f"  - Sistemas Operacionais: {stats.get('operating_system', 0)}")
                print(f"  - Patches: {stats.get('patches', 0)}")
                print(f"  - Assets: {stats.get('assets', 0)}")
                print(f"  - Vulnerabilidades: {stats.get('vulnerabilities', 0)}")
        else:
            error_msg = f"Erro na coleta de patches: {result.get('error', 'Erro desconhecido')}"
            print(f"\n{error_msg}")
            errorList.append(error_msg)
            
        return result
        
    except Exception as e:
        error_msg = f"Erro critico em ReportEndpointPatchs: {str(e)}"
        print(f"\n{error_msg}")
        import traceback
        traceback.print_exc()
        errorList.append(error_msg)
        return {
            'success': False,
            'error': error_msg
        }
    #add a try except block to execute reportendpointpatchs_old if any error occurs
    
    try:
        ReportEndpointPatchs_old()
    except Exception as e:
        error_msg = f"Erro critico em ReportEndpointPatchs_old: {str(e)}"
        print(f"\n{error_msg}")
        import traceback
        traceback.print_exc()
        errorList.append(error_msg)



def processGroups(allgroups):
    groupJsonObj = []
    groupAssetsOject = []
    groupcountSum = 0
    for group in allgroups:
        groupName = group['groupName']
        groupId = group['groupID']
        #searchQuery = group['searchQuery']
        groupTeam = group['groupTeam']
        groupTeamId = group['groupTeamId']

        # Get the count of assets for each group
        groupscount,assetgroupSRO= groups.getAssetsbyGroupID(apikey, urldashboard, groupName, groupId, 0, 500)
        print(f"Group: {groupName}, Assets: {groupscount}")
        groupcountSum += groupscount
        GroupAssetCount = groupscount
        groupJson = {
            'groupId': groupId,
            'groupName': groupName,
            'groupTeamName': groupTeam,
            'groupTeamId': groupTeamId,
            'groupAssetCount': GroupAssetCount
        }
        #print(groupJson)
        groupJsonObj.append(groupJson)
        
        if groupscount > 0:
            control_rate(50)
            all_group_assets = getAllEndpointsGroup(500, 500, groupscount, groupName, groupId, assetgroupSRO)
            groupAssetsOject.extend(all_group_assets)
            #print(all_group_assets)
        else:
            print(f"No assets found for group {groupName}")
    #print(groupJsonObj)
    #print(json.dumps(groupJsonObj))
    #print(groupAssetsOject)
    print("groups count sum: " + str(groupcountSum))
    db.insert_into_table_groups(groupJsonObj,host,port,user,password,database)
    db.insert_into_table_endpointgroups(groupAssetsOject,host,port,user,password,database)
    del groupJson
    del groupAssetsOject
    gc.collect()

def ReportGroupsSearchs():
    control_rate(20)
    db.check_create_table_groups(host,port,user,password,database)
    db.check_create_table_endpointgroups(host, port, user, password, database)

    db.clean_table_groups(host, port, user, password, database)
    db.clean_table_endpointgroups(host, port, user, password, database)
    fr0m = 0 
    siz3 = 500
    groupscount,initresponse = groups.getEndpointGroupsID(apikey, urldashboard, fr0m, siz3)
    print(f"Total Endpoint Groups: {groupscount}")

    if groupscount > 0:
        all_groups = getAllGroupsSearchs(apikey, urldashboard, 500, groupscount, initresponse)
        processGroups(all_groups)
    else:
        print("No groups found.")

def resetState():
    """
    dictState.update({'lastEndpointVulnerabilities': 0})
    dictState.update({'lastEndpoints':0})
    dictState.update({'lastEndpointsEventTask':0})
    dictState.update({'lastProductVersions':0})
    dictState.update({'lastPatchsEndpoint':0})
    dictState.update({'minDateIncidentEventVulnerabilities':0}) #minDateIncidentEventVulnerabilities
    dictState.update({'lastIncidentEventVulnerabilities':0})
    dictState.update({'minDateEventLog':0})
    dictState.update({'minDatexProtectLog':0})   
    state.setState(dictState)
    print("Done!")
    """
    try:
        os.remove("/usr/src/app/reports/state.json")
        os.remove("/usr/src/app/reports/Endpoints.csv")
        os.remove("/usr/src/app/reports/EndpointsGroup.csv")
        os.remove("/usr/src/app/logs/crontab.log.old")
        os.rename("/usr/src/app/logs/crontab.log", "/usr/src/app/logs/crontab.log.old")
    except:
        print("unable to remove a file")

def updateState():
    lastEndpointsEventTask = cd.getLastEndpointsEventTask ()
    minDateIncidentEventVulnerabilities = cd.getLastIncidentEventVulnerabilities ()
    dictState.update({'lastEndpointVulnerabilities': 0})
    dictState.update({'lastEndpoints':0})
    dictState.update({'lastEndpointsEventTask': lastEndpointsEventTask})
    dictState.update({'lastProductVersions':0})
    dictState.update({'lastPatchsEndpoint':0})
    dictState.update({'minDateIncidentEventVulnerabilities': minDateIncidentEventVulnerabilities}) #minDateIncidentEventVulnerabilities
    dictState.update({'lastIncidentEventVulnerabilities':0})    
    state.setState(dictState)
    print("Done!")

def logscriptActivity(startTime,endTime,errorList,reports):
    db.check_create_table_scriptActivity(host, port, user, password, database)

    if len(errorList) > 0:
        for row in errorList:
            #startTime = startTime.isoformat()
            #endTime = endTime.isoformat()
            recordjson = {
                "starttime": startTime,
                "endtime": endTime,
                "errors": str(row),
                "reports": reports
            }

            db.insert_into_table_scriptActivity(recordjson,host,port,user,password,database)
    else:
        startTime = startTime.isoformat()
        endTime = endTime.isoformat()
        recordjson = {
            "starttime": startTime,
            "endtime": endTime,
            "errors": "No Errors",
            "reports": reports
        }
        db.insert_into_table_scriptActivity(recordjson,host,port,user,password,database) 

def checkMetabaseExists(host, port, user, password):
    """Check if metabase database exists in PostgreSQL"""
    try:
        import psycopg2
        db_params = {
            'host': host,
            'port': port,
            'user': user,
            'password': password,
            'database': 'postgres'
        }
        conn = psycopg2.connect(**db_params)
        conn.autocommit = True
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM pg_database WHERE datname='metabase'")
        exists = cur.fetchone()
        cur.close()
        conn.close()
        return exists is not None
    except Exception as e:
        print(f"Error checking metabase database existence: {e}")
        return False

def configoptionalTools(host,port,user,password,tools):
    import optionalDBConnectors as optionalDB
    if "metabase" in tools:
        print("Using Tool: Metabase")
        dbexisted = optionalDB.create_db_metabase(host, port, user, password)
        if dbexisted == False:
            print("Metabase Database required")
            optionalDB.create_user_metabase(host, port, user, password)
            optionalDB.restore_database(host,port)
        else:
            print("Metabase Database already exists")
    
    if "n8n" in tools:
        dbexisted = optionalDB.create_db_n8n(host, port, user, password)
        if dbexisted == False:
            print("n8n Database created")
        else:
            print("n8n Database already exists")
    
    #db.create_db_n8n(host, port, user, password)

def dbreset():
    #Reset all states 
    resetState()
    #Drop all tables 
    db.drop_all_tables(host, port, user, password, database)

def backupMetabaseTemplate(host,port):
    import optionalDBConnectors as optionalDB
    optionalDB.back_postgresDB(host,port)

def metabaseTempalateReplace(host,port,user,password,tools):
    import optionalDBConnectors as optionalDB
    print("Dropping DB")
    optionalDB.drop_metabase_db(host,port,user,password)
    print("configuring DB")
    configoptionalTools(host, port, user, password, tools)

def removeCronJobs():
    cron = CronTab(user=True)  # Use 'user=True' for the current user or specify a username

    # Define the commands of the cron jobs you want to remove
    command_to_remove_1 = 'cd /usr/src/app && /usr/local/bin/python /usr/src/app/scripts/VickyTopiaReportCLI.py --refreshTables >> /var/log/refreshTables.log 2>&1'
    command_to_remove_2 = 'cd /usr/src/app && /usr/local/bin/python /usr/src/app/scripts/VickyTopiaReportCLI.py --difTables >> /var/log/difTables.log 2>&1'
    command_to_remove_3 = 'cd /usr/src/app && /usr/local/bin/python /usr/src/app/scripts/VickyTopiaReportCLI.py --allreports >> /var/log/crontab.log 2>&1'
    # Remove the first cron job
    for job in cron:
        if job.command == command_to_remove_1:
            cron.remove(job)
            print(f'Removed job: {job}')

    # Remove the second cron job
    for job in cron:
        if job.command == command_to_remove_2:
            cron.remove(job)
            print(f'Removed job: {job}')

    # Write the changes to the crontab
    cron.write()

    print("Cron jobs removed.")

def createCronJobs():
    #Create the reoccuring Cron job
    cron = CronTab(user=True)
    #Run full sync 
    #starts at 00:00 local time
    #job0 = cron.new(command='cd /usr/src/app && /usr/local/bin/python /usr/src/app/scripts/VickyTopiaReportCLI.py --allreports >> /var/log/fullsync.log 2>&1', comment='24 hours starting at 00:00 All Reports job - Includes All tables ')
    #job0.setall('0 0 * * *')  # Set to run every 4 hours

    # Create the first cron job
    ##  Starts at 04:00
    ## Has 3 hours to complete - next job starts at 07:00
    job1 = cron.new(command='cd /usr/src/app && /usr/local/bin/python /usr/src/app/scripts/VickyTopiaReportCLI.py --refreshTables >> /var/log/refreshTables.log 2>&1', comment='12 hours starting at 4:00 refreshTables job - Includes Endpoints, groups, patches, ')
    job1.setall('0 4/12 * * *')  # Set to run every 4 hours
    #job1 = cron.new(command='cd /usr/src/app && /usr/local/bin/python /usr/src/app/scripts/VickyTopiaReportCLI.py --refreshTables >> /var/log/refreshTables.log 2>&1', comment='4 hour refreshTables job')
    #job1.setall('0 */4 * * *')  # Set to run every 4 hours

    # Create the second cron job
    #  starts at 7:00 
    # has 5 hours to complete next job starts at 12:00 
    job2 = cron.new(command='cd /usr/src/app && /usr/local/bin/python /usr/src/app/scripts/VickyTopiaReportCLI.py --activeVulnsTable >> /var/log/fullsync.log 2>&1', comment='24 hours starting at 00:00 activeVulnsTable job - Includes endpoitns and Active Vulns ')
    job2.setall('0 7/12 * * *')  
    #job2 = cron.new(command='cd /usr/src/app && /usr/local/bin/python /usr/src/app/scripts/VickyTopiaReportCLI.py --difTables >> /var/log/difTables.log 2>&1', comment='4 hour difTables job')
    #job2.setall('0 2-22/4 * * *')  # Set to run at 0 minutes past every 4th hour from 2 AM to 10 PM


    # Create the Third cron job
    # starts at 00:00 
    # has 4 hours to complete next job starts at 
    job3 = cron.new(command='cd /usr/src/app && /usr/local/bin/python /usr/src/app/scripts/VickyTopiaReportCLI.py --difTables >> /var/log/difTables.log 2>&1', comment='4 hour difTables job')
    job3.setall('0 0/12 * * *')
    # Write the jobs to the cron tab
    cron.write()
    print("Cron job created:")

def listCronJobs():
    # Create a new cron object
    cron = CronTab(user=True)  # Use 'user=True' for the current user or specify a username

    # Iterate through the cron jobs and print them
    print("Listing all cron jobs:")
    for job in cron:
        print(job)

# Removed clean_future_dated_records function due to syntax issues
    
    # Add other tables as needed

def main():
    #args.dashboard
    startTime = datetime.now()
    print("Script start time: " + str(startTime))    
    errorList = []
    print("Starting VickyTopia Report CLI")
    lastrun = dictState['vRxLastRun']
    vRxSetup = dictState['vRxSetup']
    print('Last run: ' + str(lastrun))
    print('vRxReportsSetup: ' + str(vRxSetup))

    if args.resetstate:
        dbreset()
        resetState()
        exit()
    if args.metabaseTempalateReplace:
        print("Replacing Metabase Template ")
        metabaseTempalateReplace(host, port, user, password, tools)
        print("Metabase Template is up to date ")
        exit()
    if vRxSetup == 0:
        removeCronJobs()
        reports = "initSync"
        now = datetime.now()
        
        # Log system time for diagnostics
        print(f"Current system time: {now.strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Calculate start date (36 months back)
        m1 = now - relativedelta(months=36)
        date_str = m1.strftime("%Y-%m-%d")
        start_date = date_str
        end_date = now.strftime("%Y-%m-%d")
        
        # Log date range for diagnostics
        print(f"Initial sync date range: {start_date} to {end_date}")
        
        # Check if range is reasonable
        start_dt = datetime.strptime(start_date, "%Y-%m-%d")
        days_diff = (now - start_dt).days
        if days_diff > 1500:  # ~4 years
            print(f"WARNING: Large date range of {days_diff} days (~{days_diff/365:.1f} years)")
            print("This may take a long time to process and could exceed API limits")
            # Optional: Add confirmation prompt
        
        print('Reports dashboard has not been setup. Completing the initial run!')
        BeginRun = datetime.now()
        print("Pulling Data Start Time: " + str(BeginRun))

        print("Query Start date: " + str(start_date))
        print("Query End date: " + str(end_date))
        #Reset Database 

        #Setup Database
        db.check_create_database(host, port, user, password, database)
        cd.remove_all_except()
        #Setup Metabase 
        print("Setting up metabase database")
        time.sleep(5)
        configoptionalTools(host, port, user, password, tools)
        try:
            ReportEndpoints()
        except Exception as e:           
            errorList.append("ReportEndpoints:" + e)
            print(str(e))
        print("Completed Pulling endpoints")
        try:
            ReportGroupsSearchs()
        except Exception as e:
            errorList.append("ReportGroupsSearchs:" + str(e))
            print(str(e))
        print("Completed Pulling Groups")
        gc.collect()
        time.sleep(60)
        try:
            ReportTaskEvents(start_date, end_date)   
            gc.collect()
        except Exception as e:
            errorList.append("ReportTaskEvents:" + str(e))
            print(str(e))
        print("Completed Pulling Tasks")
        time.sleep(60)
        try:
            ReportVunerabilities()
            gc.collect()
        except Exception as e:
            errorList.append("ReportVunerabilities:" + str(e))
            print(str(e))
        print("Completed Pulling Vulnerabilites")
        time.sleep(60)
        try:
            ReportEndpointPatchs()
            gc.collect()
        except Exception as e:
            errorList.append("ReportEndpointPatchs:" + str(e))
            print(str(e))
        print("Completed Pulling Patches")
        time.sleep(60)
        try:
            ReportIncident(start_date, end_date)
            gc.collect()
        except Exception as e:
            errorList.append("ReportIncident:" + str(e))
            print(str(e)) 
        print("Completed Pulling Incidents")
        time.sleep(60) 
        try:
            ReportHasPatchApps()
            gc.collect()       
        except Exception as e:
            errorList.append("ReportHasPatchApps:" + str(e))
            print(str(e)) 
        print("Completed Pulling Apps")
        EndRun = datetime.now()
        print("Initial Run Completed: " + str(EndRun))
        dictState.update({'vRxSetup': 1})
        state.setState(dictState)
        #Remove initial cron
        try:
            os.remove("/etc/cron.d/my-crontab")
        except:
            print("initcron does not exist")
        print("creating cron job for updating database")
        removeCronJobs()
        #createCronJobs()
        #listCronJobs()    
    elif vRxSetup == 2:
        reports = "1monthinit"
        removeCronJobs()
        now = datetime.now()
        m1 = now - relativedelta(months=1)
        date_str = m1.strftime("%Y-%m-%d")
        start_date = date_str
        end_date = now.strftime("%Y-%m-%d")
        print('Reports dashboard has not been setup. Completing the 1month run!')
        BeginRun = datetime.now()
        print("Pulling Data Start Time: " + str(BeginRun))

        print("Query Start date: " + str(start_date))
        print("Query End date: " + str(end_date))
        #Reset Database 

        #Setup Database
        db.check_create_database(host, port, user, password, database)
        cd.remove_all_except()


        print("Setting up metabase database")
        time.sleep(5)
        configoptionalTools(host, port, user, password, tools)
        try:
            ReportEndpoints()
        except Exception as e:           
            errorList.append("ReportEndpoints:" + e)
            print(str(e))
        print("Completed Pulling endpoints")
        try:
            ReportGroupsSearchs()
        except Exception as e:
            errorList.append("ReportGroupsSearchs:" + str(e))
            print(str(e))
        print("Completed Pulling Groups")
        time.sleep(60)
        try:
            ReportTaskEvents(start_date, end_date)
            gc.collect()
        except Exception as e:
            errorList.append("ReportTaskEvents:" + str(e))
            print(str(e))
        print("Completed Pulling Tasks")
        time.sleep(60)
        try:
            ReportVunerabilities()
            gc.collect()
        except Exception as e:
            errorList.append("ReportVunerabilities:" + str(e))
            print(str(e))
        print("Completed Pulling Vulnerabilites")
        time.sleep(60)
        try:
            ReportEndpointPatchs()
            gc.collect()
        except Exception as e:
            errorList.append("ReportEndpointPatchs:" + str(e))
            print(str(e))
        print("Completed Pulling Patches")
        time.sleep(60)
        try:
            ReportIncident(start_date, end_date)
            gc.collect()
        except Exception as e:
            errorList.append("ReportIncident:" + str(e))
            print(str(e)) 
        print("Completed Pulling Incidents")
        time.sleep(60) 
        try:
            ReportHasPatchApps()       
        except Exception as e:
            errorList.append("ReportHasPatchApps:" + str(e))
            print(str(e)) 
        print("Completed Pulling Apps")
        EndRun = datetime.now()
        print("Initial Run Completed: " + str(EndRun))
        dictState.update({'vRxSetup': 1})
        state.setState(dictState)
        #Remove initial cron
        try:
            os.remove("/etc/cron.d/my-crontab")
        except:
            print("initcron does not exist")
        print("creating cron job for updating database")
        removeCronJobs()
        #createCronJobs()
        #listCronJobs() 
    else:
        startTime = datetime.now()

        print("Script start time: " + str(startTime))
        
        # Check if metabase database exists and initialize if needed
        if "metabase" in tools:
            metabase_exists = checkMetabaseExists(host, port, user, password)
            if not metabase_exists:
                print("Metabase database not found. Initializing...")
                configoptionalTools(host, port, user, password, tools)
            else:
                print("Metabase database exists. Skipping initialization.")
        
        if args.allreports:
            reports = "allreports"
            # print current timestamp as script start time
            startTime = datetime.now()
            print("Script start time: " + str(startTime))
            
            db.check_create_database(host, port, user, password, database)
            cd.remove_all_except()

            try:
                ReportEndpoints()
            except Exception as e:           
                errorList.append("ReportEndpoints:" + e)
                print(str(e))

            try:
                ReportGroupsSearchs()
            except Exception as e:
                errorList.append("ReportGroupsSearchs:" + str(e))
                print(str(e))
            time.sleep(60)
            
            try:
                ReportVunerabilities()
            except Exception as e:
                errorList.append("ReportVunerabilities:" + str(e))
                print(str(e))
            
            time.sleep(120)            

            try:
                ReportTaskEvents()
            except Exception as e:
                errorList.append("ReportTaskEvents:" + str(e))
                print(str(e))
            time.sleep(60)


            try:
                ReportEndpointPatchs()
            except Exception as e:
                errorList.append("ReportEndpointPatchs:" + str(e))
                print(str(e))
            time.sleep(60)

            try:
                ReportIncident()
            except Exception as e:
                errorList.append("ReportIncident:" + str(e))
                print(str(e))  
            time.sleep(60)
            try:
                ReportHasPatchApps()          
            except Exception as e:
                errorList.append("ReportHasPatchApps:" + str(e))
                print(str(e)) 
            time.sleep(60)
            #cd.cleanData()
            #mt.get_mitigation_time()
            
        elif args.assetsreport:
            reports = "assetsreport"
            ReportEndpoints()
            #ReportEndpointsAttributes()
            #ReportEndpointScores()        
            #ReportGroupsAtrributesTags()
            ReportGroupsSearchs()

        elif args.tasksreport:
            reports = "tasksreport"    
            if args.start_date and args.end_date:
                ReportTaskEvents(args.start_date, args.end_date)
            else:
                ReportTaskEvents()

        elif args.tasksWaitingreport:
            reports = "tasksWaitingreport"    
            try:
                getWaitingEndpoitnTasks()
            except Exception as e:
                errorList.append("getWaitingEndpoitnTasks:" + str(e))
                print(str(e)) 
            
        elif args.vulnreport:
            reports = "vulnreport" 
            ReportVunerabilities()        

        elif args.patchsreport:
            reports = "patchsreport" 
            ReportEndpointPatchs()

        elif args.incidentvulreport:
            reports = "incidentvulreport" 
            if args.start_date and args.end_date:
                ReportIncident(args.start_date, args.end_date)
            else:
                ReportIncident()

        elif args.eventreport:
            reports = "eventreport" 
            ReportEventLog()

        elif args.impersonationreport:
            reports = "impersonationreport" 
            ReportIncidientImpersontation()
    
        elif args.hasPatchAppsreport:
            reports = "hasPatchAppsreport" 
            ReportHasPatchApps()
   
        elif args.resetstate:
            reports = "resetstate"
            dbreset()
            resetState()
            exit()
   
        elif args.mitigationtime:
            reports = "mitigationtime"
            mt.get_mitigation_time()
        
        elif args.cleandata:
            reports = "cleandata"
            cd.cleanData()
        
        elif args.updatestate:
            reports = "updatestate"
            updateState ()
        
        elif args.updateExternalScore:
            reports = "updateExternalScore"
            updExSc.download_and_load_epss_data (host, port, user, password, database)
        
        elif args.external:
            reports = "external"
            print("Updating external vulnerability data (KEV + EPSS)")
            import updateExternalScore as ext
            ext.download_and_load_epss_data(host, port, user, password, database)
            ext.download_and_load_kev_data(host, port, user, password, database)
            print("External data update complete")
        
        elif args.metabaseTempalateBackup:
            reports = "metabaseTempalateBackup"
            print("Backing up Metabase Template")
            print("Option is Disabled")
            backupMetabaseTemplate(host, port)

        elif args.createMBUser:
            reports = "createMBUser"
            import optionalDBConnectors as optionalDB
            print("Creating Metabase User")
            print("Option is Disabled")
            optionalDB.create_user_metabase(host, port, user, password)
        
        elif args.refreshTables:
            #Update Tables that get a full reset
            reports = "refreshTables"
            print(reports)
            db.check_create_database(host, port, user, password, database)
            cd.remove_all_except()

            try:
                ReportEndpoints()
            except Exception as e:           
                errorList.append("ReportEndpoints:" + e)
                print(str(e))
            time.sleep(60)
            try:
                ReportGroupsSearchs()
            except Exception as e:
                errorList.append("ReportGroupsSearchs:" + str(e))
                print(str(e))
            time.sleep(60)
            #try:
            #    ReportVunerabilities()
            #except Exception as e:
            #    errorList.append("ReportVunerabilities:" + str(e))
            #    print(str(e))
            #time.sleep(120)            
            try:
                ReportEndpointPatchs()
            except Exception as e:
                errorList.append("ReportEndpointPatchs:" + str(e))
                print(str(e))
            time.sleep(60)
            try:
                ReportEndpointPatchs_old()
            except Exception as e:
                errorList.append("ReportEndpointPatchs_old:" + str(e))
                print(str(e))
            time.sleep(60)
            try:
                ReportHasPatchApps()          
            except Exception as e:
                errorList.append("ReportHasPatchApps:" + str(e))
                print(str(e)) 
            time.sleep(60)
            try:
                getWaitingEndpoitnTasks()
            except Exception as e:
                errorList.append("getWaitingEndpoitnTasks:" + str(e))
                print(str(e)) 
            time.sleep(60)
        
        elif args.activeVulnsTable:
            reports = "activeVulns"
            print(reports)
            try:
                ReportEndpoints()
            except Exception as e:           
                errorList.append("ReportEndpoints:" + e)
                print(str(e))
            time.sleep(60)
            try:
                ReportVunerabilities()
            except Exception as e:
                errorList.append("ReportVunerabilities:" + str(e))
                print(str(e))
            time.sleep(120) 

        elif args.difTables:
            reports = "difTables"
            print(reports)
            #Update Tables that only track the difference
            ##Tasks
            try:
                ReportTaskEvents()
            except Exception as e:
                errorList.append("ReportTaskEvents:" + str(e))
                print(str(e))
            time.sleep(60)
            ##INCIDENTS
            try:
                ReportIncident()
            except Exception as e:
                errorList.append("ReportIncident:" + str(e))
                print(str(e)) 

        else:
            print("Select one report and try again!!!")
    
    endTime =  datetime.now()

    dictState.update({'vRxLastRun': str(endTime)})
    state.setState(dictState)

    #create Views
    db.create_table_views(host, port, user, password, database)
    
    print("Script end time: " + str(endTime))
    print("Script Error List:" + str(errorList))

    logscriptActivity(startTime,endTime,errorList,reports)

    print("***********************************")
    print("End of Run ")
    print("***********************************")
if __name__ == '__main__':
    main()
