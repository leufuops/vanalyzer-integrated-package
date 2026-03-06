#Author: Joaldir Rani

import requests
import json
import utils
import time
from datetime import datetime

def getCountEvents(apikey, urldashboard, lastdate):
    headers = {
        'Accept': 'application/json',
        'Vicarius-Token': apikey,
    }

    params = {
        'from': 0,
        'size': 1,
        'sort': '-analyticsEventCreatedAt',
        'q': 'analyticsEventCreatedAt>' + str(lastdate),
    }

    response = requests.get(urldashboard + '/vicarius-external-data-api/taskEndpointsEvent/count', params=params, headers=headers)
    jsonresponse = json.loads(response.text)
    responsecount = jsonresponse['serverResponseCount']

    return responsecount

def getUpdatedTaskEndpointsEvents(apikey, urldashboard, fr0m, siz3, maxdate, mindate):
    """Get updated task endpoints events from the API.
    
    Note: This function needs to be completed with proper implementation.
    Currently it only defines headers and parameters but doesn't make the request
    or return anything.
    """
    headers = {
        'Accept': 'application/json',
        'Vicarius-Token': apikey,
    }

    params = {
        'from': fr0m,
        'size': siz3,
        'sort': '-analyticsEventUpdatedAtNano',
        'q': 'analyticsEventUpdatedAtNano>' + mindate + ';analyticsEventUpdatedAtNano<' + maxdate,
    }
    
    # This function appears incomplete - add placeholder return
    return [], mindate

def getTasksEndopintsEvents(apikey, urldashboard, fr0m, siz3, maxdate, mindate):
    """Get task endpoints events from the API.
    
    Args:
        apikey: The API key for authentication
        urldashboard: The base URL for the dashboard
        fr0m: The starting index for pagination
        siz3: The number of records to retrieve
        maxdate: The maximum date in nanoseconds (as string)
        mindate: The minimum date in nanoseconds (as string)
        
    Returns:
        A tuple containing (tasks_list, lastdate)
    """
    headers = {
        'Accept': 'application/json',
        'Vicarius-Token': apikey,
    }

    params = {
        'from': fr0m,
        'size': siz3,
        'sort': '-analyticsEventUpdatedAtNano',
        'q': 'analyticsEventUpdatedAtNano>' + mindate + ';analyticsEventUpdatedAtNano<' + maxdate,
    }
    
    # Initialize lastdate with a default value to avoid reference errors
    lastdate = mindate  # Use mindate as fallback value
    tasks_list = []  # Initialize tasks_list at function scope
    
    try:
        response = requests.get(urldashboard + '/vicarius-external-data-api/taskEndpointsEvent/filter', params=params, headers=headers)
        if response.status_code == 429:
            print("API Rate Limit exceeded ... Waiting and Trying again")
            time.sleep(60)
            return getTasksEndopintsEvents(apikey, urldashboard, fr0m, siz3, maxdate, mindate)
            
        # Check if response was successful
        if response.status_code != 200:
            print(f"API request failed with status code: {response.status_code}")
            print(f"Response text: {response.text}")
            return tasks_list, lastdate
            
        parsed = json.loads(response.text)
        
        # Add this to log the raw timestamp values before parsing
        try:
            print(f"Raw API date range - min: {mindate}, max: {maxdate}")
            current_time = datetime.now()
            print(f"Current system time: {current_time.isoformat()}")
            
            # Check for system clock issues
            if current_time.year >= 2025:
                print("WARNING: System clock appears to be set to a future date!")
                print("This could cause issues with date comparisons.")
            
            # Log a few sample dates from the response for verification
            if 'serverResponseObject' in parsed and len(parsed['serverResponseObject']) > 0:
                sample_count = min(3, len(parsed['serverResponseObject']))
                for i in range(sample_count):
                    sample = parsed['serverResponseObject'][i]
                    if 'analyticsEventUpdatedAtNano' in sample:
                        timestamp = sample['analyticsEventUpdatedAtNano']
                        date = datetime.fromtimestamp(int(timestamp) / 1e9)
                        print(f"Sample record {i} timestamp: {timestamp}, date: {date.isoformat()}")
        except Exception as e:
            print(f"Error in date validation: {e}")
        
        # Filter out future-dated tasks from the API response
        if 'serverResponseObject' in parsed and len(parsed['serverResponseObject']) > 0:
            # Use our new parsing function to filter out future-dated tasks
            filtered_response = parseTasksEndopintsEvents(parsed)
            if filtered_response and len(filtered_response) > 0:
                # Replace the original response with filtered one
                parsed['serverResponseObject'] = filtered_response
        
        src = len(parsed.get('serverResponseObject', []))
        if src == 0:
            print("Count is zero")
            tasks_list = 0
            # Keep lastdate as initialized above
        else:
            for i in parsed['serverResponseObject']:
                # Initialize task-specific variables before try block
                task_dict = None
                
                try:
                    automationName = i['taskEndpointsEventTask']['taskAutomation']['automationName']
                    automationId = i['taskEndpointsEventTask']['taskAutomation']['automationId']
                except:
                    automationName = ""
                    automationId = ""
                
                try:
                    taskid = i['taskEndpointsEventTask']['taskId']
                    asset = i['taskEndpointsEventEndpoint']['endpointName']
                    endpointId = i['taskEndpointsEventEndpoint']['endpointId']
                    endpointHash = i['taskEndpointsEventEndpoint']['endpointHash']
                except Exception as e:
                    print(f"Error accessing essential task properties: {e}")
                    continue  # Skip this record
                
                try:
                    username = i['taskEndpointsEventTask']['taskUser']['userFirstName']
                    username = username + " " + i['taskEndpointsEventTask']['taskUser']['userLastName']
                except:
                    username=""
                
                try:
                    taskType = i['taskEndpointsEventTask']['taskTaskType']['taskTypeName']
                except:
                    taskType = ""

                try:
                    publisherName = i['taskEndpointsEventTask']['taskPublisher']['publisherName']
                except:
                    publisherName = ""
                
                try:
                    orgTeamName = i['taskEndpointsEventTask']['taskAutomation']['automationOrganizationTeam']['organizationTeamName']
                except:
                    orgTeamName = ""
                
                try: 
                    runSequence = i['taskEndpointsEventTask']['taskAutomationRun']['automationRunSequence']
                except:
                    runSequence = ""
                
                try:
                    assetStatus = i['taskEndpointsEventEndpoint']['endpointEndpointStatus']['endpointStatusName']
                except:
                    assetStatus = ""
                
                pathproduct = ""
                pathproductdesc = ""
                patchName = ""
                patchFileName = ""
                patchPackageFileName = ""
                
                try:
                    patchReleaseDate = i['analyticsEventUpdatedAt']
                except:
                    patchReleaseDate = 0

                if 'taskPatch' in i['taskEndpointsEventTask']:
                    if i['taskEndpointsEventTask']['taskPatch'] != {}:
                        if 'patchName' in i['taskEndpointsEventTask']['taskPatch']:
                            try:            
                                patchName = i['taskEndpointsEventTask']['taskPatch']['patchName']
                            except:
                                patchName = ""
                            try:
                                patchFileName = i['taskEndpointsEventTask']['taskPatch']['patchFileName']
                            except:
                                patchFileName = ""
                            try:
                                patchReleaseDate = i['taskEndpointsEventTask']['taskPatch']['patchReleaseDate']
                            except:
                                patchReleaseDate = i.get('analyticsEventUpdatedAt', 0)
                            try:
                                pathproductdesc = i['taskEndpointsEventTask']['taskPatch']['patchDescription']
                                if "," in pathproductdesc:
                                    pathproductdesc = pathproductdesc.replace(",", " ")
                            except:
                                pathproductdesc = ""
                        else:
                            pathproduct = ""
                            pathproductdesc = ""
                    else:
                        pathproduct = ""
                        pathproductdesc = ""
                else:
                    pathproduct = ""
                    pathproductdesc = ""
                
                if 'taskProduct' in i['taskEndpointsEventTask']:
                    if 'productName' in i['taskEndpointsEventTask']['taskProduct']:
                        try:
                            pathproduct = i['taskEndpointsEventTask']['taskProduct']['productName']
                        except KeyError:
                            pathproduct = ""
                else:
                    pathproduct = ""

                try:
                    if 'ApplyPublisherOperatingSystemVersionsPatchs' in taskType:
                        pathproduct = i['taskEndpointsEventTask']['taskOperatingSystem']['operatingSystemName']
                except:
                    pass  # Keep existing pathproduct value
                
                actionStatus = ""
                messageStatus = ""
                
                try:
                    if 'ActivateTopia' in (i['taskEndpointsEventTask']['taskTaskType']['taskTypeName']):
                        actionStatus = taskType
                        messageStatus = ""
                    else:
                        try:
                            actionStatus = i['taskEndpointsEventOrganizationEndpointPatchPatchPackages']['organizationEndpointPatchPatchPackagesActionStatus']['actionStatusName']
                            messageStatus = i['taskEndpointsEventOrganizationEndpointPatchPatchPackages']['organizationEndpointPatchPatchPackagesStatusMessage']
                        except:
                            actionStatus = ""
                            messageStatus = ""
                except:
                    pass  # Keep existing values
                
                try:
                    if 'RunScript' in (i['taskEndpointsEventTask']['taskTaskType']['taskTypeName']):
                        # set actionstatus to taskTaskStatus taskStatusName
                        try:
                            messageStatus = i['taskEndpointsEventOrganizationEndpointTaskScriptTemplateCommandAbs']['organizationEndpointTaskOrganizationScriptTemplatesOutput'] 
                        except:
                            messageStatus = ''
                        
                        actionStatus = i['taskEndpointsEventTask']['taskTaskStatus']['taskStatusName']
                        
                        try:
                            pathproductdesc = i['taskEndpointsEventTask']['taskScriptTemplate']['organizationScriptTemplateName']
                        except:
                            pathproductdesc = ''
                except:
                    pass  # Keep existing values
                
                try:
                    createAt = i['analyticsEventCreatedAt']
                    updateAt = i['analyticsEventUpdatedAt']
                    createAtNano = i['analyticsEventCreatedAtNano']
                    updateAtNano = i['analyticsEventUpdatedAtNano']
                except Exception as e:
                    print(f"Error accessing timestamp fields: {e}")
                    continue  # Skip this record if we can't get timestamps
                
                try:
                    hcreateAt = datetime.fromtimestamp(createAt / 1000).isoformat()
                    hupdateAt = datetime.fromtimestamp(updateAt / 1000).isoformat()
                except:
                    hcreateAt = ""
                    hupdateAt = ""

                try:
                    # Clean up description and message fields
                    pathproductdesc = pathproductdesc.replace("\r","").replace("\n",">>")
                    pathproductdesc = pathproductdesc.replace('"',"").strip('\n')
                    pathproductdesc = pathproductdesc.replace(",", "")

                    messageStatus = messageStatus.replace("\r","").replace("\n",">>")
                    messageStatus = messageStatus.replace('"',"").strip('\n')
                except:
                    pass  # Keep existing values
                
                try:
                    task_dict = {
                        "endpointId": endpointId,
                        "taskid": taskid,
                        "automationId": automationId,
                        "automationName": automationName,
                        "assetHash": endpointHash,
                        "asset": asset,
                        "taskType": taskType,
                        "publisherName": publisherName,
                        "pathproduct": pathproduct,
                        "pathproductdesc": pathproductdesc,
                        "patchName": patchName,
                        "patchFileName": patchFileName,
                        "patchPackageFileName": patchPackageFileName,
                        "patchReleaseDate": patchReleaseDate,
                        "actionStatus": actionStatus,
                        "messageStatus": messageStatus,
                        "username": username,
                        "orgTeam": orgTeamName,
                        "runSequence": runSequence,
                        "assetStatus": assetStatus,
                        "createAtNano": createAtNano,
                        "updateAtNano": updateAtNano,
                        "hcreateAt": hcreateAt,
                        "hupdateAt": hupdateAt,
                        "createAt": createAt,
                        "updateAt": updateAt
                    }
                    
                    if isinstance(tasks_list, list):  # Make sure tasks_list is still a list
                        tasks_list.append(task_dict)
                    else:
                        # If tasks_list was changed to 0 earlier, reset it to a list
                        tasks_list = [task_dict]
                    
                    # Update lastdate with the most recent task time
                    lastdate = i['analyticsEventUpdatedAtNano']
                except Exception as e:
                    print(f"Error creating task dictionary: {e}")
                    # Continue with next record
    
    except Exception as e:
        print(f"Error processing tasks: {e}")
        # Return whatever we've collected so far
    
    # Final validation to make sure we return the expected types
    if not isinstance(tasks_list, list):
        tasks_list = []
    
    return tasks_list, lastdate

def parseTasksEndopintsEvents(response):
    """Parses API response and filters out future-dated tasks."""
    # Get current time
    current_time = int(datetime.now().timestamp() * 1e9)
    valid_tasks = []
    future_tasks = 0
    
    # For each task in the response
    for task in response['serverResponseObject']:
        # Get timestamp
        update_time_ns_key = 'analyticsEventUpdatedAtNano'
        
        if update_time_ns_key in task:
            try:
                task_time = int(task[update_time_ns_key])
                
                # Filter out future dates
                if task_time <= current_time:
                    # Process valid task
                    valid_tasks.append(task)
                else:
                    future_tasks += 1
                    # Log rejected task
                    try:
                        task_id = task.get('taskEndpointsEventTask', {}).get('taskId', 'unknown')
                        date_str = datetime.fromtimestamp(task_time/1e9).isoformat()
                        print(f"Rejected future-dated task: {task_id} with date {date_str}")
                    except Exception as e:
                        print(f"Error logging future task: {e}")
            except ValueError as e:
                print(f"Error parsing timestamp: {e}")
                # Include it anyway since we can't validate the date
                valid_tasks.append(task)
        else:
            print(f"Warning: Task missing update timestamp key: {update_time_ns_key}")
            # Include it anyway since we can't validate the date
            valid_tasks.append(task)
    
    print(f"Task filtering summary: {len(response['serverResponseObject'])} total, {len(valid_tasks)} valid, {future_tasks} with future dates")
    
    # Return only valid tasks
    return valid_tasks

def getTasksEndopintsEventsWaiting(apikey,urldashboard,fr0m,siz3,maxdate,mindate,aID):

    headers = {
        'Accept': 'application/json',
        'Vicarius-Token': apikey,
    }

    params = {
        #'includeFields': 'taskEndpointsEventOrganizationEndpointPatchPatchPackages;taskEndpointsEventEndpoint.endpointName;taskEndpointsEventTask;analyticsEventCreatedAt;analyticsEventUpdatedAt',
        'from': fr0m,
        'size': siz3,
        'sort' : '+analyticsEventUpdatedAtNano',
        'q':'analyticsEventUpdatedAtNano>' + mindate + ';analyticsEventUpdatedAtNano<' + maxdate +';taskEndpointsEventTask.automationId==' + aID,
    }
    #print(params) 
    # 
    print(aID)
    print(params)   
    response = requests.get(urldashboard + '/vicarius-external-data-api/taskEndpointsEvent/filter', params=params, headers=headers)
    parsed = json.loads(response.text)
    print(response.status_code)
    #print(parsed)
    #strTasks = ""
    tasks_list = []
    if response.status_code == 429:
        print("API Rate Limit exceeded ... Waiting and Trying again")
        time.sleep(60)
        return 0
    #print (maxdate, mindate)
    #print (parsed)
    src = len(parsed['serverResponseObject'])
    #print("length of taskEndpointsEvents/filter Response")
    #print(src)
    if src == 0:
        print("Count is zero")
        tasks_list = 0 
        lastdate = 0
    else:
        for i in parsed['serverResponseObject']:
            
            #taskEndpointsEventTask taskOperatingSystem operatingSystemName
            #print(i['taskEndpointsEventTask']['taskOperatingSystem']['operatingSystemName'])
            #if i['taskEndpointsEventTask']['taskTaskType']['taskTypeName'] == "RunScript":
            #    print(json.dumps(i, indent=4, sort_keys=True))
            #print(json.dumps(i, indent=4, sort_keys=True))

            try:
                automationName = i['taskEndpointsEventTask']['taskAutomation']['automationName']
                automationId = i['taskEndpointsEventTask']['taskAutomation']['automationId']
            except:
                automationName = ""
                automationId = ""

            
            taskid = i['taskEndpointsEventTask']['taskId']
            asset = i['taskEndpointsEventEndpoint']['endpointName']
            endpointId = i['taskEndpointsEventEndpoint']['endpointId']
            endpointHash = i['taskEndpointsEventEndpoint']['endpointHash']
            
            try:
                username = i['taskEndpointsEventTask']['taskUser']['userFirstName']
                username = username + " " + i['taskEndpointsEventTask']['taskUser']['userLastName']
            except:
                username=""
            
            try:
                taskType = i['taskEndpointsEventTask']['taskTaskType']['taskTypeName']
            except:
                taskType = ""

            try:
                publisherName = i['taskEndpointsEventTask']['taskPublisher']['publisherName']
            except:
                publisherName = ""
            try:
                orgTeamName = i['taskEndpointsEventTask']['taskAutomation']['automationOrganizationTeam']['organizationTeamName']
            except:
                orgTeamName = ""
            try: 
                runSequence = i['taskEndpointsEventTask']['taskAutomationRun']['automationRunSequence']
            except:
                runSequence = ""
            try:
                assetStatus = i['taskEndpointsEventEndpoint']['endpointEndpointStatus']['endpointStatusName']
            except:
                assetStatus = ""
            
            pathproduct = ""
            pathproductdesc = ""
            patchName = ""
            patchFileName = ""
            patchPackageFileName = ""
            patchReleaseDate = i['analyticsEventUpdatedAt']

            if 'taskPatch' in i['taskEndpointsEventTask']:
                if i['taskEndpointsEventTask']['taskPatch'] != {}:
                    #print(i['taskEndpointsEventTask']['taskPatch'])
                    if 'patchName' in i['taskEndpointsEventTask']['taskPatch']:
                        try:            
                            patchName  = i['taskEndpointsEventTask']['taskPatch']['patchName']
                        except:
                            patchName  = ""
                        try:
                            patchFileName = i['taskEndpointsEventTask']['taskPatch']['patchFileName']
                        except:
                            patchFileName = ""
                        try:
                            patchReleaseDate = i['taskEndpointsEventTask']['taskPatch']['patchReleaseDate']
                        except:
                            patchReleaseDate = i['analyticsEventUpdatedAt']
                        try:
                            pathproductdesc = i['taskEndpointsEventTask']['taskPatch']['patchDescription']
                            substring = ","
                            if substring in pathproductdesc:
                                pathproductdesc = pathproductdesc.replace(",", " ")
                        except:
                            pathproductdesc = ""
                else:
                    pathproduct = ""
                    pathproductdesc = ""
            else:
                pathproduct = ""
                pathproductdesc = ""

            #if 'patchPackageFileName' in i['taskEndpointsEventOrganizationEndpointPatchPatchPackages']:
            #    print(i['taskEndpointsEventOrganizationEndpointPatchPatchPackages'])
            #    patchPackageFileName = i['taskEndpointsEventOrganizationEndpointPatchPatchPackages']['organizationEndpointPatchPatchPackagesPatchPackage']['patchPackageFileName']
            
            if 'taskProduct' in i['taskEndpointsEventTask']:
                if 'productName' in i['taskEndpointsEventTask']['taskProduct']:
                    try:
                        pathproduct = i['taskEndpointsEventTask']['taskProduct']['productName']
                    except KeyError:
                        pathproduct = ""
            else:
                pathproduct = ""

            if 'ApplyPublisherOperatingSystemVersionsPatchs' in taskType:
                pathproduct = i['taskEndpointsEventTask']['taskOperatingSystem']['operatingSystemName']
            
            if 'ActivateTopia' in (i['taskEndpointsEventTask']['taskTaskType']['taskTypeName']):
                actionStatus = taskType
                messageStatus = ""
            else:
                try:
                    actionStatus = i['taskEndpointsEventOrganizationEndpointPatchPatchPackages']['organizationEndpointPatchPatchPackagesActionStatus']['actionStatusName']
                    messageStatus = i['taskEndpointsEventOrganizationEndpointPatchPatchPackages']['organizationEndpointPatchPatchPackagesStatusMessage']
                except:
                    actionStatus = ""
                    messageStatus = ""
            
            if 'RunScript' in (i['taskEndpointsEventTask']['taskTaskType']['taskTypeName']):
                # set actionstatus to taskTaskStatus taskStatusName
                actionStatus = i['taskEndpointsEventTask']['taskTaskStatus']['taskStatusName']
                messageStatus = ""
                
            createAt = i['analyticsEventCreatedAt']
            updateAt = i['analyticsEventUpdatedAt']
            createAtNano = i['analyticsEventCreatedAtNano']
            updateAtNano = i['analyticsEventUpdatedAtNano']

            try:
                hcreateAt = datetime.fromtimestamp(createAt / 1000).isoformat()
                hupdateAt = datetime.fromtimestamp(updateAt / 1000).isoformat()
                #patchReleaseDate = datetime.fromtimestamp(patchReleaseDate / 1000).isoformat()
            except:
                hcreateAt = 0
                hupdateAt = 0

            pathproductdesc = pathproductdesc.replace("\r","").replace("\n",">>")
            pathproductdesc = pathproductdesc.replace('"',"").strip('\n')
            pathproductdesc = pathproductdesc.replace(",", "")


            messageStatus = messageStatus.replace("\r","").replace("\n",">>")
            messageStatus = messageStatus.replace('"',"").strip('\n')
            
            try:
                #replacing string concatenation for list of task_dict
                #strTasks += (str(taskid) + "," + str(automationId) + "," + automationName + "," + asset + "," + taskType + "," + publisherName + "," + pathproduct + ",\"" + pathproductdesc + "\"," + actionStatus + ",\"" + messageStatus + "\"," + username + "," + str(createAt) + "," + str(updateAt) + "\n")
                task_dict = {
                "endpointId" : endpointId,
                "taskid": taskid,
                "automationId": automationId,
                "automationName": automationName,
                "assetHash": endpointHash,
                "asset": asset,
                "taskType": taskType,
                "publisherName": publisherName,
                "pathproduct": pathproduct,
                "pathproductdesc": pathproductdesc,
                "patchName": patchName,
                "patchFileName": patchFileName,
                "patchPackageFileName": patchPackageFileName,
                "patchReleaseDate": patchReleaseDate,
                "actionStatus": actionStatus,
                "messageStatus": messageStatus,
                "username": username,
                "orgTeam": orgTeamName,
                "runSequence": runSequence,
                "assetStatus": assetStatus,
                "createAtNano": createAtNano,
                "updateAtNano": updateAtNano,
                "hcreateAt": hcreateAt,
                "hupdateAt": hupdateAt,
                "createAt": createAt,
                "updateAt": updateAt
                }
                tasks_list.append(task_dict)

                lastdate = i['analyticsEventUpdatedAtNano']
            except:
                if lastdate is None: 
                    lastdate = maxdate
                if task_dict is None: 
                    task_dict = {}
            #print (lastdate)

    #return strTasks,lastdate
    return tasks_list,lastdate