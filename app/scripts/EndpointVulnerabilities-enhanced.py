#Author: Joaldir Rani, Juan Osorio

import requests
import json
import time
import datetime
import utils
from datetime import datetime
import urllib.parse

def safe_convert_to_datetime(timestamp, default_value=None):
    """Safely convert a timestamp to datetime, handling seconds/milliseconds and errors."""
    if default_value is None:
        default_value = datetime.now()  # Or any other default datetime

    try:
        # Check if the timestamp is likely in milliseconds (large numbers)
        if timestamp > 1e10:  # Adjust threshold as necessary
            timestamp /= 1000.0  # Convert from milliseconds to seconds

        return datetime.fromtimestamp(timestamp)
    except (TypeError, ValueError, OverflowError):
        return default_value

def get_days_diff_from_timestamp(timestamp_ms):
    # Converter timestamp em milissegundos para objeto datetime
    dt = datetime.datetime.fromtimestamp(timestamp_ms / 1000.0)

    # Obter a data atual
    current_date = datetime.datetime.now().date()

    # Calcular a diferença em dias entre as duas datas
    diff = current_date - dt.date()

    # Retornar a diferença em dias
    return diff.days

def getCountEvents(apikey,urldashboard,lastdate):
    errors = []
    headers = {
        'Accept': 'application/json',
        'Vicarius-Token': apikey,
    }
    
    params = {
        'from': 0,
        'size': 1,
        'q' : 'organizationEndpointVulnerabilitiesEndpoint.endpointCreatedAt>' + str(lastdate)
    }
    response = requests.get(urldashboard + '/vicarius-external-data-api/organizationEndpointVulnerabilities/search', params=params, headers=headers)

    jsonresponse = json.loads(response.text)
        
    responsecount = jsonresponse['serverResponseCount']

    try:
        return responsecount
    except:
        return 0

def getCountEventsPerAsset(apikey,urldashboard,endpointHash,trycount=0):
    errors = []
    headers = {
        'Accept': 'application/json',
        'Vicarius-Token': apikey,
    }
    
    params = {
        'from': 0,
        'size': 500,
        'q': 'organizationEndpointVulnerabilitiesEndpoint.endpointHash=in=('+endpointHash+')',
        'includeFields' : 'organizationEndpointVulnerabilitiesEndpoint.endpointId,organizationEndpointVulnerabilitiesEndpoint.endpointHash,organizationEndpointVulnerabilitiesVulnerability.vulnerabilityExternalReference.externalReferenceExternalId,organizationEndpointVulnerabilitiesVulnerability.vulnerabilityId,organizationEndpointVulnerabilitiesProduct.productName,organizationEndpointVulnerabilitiesOperatingSystem.operatingSystemName,organizationEndpointVulnerabilitiesVersion.versionName,organizationEndpointVulnerabilitiesSubVersion.subVersionName,organizationEndpointVulnerabilitiesProductRawEntry.productRawEntryName,organizationEndpointVulnerabilitiesVulnerability.vulnerabilitySensitivityLevel.sensitivityLevelName,organizationEndpointVulnerabilitiesVulnerability.vulnerabilitySummary,organizationEndpointVulnerabilitiesEndpoint.endpointName,organizationEndpointVulnerabilitiesPatch.patchId,organizationEndpointVulnerabilitiesPatch.patchName,organizationEndpointVulnerabilitiesPatch.patchReleaseDate,organizationEndpointVulnerabilitiesCreatedAt,organizationEndpointVulnerabilitiesUpdatedAt,organizationEndpointVulnerabilitiesVulnerability.vulnerabilityV3ExploitabilityLevel,organizationEndpointVulnerabilitiesVulnerability.vulnerabilityV3BaseScore'
    }
    if (trycount < 2):
        try:
            print(f"[DEBUG] Making countEvents request for endpoint_hash: {endpointHash}")
            response = requests.get(urldashboard + '/vicarius-external-data-api/organizationEndpointVulnerabilities/search', params=params, headers=headers)
            
            # Debug response code
            print(f"[DEBUG] CountEvents request - Status code: {response.status_code}")
            
            if response.status_code == 429:
                print("API Rate Limit exceeded ... Waiting and Trying again")
                errors.append("API Rate Limit")
                time.sleep(60)
                trycount += 1
                getCountEventsPerAsset(apikey,urldashboard,endpointHash,trycount)
                
            jsonresponse = json.loads(response.text)
            
            # Print raw response for debugging
            print(f"[DEBUG] Raw response keys: {list(jsonresponse.keys())}")
        except Exception as e:
                print(f'something is wrong, will try again- EndpointHash: {endpointHash}, ')
                errors.append(f"Exception: {e}, EndpointHash: {endpointHash}")
                time.sleep(60)
                trycount += 1
                getCountEventsPerAsset(apikey,urldashboard,endpointHash,trycount)
    
    try:
        responsecount = int(jsonresponse['serverResponseCount'])
        print(f"[DEBUG] CountEvents response count: {responsecount}")
    except Exception as e:
        print(f"[ERROR] Failed to get serverResponseCount: {e}")
        responsecount = 0
        
    
    try: 
        return responsecount, jsonresponse, errors
    except Exception as e:
        errors.append(f"Return Exception: {e},")
        jsonresponse = {}
        return 0, jsonresponse, errors
 
def getEndpointVulnerabilities(apikey,urldashboard,fr0m,siz3,minDate,maxDate,endpointName,endpointHash):

    headers = {
        'Accept': 'application/json',
        'Vicarius-Token': apikey,
    }

    params = {
        'from': fr0m,
        'size': siz3,
        'q': 'organizationEndpointVulnerabilitiesEndpoint.endpointHash=in=('+endpointHash+')',
        'includeFields' : 'organizationEndpointVulnerabilitiesEndpoint.endpointId,organizationEndpointVulnerabilitiesEndpoint.endpointHash,organizationEndpointVulnerabilitiesVulnerability.vulnerabilityExternalReference.externalReferenceExternalId,organizationEndpointVulnerabilitiesVulnerability.vulnerabilityId,organizationEndpointVulnerabilitiesProduct.productName,organizationEndpointVulnerabilitiesOperatingSystem.operatingSystemName,organizationEndpointVulnerabilitiesVersion.versionName,organizationEndpointVulnerabilitiesSubVersion.subVersionName,organizationEndpointVulnerabilitiesProductRawEntry.productRawEntryName,organizationEndpointVulnerabilitiesVulnerability.vulnerabilitySensitivityLevel.sensitivityLevelName,organizationEndpointVulnerabilitiesVulnerability.vulnerabilitySummary,organizationEndpointVulnerabilitiesEndpoint.endpointName,organizationEndpointVulnerabilitiesPatch.patchId,organizationEndpointVulnerabilitiesPatch.patchName,organizationEndpointVulnerabilitiesPatch.patchReleaseDate,organizationEndpointVulnerabilitiesCreatedAt,organizationEndpointVulnerabilitiesUpdatedAt,organizationEndpointVulnerabilitiesVulnerability.vulnerabilityV3ExploitabilityLevel,organizationEndpointVulnerabilitiesVulnerability.vulnerabilityV3BaseScore',
        'sort': '-organizationEndpointVulnerabilitiesCreatedAt',
    }
    #jresponse = []
    try:
        time.sleep(0.5)
        response = requests.get(urldashboard + '/vicarius-external-data-api/organizationEndpointVulnerabilities/search', params=params, headers=headers)
        if response.status_code == 429:
            print("API Rate Limit exceeded ... Waiting and Trying again")
            time.sleep(60)
            getEndpointVulnerabilities(apikey,urldashboard,fr0m,siz3,minDate,maxDate,endpointName,endpointHash)
        jresponse = json.loads(response.text)
  
    except:
        print("something is wrong, will try again....")
        time.sleep(30)
        getEndpointVulnerabilities(apikey,urldashboard,fr0m,siz3,minDate,maxDate,endpointName,endpointHash)
    #if response.status_code == 429:
    #    print("API Rate Limit exceeded ... Waiting and Trying again")
    #    time.sleep(60)
    #    getEndpointVulnerabilities(apikey,urldashboard,fr0m,siz3,minDate,maxDate,endpointName,endpointHash)

    try: 
        return jresponse
    except:
        jresponse = {}
        return jresponse

def parseEndpointVulnerabilities(apikey,urldashboard,jresponse): #endpointGroups):
    
    vulns_list = []

    for i in jresponse['serverResponseObject']:
        cve = i['organizationEndpointVulnerabilitiesVulnerability']['vulnerabilityExternalReference']['externalReferenceExternalId']
        vulid = str(i['organizationEndpointVulnerabilitiesVulnerability']['vulnerabilityId'])
        link = "https://www.vicarius.io/vsociety/vulnerabilities/"+vulid+"/"+cve
        #'https://www.vicarius.io/research-center/vulnerability/'+ cve + '-id' + vulid
        
        typecve = ""

        try:
            productName = i['organizationEndpointVulnerabilitiesProduct']['productName']
            typecve = "App"
        except:
            productName = ""

        try:
            productName = i['organizationEndpointVulnerabilitiesOperatingSystem']['operatingSystemName']
            typecve = "SO"
        except:
            if (typecve != "App"):
                productName = ""

        try:
            version = i['organizationEndpointVulnerabilitiesVersion']['versionName']
        except:
            version = ""
        try:
            subVersion = i['organizationEndpointVulnerabilitiesSubVersion']['subVersionName']
        except:
            subVersion = productRawEntryName

        productRawEntryName = i['organizationEndpointVulnerabilitiesProductRawEntry']['productRawEntryName']
        sensitivityLevelName = i['organizationEndpointVulnerabilitiesVulnerability']['vulnerabilitySensitivityLevel']['sensitivityLevelName']
        
        vulnerabilitySummary = i['organizationEndpointVulnerabilitiesVulnerability']['vulnerabilitySummary'] 
        vulnerabilitySummary = str(vulnerabilitySummary).replace("\"","'")
        
        asset = i['organizationEndpointVulnerabilitiesEndpoint']['endpointName']
        endpointId = (i['organizationEndpointVulnerabilitiesEndpoint']['endpointId'])
        endpointHash = i['organizationEndpointVulnerabilitiesEndpoint']['endpointHash']

        if i['organizationEndpointVulnerabilitiesPatch']['patchId'] > 0:
            patchid = str(i['organizationEndpointVulnerabilitiesPatch']['patchId'])
            patchName = (i['organizationEndpointVulnerabilitiesPatch']['patchName'])
            try:
                patchReleaseDate = i['organizationEndpointVulnerabilitiesPatch']['patchReleaseDate']
            except:
                patchReleaseDate = 0
            #patchFileName = str(i['organizationEndpointVulnerabilitiesPatch']['patchFileName'])
        else:
            patchid = "0"
            patchName = "n\\a"
            patchReleaseDate = 0
            #patchFileName = "n\\a"

        try:
            createAttimemille = i['organizationEndpointVulnerabilitiesCreatedAt']
            createAt = utils.timestamptodatetime(createAttimemille)
            updateAt = i['organizationEndpointVulnerabilitiesUpdatedAt']
            updateAt = utils.timestamptodatetime(updateAt)
        except:
            createAt = ""
            updateAt = ""

        productName = productName.replace(',',"").replace(";","")
        productRawEntryName = productRawEntryName.replace(',',"").replace(";","")
        vulnerabilitySummary = vulnerabilitySummary.replace("\r","").replace("\n",">>")
        vulnerabilitySummary = vulnerabilitySummary.replace(",","").replace(";","")
        vulnerabilitySummary = vulnerabilitySummary.replace("'","")
        
        #threatLevelId = str(i['organizationEndpointVulnerabilitiesVulnerability']['vulnerabilitySensitivityLevel']['threatLevelId'])
        vulnerabilityV3ExploitabilityLevel = str(i['organizationEndpointVulnerabilitiesVulnerability']['vulnerabilityV3ExploitabilityLevel'])
        vulnerabilityV3BaseScore = str(i['organizationEndpointVulnerabilitiesVulnerability']['vulnerabilityV3BaseScore'])
    
        if patchReleaseDate < 1:
            patchReleaseDate = createAttimemille

        hpatchReleaseDate = safe_convert_to_datetime(patchReleaseDate)


        vulnerability_dict = {
            "endpointId" : endpointId,
            "asset": asset,
            "endpointHash": endpointHash,
            "productName": productName,
            "productRawEntryName": productRawEntryName,
            "sensitivityLevelName": sensitivityLevelName,
            "cve": cve,
            "vulid": vulid,
            "patchid": patchid,
            "patchName": patchName,
            "patchReleaseDate": patchReleaseDate,
            "patchReleaseDateTimeStamp": hpatchReleaseDate,
            "createAt": createAt,
            "updateAt": updateAt,
            "link": link,
            "vulnerabilitySummary": vulnerabilitySummary,
            "vulnerabilityV3BaseScore": vulnerabilityV3BaseScore,
            "vulnerabilityV3ExploitabilityLevel": vulnerabilityV3ExploitabilityLevel,
            "typecve": typecve,
            "version": version,
            "subversion": subVersion
        }

        vulns_list.append(vulnerability_dict)


    return vulns_list 
    
def get_vulnerability_ids_by_endpoint(apikey, urldashboard, endpoint_hash, from_offset=0, size=100):
    """Get vulnerability IDs for an endpoint using the aggregation endpoint"""
    headers = {
        'Accept': 'application/json',
        'Vicarius-Token': apikey,
    }
    
    # Use the original non-encoded format (same as getEndpointVulnerabilities)
    params = {
        'from': from_offset,
        'size': size,
        'objectName': 'OrganizationEndpointVulnerabilities',
        'group': 'vulnerabilityId',
        'includeOriginalDoc': 'false',
        'q': f'organizationEndpointVulnerabilitiesEndpoint.endpointHash=in=({endpoint_hash})',
        'assetCount': 'true',
        'sort': 'aggregationId',
        'sumLastSubAggregationBuckets': '1'
    }
    
    try:
        print(f"[DEBUG] Making vuln IDs request for endpoint_hash: {endpoint_hash}, from: {from_offset}, size: {size}")
        response = requests.get(f'{urldashboard}/vicarius-external-data-api/aggregation/searchGroup', 
                              params=params, headers=headers)
        
        # Debug response code
        print(f"[DEBUG] Vulnerability IDs request - Status code: {response.status_code}")
        
        if response.status_code == 429:
            print("API Rate Limit exceeded... Waiting and trying again")
            time.sleep(60)
            return get_vulnerability_ids_by_endpoint(apikey, urldashboard, endpoint_hash, from_offset, size)
        
        json_response = json.loads(response.text)
        
        # Debug server response count
        server_response_count = json_response.get('serverResponseCount', 'N/A')
        response_obj_count = len(json_response.get('serverResponseObject', []))
        print(f"[DEBUG] Vulnerability IDs response count: {server_response_count}, objects in this page: {response_obj_count}")
        
        return json_response
    except Exception as e:
        print(f"Error fetching vulnerability IDs: {e}")
        time.sleep(30)
        return get_vulnerability_ids_by_endpoint(apikey, urldashboard, endpoint_hash, from_offset, size)

def get_vulnerability_details_by_ids(apikey, urldashboard, vuln_ids, endpoint_hash, from_offset=0, size=100):
    """Get detailed vulnerability information for a batch of vulnerability IDs"""
    headers = {
        'Accept': 'application/json',
        'Vicarius-Token': apikey,
    }
    
    # Convert list of IDs to comma-separated string (without URL encoding)
    vuln_ids_str = ','.join(map(str, vuln_ids))
    
    # Use the original non-encoded format
    params = {
        'from': from_offset,
        'size': size,
        'objectName': 'OrganizationEndpointVulnerabilities',
        'group': 'vulnerabilityId;endpointId',
        'includeOriginalDoc': 'true',
        'q': f'vulnerabilityId=in=({vuln_ids_str});organizationEndpointVulnerabilitiesEndpoint.endpointHash=in=({endpoint_hash})',
        'sort': 'aggregationId',
        'sumLastSubAggregationBuckets': '1'
    }
    
    try:
        print(f"[DEBUG] Making vuln details request for {len(vuln_ids)} IDs, endpoint_hash: {endpoint_hash}")
        response = requests.get(f'{urldashboard}/vicarius-external-data-api/aggregation/searchGroup', 
                              params=params, headers=headers)
                              
        # Debug response code
        print(f"[DEBUG] Vulnerability details request - Status code: {response.status_code}")
        
        if response.status_code == 429:
            print("API Rate Limit exceeded... Waiting and trying again")
            time.sleep(60)
            return get_vulnerability_details_by_ids(apikey, urldashboard, vuln_ids, endpoint_hash, from_offset, size)
        
        json_response = json.loads(response.text)
        
        # Debug server response count and objects
        server_response_count = json_response.get('serverResponseCount', 'N/A')
        server_response_objects = len(json_response.get('serverResponseObject', []))
        print(f"[DEBUG] Vulnerability details response count: {server_response_count}, Objects returned: {server_response_objects}")
        
        return json_response
    except Exception as e:
        print(f"Error fetching vulnerability details: {e}")
        time.sleep(30)
        return get_vulnerability_details_by_ids(apikey, urldashboard, vuln_ids, endpoint_hash, from_offset, size)

def parse_vulnerability_details(response):
    """Parse the vulnerability details from aggregation API response"""
    vulns_list = []
    
    for vuln_obj in response['serverResponseObject']:
        model_abs = vuln_obj.get('aggregationModelAbs', {})
        
        # Extract data similar to original parseEndpointVulnerabilities
        endpoint_data = model_abs.get('organizationEndpointVulnerabilitiesEndpoint', {})
        vulnerability_data = model_abs.get('organizationEndpointVulnerabilitiesVulnerability', {})
        product_data = model_abs.get('organizationEndpointVulnerabilitiesProduct', {})
        patch_data = model_abs.get('organizationEndpointVulnerabilitiesPatch', {})
        product_raw_entry = model_abs.get('organizationEndpointVulnerabilitiesProductRawEntry', {})
        version_data = model_abs.get('organizationEndpointVulnerabilitiesVersion', {})
        subversion_data = model_abs.get('organizationEndpointVulnerabilitiesSubVersion', {})
        
        # Extract external reference (CVE)
        external_ref = vulnerability_data.get('vulnerabilityExternalReference', {})
        cve = external_ref.get('externalReferenceExternalId', '')
        
        # Generate link
        vulid = str(vulnerability_data.get('vulnerabilityId', ''))
        link = f"https://www.vicarius.io/vsociety/vulnerabilities/{vulid}/{cve}" if vulid and cve else ""
        
        # Determine CVE type
        typecve = "App" if product_data.get('productName') else ""
        
        # Extract timestamps
        created_at = model_abs.get('organizationEndpointVulnerabilitiesCreatedAt', 0)
        updated_at = model_abs.get('organizationEndpointVulnerabilitiesUpdatedAt', 0)
        created_at_formatted = utils.timestamptodatetime(created_at) if created_at else ""
        updated_at_formatted = utils.timestamptodatetime(updated_at) if updated_at else ""
        
        # Extract patch data
        patch_id = patch_data.get('patchId', 0)
        patch_name = patch_data.get('patchName', 'n\\a')
        patch_release_date = patch_data.get('patchCreatedAt', 0)
        if patch_release_date < 1:
            patch_release_date = created_at
        
        # Format patch release date
        h_patch_release_date = safe_convert_to_datetime(patch_release_date)
        
        # Clean text fields
        product_name = product_data.get('productName', '').replace(',', '').replace(';', '')
        product_raw_entry_name = product_raw_entry.get('productRawEntryName', '').replace(',', '').replace(';', '')
        vulnerability_summary = vulnerability_data.get('vulnerabilitySummary', '')
        vulnerability_summary = str(vulnerability_summary).replace("\r", "").replace("\n", ">>")
        vulnerability_summary = vulnerability_summary.replace(",", "").replace(";", "").replace("'", "")
        
        # Create vulnerability dictionary
        vulnerability_dict = {
            "endpointId": endpoint_data.get('endpointId', ''),
            "asset": endpoint_data.get('endpointName', ''),
            "endpointHash": endpoint_data.get('endpointHash', ''),
            "productName": product_name,
            "productRawEntryName": product_raw_entry_name,
            "sensitivityLevelName": vulnerability_data.get('vulnerabilitySensitivityLevel', {}).get('sensitivityLevelName', ''),
            "cve": cve,
            "vulid": vulid,
            "patchid": str(patch_id),
            "patchName": patch_name,
            "patchReleaseDate": patch_release_date,
            "patchReleaseDateTimeStamp": h_patch_release_date,
            "createAt": created_at_formatted,
            "updateAt": updated_at_formatted,
            "link": link,
            "vulnerabilitySummary": vulnerability_summary,
            "vulnerabilityV3BaseScore": str(vulnerability_data.get('vulnerabilityV3BaseScore', '')),
            "vulnerabilityV3ExploitabilityLevel": str(vulnerability_data.get('vulnerabilityV3ExploitabilityLevel', '')),
            "typecve": typecve,
            "version": version_data.get('versionName', ''),
            "subversion": subversion_data.get('subVersionName', '')
        }
        
        vulns_list.append(vulnerability_dict)
    
    return vulns_list

def get_all_endpoint_vulnerabilities_optimized(apikey, urldashboard, endpoint_name, endpoint_hash):
    """Get all vulnerabilities for an endpoint using the optimized aggregation API approach"""
    all_vulns = []
    from_offset = 0
    size = 100  # Max size for aggregation API
    
    # First: Get all vulnerability IDs for this endpoint
    all_vuln_ids = []
    total_vulns = None
    
    print(f"[DEBUG] Starting vulnerability fetch for {endpoint_name} ({endpoint_hash})")
    
    while total_vulns is None or from_offset < total_vulns:
        # Get batch of vulnerability IDs
        vuln_ids_response = get_vulnerability_ids_by_endpoint(
            apikey, urldashboard, endpoint_hash, from_offset, size)
        
        if not vuln_ids_response or 'serverResponseObject' not in vuln_ids_response:
            print(f"[ERROR] Error fetching vulnerability IDs for {endpoint_name}")
            break
        
        # Set total count if first batch
        if total_vulns is None:
            total_vulns = vuln_ids_response.get('serverResponseCount', 0)
            print(f"Found {total_vulns} vulnerabilities for {endpoint_name}")
        
        # Extract vulnerability IDs from response
        batch_ids = [item.get('aggregationId') for item in vuln_ids_response.get('serverResponseObject', [])]
        print(f"[DEBUG] Batch retrieved {len(batch_ids)} IDs, offset: {from_offset}")
        all_vuln_ids.extend(batch_ids)
        
        # Move to next batch
        from_offset += size
        
        # Apply rate limiting
        time.sleep(1)
    
    print(f"[DEBUG] Retrieved {len(all_vuln_ids)} vulnerability IDs for {endpoint_name} (Expected: {total_vulns})")
    
    # Print first few IDs for debugging
    if all_vuln_ids:
        id_sample = all_vuln_ids[:min(5, len(all_vuln_ids))]
        print(f"[DEBUG] Sample IDs: {id_sample}")
    
    # Second: Get vulnerability details in batches
    for i in range(0, len(all_vuln_ids), size):
        batch_ids = all_vuln_ids[i:i+size]
        
        # Get details for this batch
        details_response = get_vulnerability_details_by_ids(
            apikey, urldashboard, batch_ids, endpoint_hash)
        
        if not details_response or 'serverResponseObject' not in details_response:
            print(f"[ERROR] Error fetching details for batch {i//size + 1}")
            continue
        
        # Parse vulnerability details
        batch_vulns = parse_vulnerability_details(details_response)
        print(f"[DEBUG] Batch {i//size + 1}: Parsed {len(batch_vulns)} vulnerabilities")
        all_vulns.extend(batch_vulns)
        
        # Apply rate limiting
        time.sleep(1)
    
    print(f"[DEBUG] Processed {len(all_vulns)} vulnerabilities for {endpoint_name}")
    return all_vulns
    
def debug_vulnerability_queries(apikey, urldashboard, endpoint_hash, from_offset=0, size=100):
    """Debug function that shows query details without executing API calls"""
    print("\n===== QUERY DEBUG INFO =====")
    
    # Original query from getEndpointVulnerabilities
    original_endpoint = f"{urldashboard}/vicarius-external-data-api/organizationEndpointVulnerabilities/search"
    original_query = f"organizationEndpointVulnerabilitiesEndpoint.endpointHash=in=({endpoint_hash})"
    
    # New query from get_vulnerability_ids_by_endpoint (UPDATED to use non-URL encoding)
    new_endpoint = f"{urldashboard}/vicarius-external-data-api/aggregation/searchGroup"
    new_query = f"organizationEndpointVulnerabilitiesEndpoint.endpointHash=in=({endpoint_hash})" # Now matches original
    
    # Convert to full URLs for comparison
    import urllib.parse
    
    original_params = {
        'from': from_offset,
        'size': size,
        'q': original_query,
        # Other params omitted for brevity
    }
    
    new_params = {
        'from': from_offset,
        'size': size,
        'objectName': 'OrganizationEndpointVulnerabilities',
        'group': 'vulnerabilityId',
        'includeOriginalDoc': 'false',
        'q': new_query,
        'assetCount': 'true',
        'sort': 'aggregationId',
        'sumLastSubAggregationBuckets': '1'
    }
    
    # Build query strings
    original_qs = urllib.parse.urlencode(original_params)
    new_qs = urllib.parse.urlencode(new_params)
    
    # How the request library will encode it
    print("COMPARISON OF QUERY ENCODINGS:")
    print(f"1. Original raw query: {original_query}")
    print(f"2. New raw query: {new_query}")
    print(f"3. After urllib.parse.urlencode: {original_qs}")
    print(f"4. How requests will encode it: {requests.utils.requote_uri(f'?q={original_query}')}")
    
    print("\nORIGINAL QUERY (getEndpointVulnerabilities):")
    print(f"Endpoint: {original_endpoint}")
    print(f"Raw Query: {original_query}")
    
    print("\nNEW QUERY (get_vulnerability_ids_by_endpoint) - UPDATED TO USE NON-URL ENCODING:")
    print(f"Endpoint: {new_endpoint}")
    print(f"Raw Query: {new_query}")
    
    print("\nIMPORTANT NOTE:")
    print("We are now using the same non-URL-encoded format for both methods.")
    print("The requests library will handle the URL encoding properly when sending the request.")
    print("If this still fails, we'll need to try other variations or investigate the API schema.")
    
    print("\n===== END DEBUG INFO =====")
    
    return {
        "original": {
            "endpoint": original_endpoint,
            "query": original_query,
            "params": original_params
        },
        "new": {
            "endpoint": new_endpoint,
            "query": new_query,
            "params": new_params
        }
    }
    