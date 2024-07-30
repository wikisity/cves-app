import json, os, requests
from datetime import datetime

'''
In: provide a severity in UPPER case value.
Out: Query the NVD and return 2 CVES if they exist. CVEs are return with some filtered attributes from the API response
'''
def filter_cves_with_severity(severity):
    url = f'https://services.nvd.nist.gov/rest/json/cves/2.0?cvssV3Severity={severity}'
    
    severity_list = ['HIGH', 'LOW', 'MEDIUM', 'CRITICAL']
    try:
        if severity not in severity_list:
            return f"Error. {severity} is not a valid severity value."
        
        response = requests.get(url)
    except requests.RequestException as e:
        print(f"An error occurred: {e}")

    parsed = json.loads(json.dumps(response.json()))
    count = 0
    filtered_cves = []
    for cve in parsed['vulnerabilities']:
        if count == 2:
            break
        id = cve['cve']['id']
        published = cve['cve']['published']
        description = cve['cve']['descriptions'][0]['value']
        keys = list(cve['cve']['metrics'].keys())
        if 'cvssMetricV31' in keys:
            attackVector = cve['cve']['metrics']['cvssMetricV31'][0]['cvssData']['attackVector']
            attackComplexity = cve['cve']['metrics']['cvssMetricV31'][0]['cvssData']['attackComplexity']
            baseSeverity = cve['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity']
            if baseSeverity == severity:
                filtered_cves.append({"id":id, "published":published, "description":description,
                                "attackVector":attackVector, "attackComplexity":attackComplexity,
                                "baseSeverity":baseSeverity})
                count += 1

        elif 'cvssMetricV30' in keys:
            attackVector = cve['cve']['metrics']['cvssMetricV30'][0]['cvssData']['attackVector']
            attackComplexity = cve['cve']['metrics']['cvssMetricV30'][0]['cvssData']['attackComplexity']
            baseSeverity = cve['cve']['metrics']['cvssMetricV30'][0]['cvssData']['baseSeverity']
            if baseSeverity == severity:
                filtered_cves.append({"id":id, "published":published, "description":description,
                                "attackVector":attackVector, "attackComplexity":attackComplexity,
                                "baseSeverity":baseSeverity})
                count += 1

    return filtered_cves
    


'''
In: Provide a start and end dates in human readable format. Start Date parameter should be smaller than End Date parameter.
Out: Query the NVD and return 2 CVEs published between the start and end dates
'''
def filter_cves_published_between(date1, date2):
    url = 'https://services.nvd.nist.gov/rest/json/cves/2.0/?'

    date1_isoformat = convert_date_to_isoformat(date1)
    date2_isoformat = convert_date_to_isoformat(date2)

    try:
        dt1 = datetime.strptime(date1, "%m %d, %Y")
        dt2 = datetime.strptime(date2, "%m %d, %Y")
        if (dt1 - dt2).days > 0:
            return f"{date1} should be your End date and {date2} your Start date parameters."
        else:
            difference = (dt2 - dt1).days

        if difference > 120:
            # Calculate the difference in days. difference should be <= 120 days as per API doc
            # https://nvd.nist.gov/developers/vulnerabilities#cves-noRejected
            return 'Incorrect dates range. The Max allowable date range parameters is 120 consecutive days.'
        
        response = requests.get(f"{url}pubStartDate={date1_isoformat}&pubEndDate={date2_isoformat}")
        
    except requests.RequestException as e:
        print(f"An error occurred: {e}")

    parsed = json.loads(json.dumps(response.json()))
    count = 0
    filtered_cves = []
    for cve in parsed['vulnerabilities']:
        if count == 2:
            break
        id = cve['cve']['id']
        published = cve['cve']['published']
        description = cve['cve']['descriptions'][0]['value']
        keys = list(cve['cve']['metrics'].keys())
        if 'cvssMetricV31' in keys:
            attackVector = cve['cve']['metrics']['cvssMetricV31'][0]['cvssData']['attackVector']
            attackComplexity = cve['cve']['metrics']['cvssMetricV31'][0]['cvssData']['attackComplexity']
            filtered_cves.append({"id":id, "published":published, "description":description,
                              "attackVector":attackVector, "attackComplexity":attackComplexity})
            count += 1
        elif 'cvssMetricV30' in keys:
            attackVector = cve['cve']['metrics']['cvssMetricV30'][0]['cvssData']['attackVector']
            attackComplexity = cve['cve']['metrics']['cvssMetricV30'][0]['cvssData']['attackComplexity']
            filtered_cves.append({"id":id, "published":published, "description":description,
                              "attackVector":attackVector, "attackComplexity":attackComplexity})
            count += 1

    return filtered_cves


'''
In: provide a start, end dates, and a severity. Severity is in UPPER case value
Out: Query the NVD and return a CVE published between the start and end dates for that severity
'''
def multi_filtering(date1, date2, severity):
    url = 'https://services.nvd.nist.gov/rest/json/cves/2.0/?'

    severity_list = ['HIGH', 'LOW', 'MEDIUM', 'CRITICAL']

    date1_isoformat = convert_date_to_isoformat(date1)
    date2_isoformat = convert_date_to_isoformat(date2)

    try:
        dt1 = datetime.strptime(date1, "%m %d, %Y")
        dt2 = datetime.strptime(date2, "%m %d, %Y")
        if (dt1 - dt2).days > 0:
            return f"{date1} should be your End date and {date2} your Start date parameters."
        else:
            difference = (dt2 - dt1).days

        if difference > 120:
            # Calculate the difference in days. difference should be <= 120 days as per API doc
            # https://nvd.nist.gov/developers/vulnerabilities#cves-noRejected
            return 'Incorrect dates range. The Max allowable date range parameters is 120 consecutive days.'
        
        if severity not in severity_list:
            return f"Error. {severity} is not a valid severity value."

        response = requests.get(f"{url}pubStartDate={date1_isoformat}&pubEndDate={date2_isoformat}")

    except requests.RequestException as e:
        print(f"An error occurred: {e}")

    parsed = json.loads(json.dumps(response.json()))
    filtered_cve = []
    for cve in parsed['vulnerabilities']:
        id = cve['cve']['id']
        published = cve['cve']['published']
        description = cve['cve']['descriptions'][0]['value']
        keys = list(cve['cve']['metrics'].keys())
        if 'cvssMetricV31' in keys:
            attackVector = cve['cve']['metrics']['cvssMetricV31'][0]['cvssData']['attackVector']
            attackComplexity = cve['cve']['metrics']['cvssMetricV31'][0]['cvssData']['attackComplexity']
            baseSeverity = cve['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity']
            if baseSeverity == severity:
                filtered_cve.append({"id":id, "published":published, "description":description,
                                "attackVector":attackVector, "attackComplexity":attackComplexity,
                                "baseSeverity":baseSeverity})
                break

        elif 'cvssMetricV30' in keys:
            attackVector = cve['cve']['metrics']['cvssMetricV30'][0]['cvssData']['attackVector']
            attackComplexity = cve['cve']['metrics']['cvssMetricV30'][0]['cvssData']['attackComplexity']
            baseSeverity = cve['cve']['metrics']['cvssMetricV30'][0]['cvssData']['baseSeverity']
            if baseSeverity == severity:
                filtered_cve.append({"id":id, "published":published, "description":description,
                                "attackVector":attackVector, "attackComplexity":attackComplexity,
                                "baseSeverity":baseSeverity})
                break

    return filtered_cve

'''
In: date in "mm d, yyyy" format
Out: return date in ISO 8601 format
'''
def convert_date_to_isoformat(date_str):
    # Example date in "mm d, yyyy" format
    # date_str = "06 1, 2024"
    date_format = "%m %d, %Y"
    try:
        date_obj = datetime.strptime(date_str, date_format) # Parse the date
        iso_date = date_obj.isoformat()  # Convert to ISO 8601 format
    except ValueError:
        print(f"Is the date '{date_str}' in the format {date_format} ?")
    
    return iso_date



def main():
    #print(convert_date_to_isoformat('06 1, 2024'))
    #print(filter_cves_with_severity('MEDIUM'))
    #print(filter_cves_with_severity('HIGH'))
    #print(filter_cves_with_severity('CRITICAL'))
    #print(filter_cves_with_severity('LOW'))
    print(filter_cves_published_between("01 1, 2024", "03 1, 2024"))
    #print(filter_cves_published_between("05 1, 2024", "01 1, 2024"))
    #print(multi_filtering("01 1, 2024", "03 1, 2024", 'high'))

main()