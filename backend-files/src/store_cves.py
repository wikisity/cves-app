import json, os, time
import requests, boto3


def handler(event, context):
    
    if not table_exists():
        create_cvesData_table()
    
    cves = filter_cves_with_severity('MEDIUM')
    load_cves(cves)
    time.sleep(3)

    cves = filter_cves_with_severity('HIGH')
    load_cves(cves)
    time.sleep(3)

    cves = filter_cves_with_severity('CRITICAL')
    load_cves(cves)
    time.sleep(3)

    cves = filter_cves_with_severity('LOW')
    load_cves(cves)
    
    
   
    

def table_exists():
    # Instantiate your dynamo client object
    client = boto3.client('dynamodb')
    # Get an array of table names associated with the current account and endpoint.
    response = client.list_tables()
    if 'cvesData' in response['TableNames']:
        table_found = True
    else:
        table_found = False
        
    return table_found
    
    
    
def create_cvesData_table():
    # Get the service resource.
    ddb = boto3.resource('dynamodb')
    # Create the DynamoDB table called cvesData
    table_name = 'cvesData'
    table = ddb.create_table(
        TableName=table_name,
        KeySchema=[
            {
                'AttributeName': 'Id',
                'KeyType': 'HASH' # Partition key
            }
        ],
        AttributeDefinitions=[
            {
                'AttributeName': 'Id',
                'AttributeType': 'S'
            }    
        ],
        ProvisionedThroughput={
            'ReadCapacityUnits': 10,
            'WriteCapacityUnits': 10
        }
    )
    
    # Wait until the table exists.
    table.meta.client.get_waiter('table_exists').wait(TableName=table_name)
    return table


'''
Input: list of cves
'''   
def load_cves(cves):
    
    # Get the service resource.
    ddb = boto3.resource('dynamodb')
    tb = ddb.Table('cvesData')
    for cve in cves:
        print()
        print(cve)
        tb.put_item(Item=cve)
    
    

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
                filtered_cves.append({"Id":id, "published":published, "description":description,
                                "attackVector":attackVector, "attackComplexity":attackComplexity,
                                "baseSeverity":baseSeverity})
                count += 1

        elif 'cvssMetricV30' in keys:
            attackVector = cve['cve']['metrics']['cvssMetricV30'][0]['cvssData']['attackVector']
            attackComplexity = cve['cve']['metrics']['cvssMetricV30'][0]['cvssData']['attackComplexity']
            baseSeverity = cve['cve']['metrics']['cvssMetricV30'][0]['cvssData']['baseSeverity']
            if baseSeverity == severity:
                filtered_cves.append({"Id":id, "published":published, "description":description,
                                "attackVector":attackVector, "attackComplexity":attackComplexity,
                                "baseSeverity":baseSeverity})
                count += 1

    return filtered_cves


    
#handler({'key1': 'value1', "key2": 'value2'},"")

