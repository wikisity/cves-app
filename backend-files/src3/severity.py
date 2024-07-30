import boto3, json
from boto3.dynamodb.conditions import Key, Attr


def handler(event, context):
    
    response = {
        "statusCode": 200,
        "headers": {
            'Content-Type': 'application/json'
        },
        "body": '',
        "isBase64Encoded": "False"
    }
    
    print(event)
    print()
    
    severity = event['queryStringParameters']['severity']
    items = scan_cves_By_severity(severity)
    
    if items == None:
        response['body'] = 'Items not in database'
        return response
        
    if len(items) > 1:
        response['body'] = json.dumps((items[0], items[1]))
        return response
    
    response['body'] = json.dumps(items)
    return response


'''
Input: a SEVERITY
output: return 2 CVEs with severity equaled to SEVERITY
        if length API response < 2 then return items found
'''
def scan_cves_By_severity(severity):
    
    severity_list = ['HIGH', 'LOW', 'MEDIUM', 'CRITICAL']
    if severity not in severity_list:
        return None
        
    ddb = boto3.resource('dynamodb')
    tb =  ddb.Table('cvesData')
    response = tb.scan(
        FilterExpression=Attr('baseSeverity').eq(severity)
        )
        
    if response == False: # item not in database
        return None
    if len(response['Items']) > 1:
        return response['Items'][0:2]
    
    return response['Items']  # found items