import boto3, json
from boto3.dynamodb.conditions import Key


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
    
    idf = event['queryStringParameters']['Id']
    items = query_cve_By_Id(idf)
    
    if items == None:
        response['body'] = 'Items not in database'
        return response
        
    if len(items) > 1:
        response['body'] = json.dumps((items[0], items[1]))
        return response
    
    response['body'] = json.dumps(items)
    return response
    
    

'''
Input: CVE ID
output: return CVE with id EQUALED ID
'''
def query_cve_By_Id(idf):
    
    ddb = boto3.resource('dynamodb')
    tb = ddb.Table('cvesData')
    response = tb.query(
        KeyConditionExpression=Key('Id').eq(idf)
        )
        
    if response == False: # item not in database
        return None
    if len(response['Items']) > 1:
        return response['Items'][0:2]
    
    return response['Items']  # found items
    


    









