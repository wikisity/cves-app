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
    
    integrityImpact = event['queryStringParameters']['integrityImpact']
    attackVector =  event['queryStringParameters']['attackVector']
    items = scan_cves_By_integrityImpact_and_attackVector(integrityImpact, attackVector)
    
    if items == None:
        response['body'] = 'Items not in database'
        return response
        
    if len(items) > 1:
        response['body'] = json.dumps((items[0], items[1]))
        return response
    
    response['body'] = json.dumps(items)
    return response


'''
Input: IntegrityImpact, AttackVector
output: return 2 CVEs with integrity impact equaled to IntegrityImpact and attack vector equaled to AttackVector
        if length API response < 2 then return items found 
'''
def scan_cves_By_integrityImpact_and_attackVector(integrityImpact, attackVector):
    
    ddb = boto3.resource('dynamodb')
    tb =  ddb.Table('cvesData')
    
    response = tb.scan(
        FilterExpression=Attr('IntegrityImpact').eq(integrityImpact) & Attr('AttackVector').eq(attackVector)
        )
    
    if response == False: # item not in database
        return None
    if len(response['Items']) > 1:
        return response['Items'][0:2]
    
    return response['Items']  # found items
    
    
    
    
        
