#!/usr/bin/python3

## Create Service-Now incident from Zabbix
## Copyright (C) 2001-2015 Jan Garaj - www.jangaraj.com
## Doc: http://wiki.servicenow.com/index.php?title=Python_Web_Services_Client_Examples
## WSDL doc: https://<your_instance>.service-now.com/incident.do?WSDL
##
'''
debug     = 0                 # 0/1 - enable/disable debug outputs
instance  = 'ateatest.service-now.com'   #
username  = 'stefan.olaf.larsen@atea.dk'          # Service-Now login
password  = 'Jrv2r4nxh!'        # base64 encrypted Service-Now password, don't use plaintext passwords
interface = 'incident.do'     #
agroup    = 'https://ateatest.service-now.com/sys_user_group.do?sys_id=a894b85ddb0b98d41fed199f2996195e&sysparm_view=' # Assignment group (DK-AOS-OC) 
category  = 'bd0ef4cddb8550d0dbdd9e85f3961980'  # Category of incident##
'''
'''
import sys
if len(sys.argv) < 3:
    print("""
Incorrect usage of Create Service-Now incident from Zabbix script
Example:
   zabbix-create-service-now-incident.py <to> <subject> <message>
   zabbix-create-service-now-incident.py "Jan Garaj" "PROBLEM" "
Trigger: Zabbix Server is down
Trigger description: Zabbix Server is down, please check it immediately
Trigger severity: Hight
Trigger nseverity: 4
Trigger status: Problem
Trigger URL:
Host: zabserver01
Host description: Main Zabbix Server
Event age: 10s
Current Zabbix time: 2015.06.19 21:23:12
Item values:
1. {ITEM.NAME1} ({HOST.NAME1}:{ITEM.KEY1}): {ITEM.VALUE1}
2. {ITEM.NAME2} ({HOST.NAME2}:{ITEM.KEY2}): {ITEM.VALUE2}
3. {ITEM.NAME3} ({HOST.NAME3}:{ITEM.KEY3}): {ITEM.VALUE3}
Zabbix event ID: 12345
Zabbix web UI: https://zabbix.domain.com/zabbix
   "
   """)'''
 #   sys.exit(1)

# command line arguments
# subject - {TRIGGER.STATUS} - PROBLEM or OK
#subject = sys.argv[2]
# message - whatever message the Zabbix action sends, preferably something like "Zabbix server is unreachable for 5 minutes"
# recommended setting:
'''
Trigger: {TRIGGER.NAME}
Trigger description: {TRIGGER.DESCRIPTION}
Trigger severity: {TRIGGER.SEVERITY}
Trigger nseverity: {TRIGGER.NSEVERITY}
Trigger status: {TRIGGER.STATUS}
Trigger URL: {TRIGGER.URL}
Host: {HOST.HOST}
Host description: {HOST.DESCRIPTION}
Event age: {EVENT.AGE}
Current Zabbix time: {DATE} {TIME}
Item values:
1. {ITEM.NAME1} ({HOST.NAME1}:{ITEM.KEY1}): {ITEM.VALUE1}
2. {ITEM.NAME2} ({HOST.NAME2}:{ITEM.KEY2}): {ITEM.VALUE2}
3. {ITEM.NAME3} ({HOST.NAME3}:{ITEM.KEY3}): {ITEM.VALUE3}
Zabbix event ID: {EVENT.ID}
Zabbix web UI: https://zabbix.domain.com/zabbix

message = sys.argv[3]
# value mapping
zabbix2servicenow = {
    # parse from Zabbix message, remap value if map exists
    'dynamic': {
        "impact": "^Trigger nseverity: .*",
        'urgency': '^Trigger nseverity: .*',
        'priority': '^Trigger nseverity: .*',
        'configuration_item': '^Host: .*',
        'short_description': '^Trigger: .*',
        'zabbix_event_id': '^Zabbix event ID: .*',
    },
    # maps Zabbix value -> Service Now value
    'maps': {
        'impact': {
            # ServiceNow: 1 - High, 2 - Medium, 3 - Low
            # Zabbix:     0 - Not classified, 1 - Information, 2 - Warning, 3 - Average, 4 - High, 5  - Disaster
            '0': 'Low',
            '1': 'Low',
            '2': 'Medium',
            '3': 'Medium',
            '4': 'High',
            '5': 'High',
        },
        'urgency': {
            # ServiceNow: 1 - Immediate, 2 - Prompt, 3 - Non-urgent
            # Zabbix:     0 - Not classified, 1 - Information, 2 - Warning, 3 - Average, 4 - High, 5  - Disaster
            '0': 'Non-urgent',
            '1': 'Non-urgent',
            '2': 'Prompt',
            '3': 'Prompt',
            '4': 'Immediate',
            '5': 'Immediate',
        }
    },
    # static
    'static': {
        'category': category,
        'caller': username,
        'assignment_group': agroup,
        'additional_comments': message,
    }
}

import re, sys, base64
incident = zabbix2servicenow['static']
for key in zabbix2servicenow['dynamic']:
    items=re.findall(zabbix2servicenow['dynamic'][key], message, re.MULTILINE)
    if len(items) != 1:
        if debug:
            print('Problem with "%s" matching, found %i times' % (zabbix2servicenow['dynamic'][key], len(items)))
        incident[key] = 'Problem with "%s" matching, found %i times' % (zabbix2servicenow['dynamic'][key], len(items))
        continue
    else:
        items[0] = items[0].split(':')[1].strip()
        if key in zabbix2servicenow['maps']:
            if items[0] not in zabbix2servicenow['maps'][key]:
                if debug:
                    print "Problem with mapping of value %s" % str(items[0])
                incident[key] = "Problem with mapping of value %s" % str(items[0])
            else:
                incident[key] = zabbix2servicenow['maps'][key][items[0]]
        else:
            incident[key] = items[0]

# add host name to short description
incident['short_description'] = incident['configuration_item'] + ": " + incident['short_description']
'''
import requests
import json

def createincident():
    url = "https://ateatest.service-now.com/api/now/table/incident"

    payload = json.dumps({
        "company": "7f037de3b1d03100ed6d92aa7b025705",
        "category": "bd0ef4cddb8550d0dbdd9e85f3961980",
        "caller_id": "stefan.olaf.larsen@atea.dk",
        "assignment_group": "a894b85ddb0b98d41fed199f2996195e",
        "description": "test",
        "impact": 1,
        "urgency": 2,
        "u_ticket_type": "incident",
        "short_description": "short description"
    })
    headers = {
    'Content-Type': 'application/json',
    'Authorization': 'Basic c3RlZmFuLm9sYWYubGFyc2VuQGF0ZWEuZGs6SnJ2MnI0bnhoIQ==',
    'Cookie': 'BIGipServerpool_ateatest=f6e30673ea606d552a8dd47a0c6208ac; JSESSIONID=660BA618EAA10AA00E25FA102B8393C3; glide_session_store=841733A21BB319D825F7A68EE54BCB34; glide_user_route=glide.161798e0b202308f23b8fedb6c97c135'
    }

    response = requests.request("POST", url, headers=headers, data=payload)
    return response

response     = createincident()
responseJSON = response.json()
sys_id       = responseJSON['result']['sys_id']
print(sys_id)


  