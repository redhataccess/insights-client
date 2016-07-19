'''
Module for fetching and displaying Insights maintenance plans
'''
import json
import textwrap
from connection import InsightsConnection
from client_config import InsightsClient
from utilities import generate_machine_id

planstr = '''
[
    {
        "overdue": false,
        "maintenance_id": 59,
        "name": "",
        "start": "2016-04-01T02:00:00.000Z",
        "end": "2016-04-01T03:00:00.000Z",
        "created_by": "rhn-support-jkinlaw",
        "silenced": false,
        "actions": [
            {
                "done": true,
                "id": 39,
                "maintenance_id": 59,
                "system": {
                    "system_id": "9b3fee48ce0f441a90dd1b31c4dedb71",
                    "display_name": null,
                    "hostname": "jaguatirica",
                    "last_check_in": "2016-04-11T06:39:46.000Z"
                },
                "rule": {
                    "id": "machine_check_exception|MACHINE_CHECK_EXCEPTION",
                    "description": "MCE kernel panic",
                    "severity": "ERROR",
                    "category": "Stability"
                },
                "current_report": null
            },
            {
                "done": true,
                "id": 49,
                "maintenance_id": 59,
                "system": {
                    "system_id": "39bbfe0c-3937-41d7-b2f3-bf85394d4b08",
                    "display_name": null,
                    "hostname": "mhuth-laptop",
                    "last_check_in": "2016-04-12T17:35:18.000Z"
                },
                "rule": {
                    "id": "machine_check_exception|MACHINE_CHECK_EXCEPTION",
                    "description": "MCE kernel panic",
                    "severity": "ERROR",
                    "category": "Stability"
                },
                "current_report": null
            },
            {
                "done": false,
                "id": 125,
                "maintenance_id": 59,
                "system": {
                    "system_id": "166dc03b-83be-48e3-ab31-0cdcfb45ff5b",
                    "display_name": null,
                    "hostname": "1c41e51d0cb2",
                    "last_check_in": "2016-03-31T22:22:42.000Z"
                },
                "rule": {
                    "id": "CVE_2016_0728_kernel|KERNEL_CVE-2016-0728",
                    "description": "Kernel keychain vulnerability (CVE-2016-0728)",
                    "severity": "ERROR",
                    "category": "Security"
                },
                "current_report": {
                    "details": {},
                    "id": 112409725
                }
            }
        ]
    },
    {
        "overdue": false,
        "maintenance_id": 89,
        "name": "",
        "start": "2016-04-14T03:00:00.000Z",
        "end": "2016-04-14T04:00:00.000Z",
        "created_by": "rhn-support-jkinlaw",
        "silenced": false,
        "actions": []
    },
    {
        "overdue": false,
        "maintenance_id": 111,
        "name": "Doctor Jimmy Bringus",
        "start": "2016-05-06T03:00:00.000Z",
        "end": "2016-05-06T04:00:00.000Z",
        "created_by": "rhn-support-jcrafts",
        "silenced": false,
        "actions": [
            {
                "done": false,
                "id": 131,
                "maintenance_id": 111,
                "system": {
                    "system_id": "9186bf73-93c1-4855-9e04-2ce3c9f13125",
                    "display_name": null,
                    "hostname": "nelson.usersys.redhat.com",
                    "last_check_in": "2016-05-05T11:47:15.000Z"
                },
                "rule": {
                    "id": "CVE_2015_7547_glibc|GLIBC_CVE_2015_7547",
                    "description": "Glibc stack-based buffer overflow security flaw (CVE-2015-7547)",
                    "severity": "ERROR",
                    "category": "Security"
                },
                "current_report": {
                    "details": {},
                    "id": 124904841
                }
            }
        ]
    }
]
'''


def get_all_plans():
    '''
    Fetch all the plans for this account
    '''
    conn = InsightsConnection()
    endpoint = conn.api_url + '/maintenance/'
    res = conn.session.get(endpoint)
    all_plans = json.loads(res.content)
    return all_plans


def get_plans_for_this_system():
    '''
    Fetch plans and filter by this system's ID
    '''
    # all_plans = get_all_plans()
    all_plans = json.loads(planstr)
    # find the plans for this system
    # API returns all plans for this account, so filter them out
    #   just for the current machine
    # system_id is nested in plans[plan index].actions[action index].system.system_id
    sys_plans = []
    for p in all_plans:
        actions = p['actions']
        for a in actions:
            system_id = a['system']['system_id']
            if system_id == generate_machine_id():
                sys_plans.append(p)
    return all_plans


def consolidate_actions(actions):
    '''
    Put all systems of the same action in one group
    '''
    new_actions = {}
    rules = {}
    for a in actions:
        rule_id = a['rule']['id']
        if rule_id not in new_actions:
            new_actions[rule_id] = []
        if rule_id not in rules:
            rules[rule_id] = a['rule']
        new_actions[rule_id].append(a)
    return new_actions, rules


def display_plans():
    '''
    Pretty print the maintenance plan to the console
    '''
    twidth = 92
    tl = u'\u250f'
    tr = u'\u2513'
    bl = u'\u2517'
    br = u'\u251b'
    hr = ''.join([u'\u2501' for u in range(twidth)])
    vr = u'\u2503'
    tl2 = u'\u250c'
    tr2 = u'\u2510'
    bl2 = u'\u2514'
    br2 = u'\u2518'
    hr2 = ''.join([u'\u2500' for u in range(twidth - 2)])
    vr2 = u'\u2502'
    mvl2 = u'\u251c'
    mvr2 = u'\u2524'
    hr3 = ''.join([u'\u2508' for u in range(twidth - 2)])
    clock = u'\u25f4'
    x = u'\u2717'
    check = u'\u2714'
    greenon = '\033[92m'
    redon = '\033[91m'
    boldon = '\033[1m'
    boldoff = '\033[0m'
    plans = get_all_plans()
    for p in plans:
        print(tl + hr + tr)
        print(vr + boldon + '{name}'.format(name=p['name'] if p['name'] else '(untitled)').ljust(twidth) + boldoff + vr)
        start = p['start'] if p['start'] else '(no start time)'
        end = p['end'] if p['end'] else '(no end time)'
        print(vr + (' ' + clock + ' ' + start + ' to ' + end).ljust(twidth) + vr)
        actions, rules = consolidate_actions(p['actions'])
        for r in rules:
            print(vr + tl2 + hr2 + tr2 + vr)
            print(vr + vr2 + boldon + rules[r]['description'].ljust(twidth - 2) + boldoff + vr2 + vr)
            print(vr + mvl2 + hr2 + mvr2 + vr)
            print(vr + vr2 + 'System'.ljust((twidth - 2) / 2) + 'Last Check In'.ljust((twidth - 2) / 3) + 'Status'.ljust((twidth - 2) / 6) + vr2 + vr)
            print(vr + vr2 + hr3 + vr2 + vr)
            for a in actions[rules[r]['id']]:
                if not a['system']:
                    continue
                display_name = a['system']['display_name']
                hostname = display_name if display_name else a['system']['hostname']
                status = check if a['done'] else x
                print(vr + vr2 +
                      hostname.ljust((twidth - 2) / 2) +
                      a['system']['last_check_in'].ljust((twidth - 2) / 3) +
                      (greenon if a['done'] else redon) +
                      status.ljust((twidth - 2) / 6) + boldoff + vr2 + vr)
            print(vr + bl2 + hr2 + br2 + vr)
        print(bl + hr + br)
