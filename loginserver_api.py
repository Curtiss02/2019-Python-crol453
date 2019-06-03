#Contains all api calls to the login server for use own server
#Will execute the API call and then 
import http_funcs
import nacl

#Implements report API call to login server
def report(connection_location, connection_address, pubkey, status, authenticationHeader):

    #Get our needed values
    report_url = "http://cs302.kiwi.land/api/report"

    #Turn our public key into a hex eoncoded string

    
    headers = authenticationHeader

    payload = {
        "connection_location" : connection_location,
        "connection_address"  : connection_address,
        "incoming_pubkey"     : pubkey,
        "status"              : status

    }   
    try:
        data = http_funcs.sendJsonRequest(report_url, payload, headers)
    except Exception as e:
        print(e)
        return 1
    return data

def ping(pubkey = None, signature = None, authenticationHeader = None):
    ping_url = "http://cs302.kiwi.land/api/ping"

    payload = {}
    if(pubkey):
        payload['pubkey'] = pubkey
    if(signature):
        payload['signature'] = signature
    try:
        data = http_funcs.sendJsonRequest(ping_url, payload=payload, header=authenticationHeader)
    except Exception as e:
        print(e)
        return "FAIL"
    return data

def load_new_apikey(authenticationHeader):
    url = "http://cs302.kiwi.land/api/load_new_apikey"
    data = http_funcs.sendJsonRequest(url, header=authenticationHeader)
    return data


def loginserver_pubkey():
    pubkey_url = "http://cs302.kiwi.land/api/loginserver_pubkey"
    data = http_funcs.sendJsonRequest(pubkey_url, None, None)
    return data

def list_users(authenticationHeader):
    userlist_url = "http://cs302.kiwi.land/api/list_users"
    try:
        data = http_funcs.sendJsonRequest(userlist_url, None, authenticationHeader)
    except Exception as e:
        print(e)
        return 1
    return data

def add_pubkey(pubkey, username, signature, authenticationHeader):
    '''Expect pubkey as hex encoded string'''

    addkey_url = "http://cs302.kiwi.land/api/add_pubkey"

    #create HTTP BASIC authorization header


    payload = {
        "pubkey" : pubkey,
        "username" : username,
        "signature" : signature
    }   
    try:
        data = http_funcs.sendJsonRequest(addkey_url, payload, authenticationHeader)
    except Exception as e:
        print(e)
        return 1
    return data

def get_loginserver_record(authenticationHeader):
    url = "http://cs302.kiwi.land/api/get_loginserver_record"
    data = http_funcs.sendJsonRequest(url, header=authenticationHeader)
    return data

def check_pubkey(pubkey, authenticationHeader):
    url = "http://cs302.kiwi.land/api/check_pubkey"
    payload = {"pubkey" : pubkey}
    data = http_funcs.sendJsonRequest(url, payload=payload, header=authenticationHeader)
    return data