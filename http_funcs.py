
import cherrypy
import urllib.request
import json
import base64
import time
import socket

def sendJsonRequest(url,payload = None, header = None):
    '''
        Sends a request to the specified URL with the given header(dict) and payload(dict).
        Returns the response in python dict format
    '''

    payload = json.dumps(payload)

    payload = bytes(payload, 'utf-8')

    if (header == None):
        header = {
        'Content-Type' : 'application/json; charset=utf-8'
        }


    try:
        req = urllib.request.Request(url, data=payload, headers=header)
        response = urllib.request.urlopen(req, timeout=4)
        data = response.read() # read the received bytes
        encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
        response.close()
        data = json.loads(data.decode(encoding))
    except Exception as ex:
        return 1
    return data



def getAuthenticationHeader(username, api_key):

    headers = {
        'X-username' : str(username),
        'X-apikey' : str(api_key),
        'Content-Type' : 'application/json; charset=utf-8'
        }
    return headers
