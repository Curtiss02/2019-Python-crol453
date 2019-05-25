
import cherrypy
import urllib.request
import json
import base64
import time
import socket

def sendJsonRequest(url,payload, header):
    """Sends a request to the specified URL with the given header(dict) and payload(dict).
        Returns the response in python dict format
    """

    payload = json.dumps(payload)

    payload = bytes(payload, 'utf-8')

    req = urllib.request.Request(url, data=payload, headers=header)
    response = urllib.request.urlopen(req)
    data = response.read() # read the received bytes
    print(data)

    encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
    response.close()

    
    data = json.loads(data.decode(encoding))

    return data




def getAuthenticationHeader():

    try:
        username = cherrypy.session['username']
        password = cherrypy.session['password']

        #create HTTP BASIC authorization header
        credentials = ('%s:%s' % (username, password))
        b64_credentials = base64.b64encode(credentials.encode('ascii'))
        headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type' : 'application/json; charset=utf-8',
        }
        
    except KeyError:
        headers - -1

    return headers