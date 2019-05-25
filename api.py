import cherrypy
import urllib.request
import json
import base64
import nacl.encoding
import nacl.signing
import time

class MainApp(object):
    #CherryPy Configuration
    _cp_config = {'tools.encode.on': True, 
                  'tools.encode.encoding': 'utf-8',
                  'tools.sessions.on' : 'True',
                 }       

	# If they try somewhere we don't know, catch it here and send them to the right place.
    @cherrypy.expose
    @cherrypy.tools.json_in()
    def default(self, *args, **kwargs):
        """The default page, given when we don't recognise where the request is for."""
        try:
            input_json = cherrypy.request.json
        except:
            input_json = None
        print(input_json)
        response = {
            "response" : "bad-api-call"
        }
        return json.dumps(response)

    @cherrypy.expose
    def grab(self):
        url = "http://192.168.20.13:8080/api/test_url"
        payload = {
            "connection_location" : "2",
            "connection_address"  : "122.57.4.189:41480",
            "incoming_pubkey"     : "123123123123"
        }
        headers = {
            'Content-Type' : 'application/json; charset=utf-8',
        }   

        payload = json.dumps(payload)
        payload = bytes(payload, 'utf-8')
        req = urllib.request.Request(url, data=payload, headers=headers)

        response = urllib.request.urlopen(req)

        data = response.read() # read the received bytes
        encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
        response.close()

        data = json.loads(data.decode(encoding))
    def test_url(self):
        """The default page, given when we don't recognise where the request is for."""
        try:
            input_json = cherrypy.request.json
        except:
            input_json = None
        print(input_json)
        response = {
            "response" : "bad-api-call"
        }
        return json.dumps(response)
        
