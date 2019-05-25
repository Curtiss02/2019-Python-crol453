import sqlite3
import cherrypy
import urllib.request
import json
import base64
import nacl.encoding
import nacl.signing
import time
import sqlite3


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
    def test(self):
        url = "http://192.168.20.13:8080/api/rx_message"

        payload = {
            "message" : "TEST API 123"
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



    @cherrypy.expose
    @cherrypy.tools.json_in()
    def rx_message(self):
        input_json = cherrypy.request.json
        
        msg = input_json['message']
        
        result = {"response" : "ok"}

        print(msg)

        # Responses are serialized to JSON (because of the json_out decorator)
        return json.dumps(result)
    
    @cherrypy.expose
    @cherrypy.tools.json_in()
    def rx_broadcast(self):
        input_json = cherrypy.request.json
        
        msg = json.loads(input_json)

        msg = msg['message']
        
        result = {"response" : "ok"}

        print(msg)
        
        # Responses are serialized to JSON (because of the json_out decorator)
        return json.dumps(result)
        
