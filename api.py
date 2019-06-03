import cherrypy
import urllib.request
import json
import base64
import nacl.encoding
import nacl.signing
import time
import sqlite3
import sql_funcs
import socket
import time
import binascii


LOCAL_IP = socket.gethostbyname(socket.gethostname()) + ":8080"



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
        response = {
            "response" : "bad-api-call"
        }
        return json.dumps(response)

    @cherrypy.expose
    def test(self):

        url = "http://" + LOCAL_IP + "/api/rx_broadcast"
        timestamp = str(time.time())
        payload = {
            "loginserver_record" : "adkjaskldjasldjajklsd1231",
            "message" : "TEST API 123",
            "sender_created_at" : timestamp,
            "signature" : "hey feller"
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


        return json.dumps(result)
    
    @cherrypy.expose
    #allows incoming json data
    @cherrypy.tools.json_in()
    def rx_broadcast(self):
        try:
            input_json = cherrypy.request.json
        except:
            return json.dumps({"response" : "error", "message" : "invalid json"})
        
        try:
            sender_record = input_json['loginserver_record']
            msg = input_json['message']
            timestamp = input_json['sender_created_at']
            sig = input_json['signature']
            
        except KeyError:
            result = {
                "response" : "error",
                "message" : "missing field"}
            return json.dumps(result)
        if(not(verifyBroadcastSignature(sender_record, msg, timestamp, sig))):
            print("FAIL VERIFY")
            result = {
                "response" : "error",
                "message" : "bad signature"}
            return json.dumps(result)
        print(sender_record, msg, timestamp, sig)
        sql_funcs.add_broadcast(sender_record, msg, timestamp, sig)
       

        result = {"response" : "ok"}
        return json.dumps(result)
    
    @cherrypy.expose
    #allows incoming json data
    @cherrypy.tools.json_in()
    def ping_check(self):
        try:
            input_json = cherrypy.request.json
        except:
            return json.dumps({"response" : "error", "message" : "invalid json"})
        try:
            ping_time = input_json['my_time']
            connection_address = input_json['connection_address']
            connection_location = input_json['connection_location']
            response = "ok"
            message = "success"
        except KeyError:
            response = "error"
            message = "missing field"
                   
        timestamp =  str(time.time())
        result = {"response" : response, "message": message, "my_time": timestamp}
        return json.dumps(result)

def verifyLoginserverRecord(loginserver_record):
    arr = loginserver_record.split(",")
    username = arr[0]


    return True

def verifyBroadcastSignature(loginserver_record, message, timestamp, signature):
    #Verifying throws excepton if the signature doesnt match
    try:
        pubkey = loginserver_record.split(',')[1]
        message = message
        verify_key = nacl.signing.VerifyKey(pubkey, encoder=nacl.encoding.HexEncoder)
        sig_bytes = binascii.unhexlify(signature)
        msg_bytes = bytes(loginserver_record + message + timestamp, 'utf-8')
        verify_key.verify(msg_bytes, sig_bytes)
        return True
    except Exception as e:
        print(e)
        return False


        
