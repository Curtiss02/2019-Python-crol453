import cherrypy
import urllib.request
import json
import base64
import nacl.encoding
import nacl.signing
import nacl
import time
import sqlite3
import sql_funcs
import socket
import time
import binascii
import loginserver_api


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
        if(rateLimit()):
            return json.dumps({"response" : "error", "message" : "rate limit"})
        return "<html><body>404</body></html>"


    @cherrypy.expose
    @cherrypy.tools.json_in()
    def rx_message(self):
        if(rateLimit()):
            return json.dumps({"response" : "error", "message" : "rate limit"})
        input_json = cherrypy.request.json
        
        msg = input_json['message']
        
        result = {"response" : "ok"}


        return json.dumps(result)
    
    @cherrypy.expose
    #allows incoming json data
    @cherrypy.tools.json_in()
    def rx_broadcast(self):
        if(rateLimit()):
            return json.dumps({"response" : "error", "message" : "rate limit"})
        try:
            input_json = cherrypy.request.json
        except:
            return json.dumps({"response" : "error", "message" : "invalid json"})
        
        try:
            sender_record = input_json['loginserver_record']
            msg = input_json['message']
            timestamp = input_json['sender_created_at']
            sig = input_json['signature']
            if(len(msg) > 256):
                return json.dumps({"response": "error", "message" : "brpadcast exceeds length limit"})
            
        except KeyError:
            result = {
                "response" : "error",
                "message" : "missing field"}
            return json.dumps(result)
        verifyLoginserverRecord(sender_record)
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
        if(rateLimit()):
            return json.dumps({"response" : "error", "message" : "rate limit"})
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

    @cherrypy.expose
    #allows incoming json data
    @cherrypy.tools.json_in()    
    def rx_privatemessage(self):
        if(rateLimit()):
            return json.dumps({"response" : "error", "message" : "rate limit"})
        try:
            input_json = cherrypy.request.json
        except:
            return json.dumps({"response" : "error", "message" : "invalid json"})
        try:
            loginserver_record = input_json['loginserver_record']
            target_pubkey = input_json['target_pubkey']
            target_username = input_json['target_username']
            encrypted_message = input_json['encrypted_message']
            timestamp = input_json['sender_created_at']
            signature = input_json['signature']
        except KeyError:
            return json.dumps({"response" : "error", "message" : "missing field"})

        sql_funcs.addPrivateMessage(loginserver_record, target_pubkey, target_username, encrypted_message, timestamp, signature)
        return json.dumps({"response" : "ok"})
    @cherrypy.expose
    @cherrypy.tools.json_in()
    def checkmessages(self):
        if(rateLimit()):
            return json.dumps({"response" : "error", "message" : "rate limit"})
        try:
            input_json = cherrypy.request.json
        except:
            return json.dumps({"response" : "error", "message" : "invalid json"})
        try:
            since = float(input_json['since'])
        except:
            return json.dumps({"response" : "error", "message" : "missing time"})
        broadcast_rows = sql_funcs.get_broadcasts()
        broadcasts_since = []
        for broadcast in broadcast_rows:
            timestamp = float(broadcast[2])
            if(timestamp > since):
                broadcast_dict = {
                    "loginserver_record" : broadcast[0],
                    "message" : broadcast[1],
                    "sender_created_at" : broadcast[2],
                    "signature" : broadcast[3]
                }
                broadcasts_since.append(broadcast_dict)
        message_rows = sql_funcs.getAllPrivateMessages()
        messages_since = []
        for message in message_rows:
            timestamp = float(message[4])
            if(timestamp > since):
                message_dict = {
                    "loginserver_record" : message[0],
                    "target_pubkey" : message[1],
                    "target_username" : message[2],
                    "encrypted_message" : message[3],
                    "sender_created_at" : message[4],
                    "signature" : message[5]
                }
        payload = {
            "response" : "ok",
            "broadcasts" : broadcasts_since,
            "private_messages" : messages_since
        }
        return json.dumps(payload)

def verifyLoginserverRecord(loginserver_record):

    try:
        arr = loginserver_record.split(",")
        username = arr[0]
        pubkey = arr[1]
        timestamp = arr[2]
        sig = arr[3]
        server_pubkey = loginserver_api.loginserver_pubkey()['pubkey']
        server_pubkey = nacl.signing.VerifyKey(server_pubkey, encoder=nacl.encoding.HexEncoder)
        verify_key = server_pubkey
        sig_bytes = binascii.unhexlify(sig)
        msg_bytes = bytes(username + pubkey + timestamp, 'utf-8')
        print(msg_bytes)

        verify_key.verify(msg_bytes, sig_bytes)

        return True
    except Exception as e:
        print(e)
        return False


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
def verifyPrivateMessage():
    
    return 1

def rateLimit():
    rate = 20.0
    per = 5.0
    if(cherrypy.session.get('last_check') == None or cherrypy.session.get('allowance') == None):
        cherrypy.session['last_check'] = time.time()
        cherrypy.session['allowance'] = rate
    print(cherrypy.session['allowance'] )

    current = time.time()
    time_passed = current - cherrypy.session['last_check']
    cherrypy.session['last_check'] = current
    print(time_passed)
    cherrypy.session['allowance'] += time_passed * (rate / per)
    if (cherrypy.session['allowance'] > rate):
        cherrypy.session['allowance'] = rate
    if (cherrypy.session['allowance'] < 1.0):
        return True
    else:
        cherrypy.session['allowance'] = cherrypy.session['allowance'] - 1.0
        return False




        
