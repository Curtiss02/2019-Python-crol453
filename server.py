import sqlite3
import cherrypy
import urllib.request
import json
import base64
import nacl.encoding
import nacl.signing
import time
import socket
import http_funcs
import sql_funcs
import datetime


startHTML = """<html><head><title>Chatter</title><link rel='stylesheet'type='text/css' href='static/example.css' />
<style>
body {
  margin: 0 auto;
  max-width: 800px;
  padding: 0 20px;
}

.container {
  border: 2px solid #dedede;
  background-color: #f1f1f1;
  border-radius: 5px;
  padding: 10px;
  margin: 10px 0;
}

.darker {
  border-color: #ccc;
  background-color: #ddd;
}

.container::after {
  content: "";
  clear: both;
  display: table;
}

.container img {
  float: left;
  max-width: 60px;
  width: 100%;
  margin-right: 20px;
  border-radius: 50%;
}

.container img.right {
  float: right;
  margin-left: 20px;
  margin-right:0;
}

.time-right {
  float: right;
  color: #aaa;
}

.time-left {
  float: left;
  color: #999;
}
</style></head><body>"""

endHTML = """</body>
                </html>"""

class MainApp(object):

	#CherryPy Configuration
    _cp_config = {'tools.encode.on': True, 
                  'tools.encode.encoding': 'utf-8',
                  'tools.sessions.on' : 'True',
                 }       

	# If they try somewhere we don't know, catch it here and send them to the right place.
    @cherrypy.expose
    def default(self, *args, **kwargs):
        """The default page, given when we don't recognise where the request is for."""
        Page = startHTML + "<h1>404 ERROR</h1>"
        cherrypy.response.status = 404
        return Page

    # PAGES (which return HTML that can be viewed in browser)
    @cherrypy.expose
    def index(self):
        Page = startHTML + "Welcome! This is a test website for COMPSYS302!<br/>"
        try:
            Page += "Hello " + cherrypy.session['username'] + "!<br/>"
            Page += "Here is some bonus text because you've logged in! <a href='/signout'>Sign out</a><br/>"
            Page += '<form action="/broadcast" method="post" enctype="multipart/form-data">'
            Page += 'Message: <input type="text" name="message"/><br/>'
            Page += '<input type="submit" value="Broadcast Message"/></form>'
            Page += displayBroadcasts()
        except KeyError: #There is no username
            Page += "<a href='login'><button type=\"button\">Login</button></a>"
        return Page
        
    @cherrypy.expose
    def login(self, bad_attempt = 0):
        Page = startHTML 
        if bad_attempt != 0:
            Page += "<font color='red'>Invalid username/password!</font>"
            
        Page += '<form action="/signin" method="post" enctype="multipart/form-data">'
        Page += 'Username: <input type="text" name="username"/><br/>'
        Page += 'Password: <input type="text" name="password"/>'
        Page += '<input type="submit" value="Login"/></form>'

        return Page
    
    @cherrypy.expose    
    def sum(self, a=0, b=0): #All inputs are strings by default
        output = int(a)+int(b)
        return str(output)
        
    # LOGGING IN AND OUT
    @cherrypy.expose
    def signin(self, username=None, password=None):
        """Check their name and password and send them either to the main page, or back to the main login screen."""
        error = authLogin(username, password)
        #error = authoriseUserLogin(username, password)
        if error == 0:
            cherrypy.session['username'] = username
            cherrypy.session['password'] = password          
            addnewPubKey()
            report("online")
            raise cherrypy.HTTPRedirect('/')
        else:
            raise cherrypy.HTTPRedirect('/login?bad_attempt=1')

    @cherrypy.expose
    def signout(self):
        """Logs the current user out, expires their session"""
        username = cherrypy.session.get('username')
        if username is None:
            pass
        else:
            cherrypy.lib.sessions.expire()
        raise cherrypy.HTTPRedirect('/')
    @cherrypy.expose
    def broadcast(self, message=None):
        api_broadcast(message)
        raise cherrypy.HTTPRedirect('/')


    @cherrypy.expose
    def users(self):
        userList = getUserList()
        Page = startHTML
        for user in userList:
            print(user['username'])
            timeSinceActivity = round((time.time() - float(user['connection_updated_at']))/60)
            print(timeSinceActivity, "minutes since last activity\n")

    

        


###
### Functions only after here
###

def generateNewKeyPair():
    privateKey = nacl.signing.SigningKey.generate()
    publicKey = privateKey.verify_key
    return privateKey, publicKey


#Reports that the user is online and lets the login server know what public key they will be using for this session
def report(status):

    #Get our needed values
    login_url = "http://cs302.kiwi.land/api/report"
    privateKey = cherrypy.session['privateKey']
    publicKey = cherrypy.session['publicKey']
    username = cherrypy.session['username']
    password = cherrypy.session['password']

    #Turn our public key into a hex eoncoded string
    pubkey_hex = publicKey.encode(encoder=nacl.encoding.HexEncoder) 
    pubkey_hex_str = pubkey_hex.decode('utf-8')  
    
    LOCAL_IP = socket.gethostbyname(socket.gethostname())

    #create HTTP BASIC authorization header
    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))
    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type' : 'application/json; charset=utf-8',
    }

    payload = {
        "connection_location" : "2",
        "connection_address"  : str(LOCAL_IP),
        "incoming_pubkey"     : pubkey_hex_str,
        "status"              : status

    }   

    payload = json.dumps(payload)

    payload = bytes(payload, 'utf-8')


    req = urllib.request.Request(login_url, data=payload, headers=headers)
    response = urllib.request.urlopen(req)

    data = response.read() # read the received bytes
    encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
    response.close()

    data = json.loads(data.decode(encoding))

    if ( data["response"] == "ok"):
        print("\nSuccess reporting !!!\n")
        return 0
    else:
        print("Failure")
        return 1
    


#Pings the server with usernamd/password for basic authentiction/login confirmation    
def authLogin(username, password):
    login_url = "http://cs302.kiwi.land/api/ping"
    privateKey, publicKey = generateNewKeyPair()

    pubkey_hex = publicKey.encode(encoder=nacl.encoding.HexEncoder) 
    pubkey_hex_str = pubkey_hex.decode('utf-8')  
    
    
    #create HTTP BASIC authorization header
    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))
    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type' : 'application/json; charset=utf-8',
    }

    payload = {

    }   

    payload = json.dumps(payload)

    payload = bytes(payload, 'utf-8')


    req = urllib.request.Request(login_url, data = payload, headers=headers)
    response = urllib.request.urlopen(req)

    data = response.read() # read the received bytes
    encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
    response.close()

    data = json.loads(data.decode(encoding))
    print(data)
    if ( data["authentication"] == "basic"):
        print("Success")
        return 0
    else:
        print("Failure")
        return 1




def addnewPubKey():
    privateKey, publicKey = generateNewKeyPair()
    username = cherrypy.session['username']
    password = cherrypy.session['password']

    pubkey_hex = publicKey.encode(encoder=nacl.encoding.HexEncoder) 
    pubkey_hex_str = pubkey_hex.decode('utf-8')  
    message_bytes = bytes(pubkey_hex_str + username, encoding='utf-8')  
    signed = privateKey.sign(message_bytes, encoder=nacl.encoding.HexEncoder) 
    signature_hex_str = signed.signature.decode('utf-8')

    addkey_url = "http://cs302.kiwi.land/api/add_pubkey"

    #create HTTP BASIC authorization header
    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))
    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type' : 'application/json; charset=utf-8',
    }

    payload = {
        "pubkey" : pubkey_hex_str,
        "username" : username,
        "signature" : signature_hex_str
    }   

    payload = json.dumps(payload)

    payload = bytes(payload, 'utf-8')

    req = urllib.request.Request(addkey_url, data=payload, headers=headers)
    response = urllib.request.urlopen(req)

    data = response.read() # read the received bytes
    encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
    response.close()

    data = json.loads(data.decode(encoding))
    print(data)
    if ( data["loginserver_record"]):
        print("ADD PUBKEY SUCESS")
        cherrypy.session['privateKey'] = privateKey
        cherrypy.session['publicKey'] = publicKey
        cherrypy.session['loginserver_record'] = data['loginserver_record']
        return 0
    else:
        print("ADD PUBKEY FAIL")
        return 1






def api_broadcast(message):
    privateKey = cherrypy.session['privateKey']
    publicKey = cherrypy.session['publicKey']

    username = cherrypy.session['username']
    password = cherrypy.session['password']
    timestamp = time.time()


    
    message_bytes = bytes(str(cherrypy.session['loginserver_record']) + str(message) + str(timestamp), encoding='utf-8')  
    signed = privateKey.sign(message_bytes, encoder=nacl.encoding.HexEncoder) 
    signature_hex_str = signed.signature.decode('utf-8')

    broadcast_url = "http://cs302.kiwi.land/api/rx_broadcast"

    #create HTTP BASIC authorization header
    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))
    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type' : 'application/json; charset=utf-8',
    }

    payload = {
        "loginserver_record" : cherrypy.session['loginserver_record'],
        "message" : str(message),
        "sender_created_at": str(timestamp),
        "signature" : signature_hex_str
    }



    data = http_funcs.sendJsonRequest(broadcast_url, payload, headers)

    if ( data["response"] == "ok"):
        print("Succesfully broadcasted message")
        return 0
    else:
        print("Failed broadcast")
        return 1

def getUserList():
    url = "http://cs302.kiwi.land/api/list_users"

    headers = getAuthenticationHeader()
    req = urllib.request.Request(url, headers=headers)
    response = urllib.request.urlopen(req)
    data = response.read()
    print(data)
    data = json.loads(data)

    return data['users']
def displayBroadcasts():
    broadcasts = sql_funcs.get_broadcasts()
    html = ""
    #Format is (Loginserver_recod, message, timestamp, signature)
    for row in broadcasts:
        print(row)
        message = row[1]
        username = row[0].split(',')[0]
        timestamp = row[2]
        #timestring = datetime.datetime.fromtimestamp(int(float(timestamp))).strftime('%Y-%m-d %H:%M:%S')

        html += """ <div class="container">
	                <p>"""
        html +=  message 
        html +=  """</p>
	                <span class="time-right">""" 
        html += username 
        html += ": " 
        html += timestamp 
        html += """</span>
        	     </div> """
                
    return html

        
