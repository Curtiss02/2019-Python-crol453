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
import cgi
import html_strings

LOCAL_IP = socket.gethostbyname(socket.gethostname()) + ":8080"
EXTERNALIP = urllib.request.Request("https://api.ipify.org")
EXTERNALIP = urllib.request.urlopen(EXTERNALIP)
EXTERNALIP = EXTERNALIP.read().decode('utf-8')
#server_location = input("Enter server location (lab-pc:0, uni-wifi:1, external-ip:2: ")
SERVER_IP = EXTERNALIP

#if (server_location == 0 or server_location == 1):
#    SERVER_IP = LOCAL_IP
#elif (server_location == 2):
#    SERVER_IP = EXTERNALIP

startHTML = """<html><head><title>Chatter</title><link rel='stylesheet'type='text/css' href='static/example.css' /><link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" integrity="sha384-Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm" crossorigin="anonymous"></head><body>"""

endHTML = """<script src="https://code.jquery.com/jquery-3.2.1.slim.min.js" integrity="sha384-KJ3o2DKtIkvYIK3UENzmM7KCkRr/rE9/Qpg6aAZGJwFDMVNA/GpGFF93hXpG5KkN" crossorigin="anonymous"></script>
            <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.12.9/umd/popper.min.js" integrity="sha384-ApNbgh9B+Y1QKtv3Rn7W3mgPxhU9K/ScQsAP7hUibX39j7fakFPskvXusvfa0b4Q" crossorigin="anonymous"></script>
            <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/js/bootstrap.min.js" integrity="sha384-JZR6Spejh4U02d8jOt6vLEHfe/JQGiRRSQQxSfFWpi1MquVdAyjUar5+76PVCmYl" crossorigin="anonymous"></script></body>
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
        if(cherrypy.session.get('username') == None):
            raise cherrypy.HTTPRedirect('/login')
        else:
            Page = startHTML 
            Page += html_strings.getNavbar(cherrypy.session['username'])
                
            Page += html_strings.jumbotron
            Page += '<form action="/broadcast" method="post" enctype="multipart/form-data">'
            Page += 'Message: <input type="text" name="message"/><br/>'
            Page += '<input type="submit" value="Broadcast Message"/></form>'
            Page += displayBroadcasts()

        return Page
        
    @cherrypy.expose
    def login(self, bad_attempt = 0):
        Page = startHTML 
        Page += html_strings.jumbotron_login
        Page += """ <div class="container">
                    <div class=".col-sm-">
                    
                    """
        if bad_attempt != 0:
            Page += "<font color='red'>Invalid username/password!</font>"
        Page += html_strings.login_form

        return Page
        
    # LOGGING IN 
    @cherrypy.expose
    def signin(self, username=None, password=None, hidden = None):
        """Check their name and password and send them either to the main page, or back to the main login screen."""
        error = authLogin(username, password)
        #error = authoriseUserLogin(username, password)
        if error == 0:  
            addnewPubKey()
            if(hidden == "on"):
                report("offline")
            else:
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
        send_broadcast(message, "172.23.8.206:8080")
        raise cherrypy.HTTPRedirect('/')


    @cherrypy.expose
    def users(self):
        userList = getUserList()
        sql_funcs.updateUserList(userList)
        Page = startHTML
        Page += html_strings.getNavbar(cherrypy.session['username'])
        Page += displayUserList(userList)

        return Page

    

        


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
    publicKey = cherrypy.session['publicKey']

    #Turn our public key into a hex eoncoded string
    pubkey_hex = publicKey.encode(encoder=nacl.encoding.HexEncoder) 
    pubkey_hex_str = pubkey_hex.decode('utf-8')  
    
    #create HTTP BASIC authorization header
    headers = http_funcs.getAuthenticationHeader()

    payload = {
        "connection_location" : "1",
        "connection_address"  : str(SERVER_IP),
        "incoming_pubkey"     : pubkey_hex_str,
        "status"              : status

    }   

    data = http_funcs.sendJsonRequest(login_url, payload, headers)

    if ( data["response"] == "ok"):
        print("\nSuccess reporting !!!\n")
        return 0
    else:
        print("Failure")
        return 1
    


#Pings the server with usernamd/password for basic authentiction/login confirmation    
def authLogin(username, password):
    login_url = "http://cs302.kiwi.land/api/ping"
   
    # Creates basic header for intial authorisation
    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))
    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type' : 'application/json; charset=utf-8',
    }

    data = http_funcs.sendJsonRequest(login_url, None, headers)
    if ( data["authentication"] == "basic"):
        url = "http://cs302.kiwi.land/api/load_new_apikey"
        data = http_funcs.sendJsonRequest(url, None, headers)
        if(data["response"] == "ok"):
            cherrypy.session['username'] = username
            cherrypy.session['api_key'] = data['api_key']
            return 0
        else:
            return 1
    else:
        return 1




def addnewPubKey():
    privateKey, publicKey = generateNewKeyPair()
    username = cherrypy.session['username']

    pubkey_hex = publicKey.encode(encoder=nacl.encoding.HexEncoder) 
    pubkey_hex_str = pubkey_hex.decode('utf-8')  
    message_bytes = bytes(pubkey_hex_str + username, encoding='utf-8')  
    signed = privateKey.sign(message_bytes, encoder=nacl.encoding.HexEncoder) 
    signature_hex_str = signed.signature.decode('utf-8')

    addkey_url = "http://cs302.kiwi.land/api/add_pubkey"

    #create HTTP BASIC authorization header
    headers = http_funcs.getAuthenticationHeader()

    payload = {
        "pubkey" : pubkey_hex_str,
        "username" : username,
        "signature" : signature_hex_str
    }   

    data = http_funcs.sendJsonRequest(addkey_url, payload, headers)

    if ( data["loginserver_record"]):
        print("ADD PUBKEY SUCESS")
        cherrypy.session['privateKey'] = privateKey
        cherrypy.session['publicKey'] = publicKey
        cherrypy.session['loginserver_record'] = data['loginserver_record']
        return 0
    else:
        print("ADD PUBKEY FAIL")
        return 1






def send_broadcast(message, ip):
    privateKey = cherrypy.session['privateKey']
    publicKey = cherrypy.session['publicKey']

    username = cherrypy.session['username']
    timestamp = time.time()


    
    message_bytes = bytes(str(cherrypy.session['loginserver_record']) + str(message) + str(timestamp), encoding='utf-8')  
    signed = privateKey.sign(message_bytes, encoder=nacl.encoding.HexEncoder) 
    signature_hex_str = signed.signature.decode('utf-8')

    broadcast_url = "http://" + ip + "/api/rx_broadcast"


        
    #create HTTP BASIC authorization header
    headers = http_funcs.getAuthenticationHeader()

    payload = {
        "loginserver_record" : cherrypy.session['loginserver_record'],
        "message" : str(message),
        "sender_created_at": str(timestamp),
        "signature" : signature_hex_str
    }


    try:
        data = http_funcs.sendJsonRequest(broadcast_url, payload, headers)
    except:
        return 1

    if ( data["response"] == "ok"):
        print("Succesfully broadcasted message")
        return 0
    else:
        print("Failed broadcast")
        return 1

def getUserList():
    url = "http://cs302.kiwi.land/api/list_users"

    headers = http_funcs.getAuthenticationHeader()
    data = http_funcs.sendJsonRequest(url, None, headers)
    return data['users']

def displayBroadcasts():
    broadcasts = sql_funcs.get_broadcasts()
    html = ""
    #Format is (Loginserver_recod, message, timestamp, signature)
    html += "<h1>Public Broadcasts</h1>"
    for row in broadcasts:
        message = row[1]
        username = row[0].split(',')[0]
        timestamp = row[2]
        int_timestamp = int(float(timestamp))
        
        readable_timestamp = time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime(int_timestamp))

        html += """ <div class="container">
	                <p>"""
        html +=  cgi.escape(message) 
        html +=  """</p>
	                <span class="time-right">""" 
        html += cgi.escape(username) 
        html += ": " 
        html += readable_timestamp 
        html += """</span>
        	     </div> """
                
    return html

def displayUserList(userList):
    html = """<table class="table">
    <thead class="thead-dark">
    <tr>
    <th scope="col">Username</th>
    <th scope="col">Connection Address</th>
    <th scope="col">Connection Location</th>
    <th scope="col">Public Key</th>
    <th scope="col">Last Seen</th>
    <th scope="col">Status</th>
    </tr>
    </thead>
    <tbody>"""

    for user in userList:
        html += "<tr>"
        username = cgi.escape((user['username']))
        timeSinceActivity =  cgi.escape(str(round((time.time() - float(user['connection_updated_at']))/60)) + "minutes ago")
        connection_address = cgi.escape(user['connection_address'])
        connection_location = cgi.escape(str(user['connection_location']))
        pubkey = cgi.escape(user['incoming_pubkey'])
        status = cgi.escape(user['status'])
        html += "<th scope=\"row\">" + username + "</th>"
        html += "<td>" + connection_address + "</td>"
        html += "<td>" + connection_location + "</td>"
        html += "<td>" + pubkey + "</td>"
        html += "<td>" + timeSinceActivity + "</td>"
        html += "<td>" + status + "</td>"
        html += "</tr>"
    return html

        
