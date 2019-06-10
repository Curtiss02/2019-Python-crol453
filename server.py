import sqlite3
import cherrypy
import urllib.request
import json
import base64
import nacl.encoding
import nacl.signing
import nacl
import time
import socket
import http_funcs
import sql_funcs
import datetime
import cgi
import html_strings
import markdown
from threading import Thread
import loginserver_api
import reporter

LOCAL_IP = "localhost:10000"


SERVER_IP = socket.gethostbyname(socket.gethostname()) + ":10000"
SERVER_LOCATION = '0'

startHTML = """<html><head><title>Chatter</title><link rel='stylesheet'type='text/css' href='static/example.css' /><link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" integrity="sha384-Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm" crossorigin="anonymous"></head><body>"""

endHTML = """<script src="https://code.jquery.com/jquery-3.2.1.slim.min.js" integrity="sha384-KJ3o2DKtIkvYIK3UENzmM7KCkRr/rE9/Qpg6aAZGJwFDMVNA/GpGFF93hXpG5KkN" crossorigin="anonymous"></script>
            <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.12.9/umd/popper.min.js" integrity="sha384-ApNbgh9B+Y1QKtv3Rn7W3mgPxhU9K/ScQsAP7hUibX39j7fakFPskvXusvfa0b4Q" crossorigin="anonymous"></script>
            <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/js/bootstrap.min.js" integrity="sha384-JZR6Spejh4U02d8jOt6vLEHfe/JQGiRRSQQxSfFWpi1MquVdAyjUar5+76PVCmYl" crossorigin="anonymous"></script>
            <script src="static/custom.js"></script></body>
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
            #Page += "<div class=\"d-flex justify-content-center\">"
            Page += "<div class=\"mx-auto\" style=\"width: 100%;padding-right: 10%; padding-left: 10%;margin-right: 15px; margin-left: 15px;\">"
            Page += '<form action="/broadcast" method="post" enctype="multipart/form-data">'
            Page += """<div class="form-group">
                    <label for="message"><strong>Message:</strong></label>
                    <textarea class="form-control" class="rounded" rows="5" id="message" name="message"></textarea>
                    </div>"""
            Page += '<input type="submit" value="Send Broadcast"/></form>'
            Page += "</div>"
            Page += displayBroadcasts()
            Page += endHTML

        return Page
        
    @cherrypy.expose
    def login(self, bad_attempt = 0):
        Page = startHTML 
        Page += html_strings.jumbotron_login
        Page += """<div class=".col-sm-">
                    
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
        
        if error == 0:
            try:
                setKeys(username)
                loginReport()
                addUserInfo()
                reporter.updateUserList()
            except:
                raise cherrypy.HTTPRedirect('/login?bad_attempt=1')
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
            sql_funcs.remove_client_user(username)
            cherrypy.lib.sessions.expire()
        raise cherrypy.HTTPRedirect('/')
    @cherrypy.expose
    def broadcast(self, message=None):
        if(cherrypy.session.get('username') == None):
            raise cherrypy.HTTPRedirect('/login')
        if message != "":
            send_broadcast(message)
        raise cherrypy.HTTPRedirect('/')


    @cherrypy.expose
    def users(self):
        if(cherrypy.session.get('username') == None):
            raise cherrypy.HTTPRedirect('/login')
        else:
            userList = sql_funcs.getUserList()
            Page = startHTML
            Page += html_strings.getNavbar(cherrypy.session['username'])
            Page += displayUserList(userList)
            Page += endHTML 
            return Page

    @cherrypy.expose
    def send_private(self, recipient=None, message = None, previous=None):
        if(cherrypy.session.get('username') == None):
            raise cherrypy.HTTPRedirect('/login')
        send_private_message(recipient, message)
        raise cherrypy.HTTPRedirect('/' + previous)

    @cherrypy.expose
    def private(self):
        if(cherrypy.session.get('username') == None):
            raise cherrypy.HTTPRedirect('/login')
        else:
            Page = startHTML
            Page += html_strings.getNavbar(cherrypy.session['username'])
            Page +=  displayPrivateMessages()
            Page += endHTML
            return Page
    @cherrypy.expose
    def account(self):
        if(cherrypy.session.get('username') == None):
            raise cherrypy.HTTPRedirect('/login')
        Page = startHTML
        Page += html_strings.getNavbar(cherrypy.session['username'])
        Page += displayAccountInfo()
        Page += endHTML
        return Page
    @cherrypy.expose
    def addfilter(self, filterstring = None):
        if(cherrypy.session.get('username') == None):
            raise cherrypy.HTTPRedirect('/login')
        sql_funcs.addFilterWordForUser(cherrypy.session.get('username'), filterstring)
        raise cherrypy.HTTPRedirect('/account')
    @cherrypy.expose
    def removefilter(self, filterstring = None):
        if(cherrypy.session.get('username') == None):
            raise cherrypy.HTTPRedirect('/login')
        sql_funcs.removeFilterWordForUser(cherrypy.session.get('username'), filterstring)
        raise cherrypy.HTTPRedirect('/account')
    @cherrypy.expose
    def setstatus(self, status=None):
        if(cherrypy.session.get('username') == None):
            raise cherrypy.HTTPRedirect('/login')
        statuses = ['online', 'away', 'busy', 'offline']
        if(status in statuses):
            publicKey = cherrypy.session['public_key']
            pubkey_hex = publicKey.encode(encoder=nacl.encoding.HexEncoder) 
            pubkey_hex_str = pubkey_hex.decode('utf-8')  
            headers = http_funcs.getAuthenticationHeader(cherrypy.session['username'], cherrypy.session['api_key'])
            sql_funcs.updateStatusforUser(cherrypy.session['username'], status)

        raise cherrypy.HTTPRedirect('/account')
    @cherrypy.expose
    def set2fa(self, password=None):
        if(cherrypy.session.get('username') == None):
            raise cherrypy.HTTPRedirect('/login')
        if(password):
            pwhash = nacl.pwhash.str(password)
            sql_funcs.add2FAHAsh(cherrypy.session.get('username'), pwhash)
            encryptKeysWith2FA(password)
    
    @cherrypy.expose
    def blockuser(self, blockeduser = None, unblock=None):
        if(cherrypy.session.get('username') == None):
            raise cherrypy.HTTPRedirect('/login')
        if(unblock == '0'):
            sql_funcs.addBlockedUser(cherrypy.session['username'], blockeduser)
        elif(unblock == '1'):
            sql_funcs.removeBlockedUser(cherrypy.session['username'], blockeduser)
        raise cherrypy.HTTPRedirect('/account')
                


###
### Functions only after here
###

def generateNewKeyPair():
    privateKey = nacl.signing.SigningKey.generate()
    publicKey = privateKey.verify_key
    return publicKey, privateKey


#Reports that the user is online and lets the login server know what public key they will be using for this session
def loginReport():

    publicKey = cherrypy.session['public_key']

    #Turn our public key into a hex eoncoded string
    pubkey_hex = publicKey.encode(encoder=nacl.encoding.HexEncoder) 
    pubkey_hex_str = pubkey_hex.decode('utf-8')  
    
    #create HTTP BASIC authorization header
    headers = http_funcs.getAuthenticationHeader(cherrypy.session['username'], cherrypy.session['api_key'])

    data = loginserver_api.report(SERVER_LOCATION,SERVER_IP,pubkey_hex_str, "online", headers)

    if ( data["response"] == "ok"):
        print("\nSuccess reporting !!!\n")
        data = loginserver_api.get_loginserver_record(headers)
        cherrypy.session['loginserver_record'] = data['loginserver_record']
        return 0
    else:
        print("Failure")
        return 1
    


#Pings the server with usernamd/password for basic authentiction/login confirmation    
def authLogin(username, password):
    
   
    # Creates basic header for intial authorisation
    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))
    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type' : 'application/json; charset=utf-8',
    }

    data = loginserver_api.ping(authenticationHeader=headers)
    if ( data["authentication"] == "basic"):
        data = loginserver_api.load_new_apikey(headers)
        if(data["response"] == "ok"):
            cherrypy.session['username'] = username
            cherrypy.session['api_key'] = data['api_key']
            return 0
        else:
            return 1
    else:
        return 1


def setKeys(username):
    userKeys = getKeysforUser(username)
    #User previous keypair if found
    if(userKeys):
        cherrypy.session['private_key'] = nacl.signing.SigningKey(userKeys[0][1], encoder=nacl.encoding.HexEncoder)
        cherrypy.session['public_key'] = cherrypy.session['private_key'].verify_key
    else:
        publicKey, privateKey = generateNewKeyPair()
        pubkey_response = addnewPubKey(publicKey, privateKey)
        print("GEN NEW KEY")


    private_key_hex_str = cherrypy.session['private_key'].encode(encoder=nacl.encoding.HexEncoder).decode('utf-8') 
    public_key_hex_str = cherrypy.session['public_key'].encode(encoder=nacl.encoding.HexEncoder).decode('utf-8') 
    sql_funcs.addKeyPair(cherrypy.session['username'],public_key_hex_str , private_key_hex_str)


def addUserInfo():
    sql_funcs.add_client_user(cherrypy.session['username'], cherrypy.session['api_key'], cherrypy.session['public_key'].encode(encoder=nacl.encoding.HexEncoder).decode('utf-8') , cherrypy.session['loginserver_record'])
    


def addnewPubKey(publicKey, privateKey):
    
    username = cherrypy.session['username']

    pubkey_hex = publicKey.encode(encoder=nacl.encoding.HexEncoder) 
    pubkey_hex_str = pubkey_hex.decode('utf-8')  
    private_key_hex_str = privateKey.encode(encoder=nacl.encoding.HexEncoder).decode('utf-8') 
    message_bytes = bytes(pubkey_hex_str + username, encoding='utf-8')

    signed = privateKey.sign(message_bytes, encoder=nacl.encoding.HexEncoder) 
    signature_hex_str = signed.signature.decode('utf-8')


    header = http_funcs.getAuthenticationHeader(username, cherrypy.session['api_key'])


    data = loginserver_api.add_pubkey(pubkey_hex_str, username, signature_hex_str, header)
    try:
        cherrypy.session['private_key'] = privateKey
        cherrypy.session['public_key'] = publicKey
        
        print("ADD PUBKEY SUCESS")
        return 0
    except Exception as e:  
        print(e)
        print("ADD PUBKEY FAIL")
        return 1    
    
def send_broadcast(message):

    privateKey = cherrypy.session['private_key']
    timestamp = time.time()
    
    message_bytes = bytes(str(cherrypy.session['loginserver_record']) + str(message) + str(timestamp), encoding='utf-8')  
    signed = privateKey.sign(message_bytes, encoder=nacl.encoding.HexEncoder) 
    signature_hex_str = signed.signature.decode('utf-8')

       
    #create HTTP BASIC authorization header
    headers = http_funcs.getAuthenticationHeader(cherrypy.session['username'], cherrypy.session['api_key'])

    payload = {
        "loginserver_record" : cherrypy.session['loginserver_record'],
        "message" : str(message),
        "sender_created_at": str(timestamp),
        "signature" : signature_hex_str
    }

    #Send to own server so we can reload the page
    broadcast_url = "http://" + LOCAL_IP + "/api/rx_broadcast"
    http_funcs.sendJsonRequest(broadcast_url, payload, headers)

    userList = sql_funcs.getUserList()
    
    ips = [user[1] for user in userList]
    ips = set(ips)
    print(ips)
    for ip in ips:
        if(ip != SERVER_IP):
            broadcast_url = "http://" + ip + "/api/rx_broadcast"
            print("\nSending Broadcast to: " + ip)
            send = Thread(target=http_funcs.sendJsonRequest, args=[broadcast_url, payload, headers])
            send.start()    
    return 0



def getUserList():
    url = "http://cs302.kiwi.land/api/list_users"

    headers = http_funcs.getAuthenticationHeader(cherrypy.session['username'], cherrypy.session['api_key'])
    data = loginserver_api.list_users(headers)
    return data['users']

def displayBroadcasts():
    broadcasts = sql_funcs.get_broadcasts()
    html = ""
    #Format is (Loginserver_recod, message, timestamp, signature)
    hiddenCounter = 0
    filter_strings = sql_funcs.getFilterWordForUser(cherrypy.session['username'])
    filter_strings = [word[0] for word in filter_strings]
    msg = []
    blockedUsers = sql_funcs.getBlockedUsers(cherrypy.session['username'])
    blockedUsers = [user[0] for user in blockedUsers]

    #Get favourited broadcast meta messages
    meta_messages = [row[1] for row in broadcasts if row[1].lower().startswith('!meta:favourite_broadcast')]
    sigs = [msg.split(":")[2] for msg in meta_messages]
    fav_sigs = []
    #To account for people sending the signature in the form ["sig"] or just "sig"
    for sig in sigs:
        if sig.startswith("["):
            fav_sigs.append(sig[1:-1])
        else:
            fav_sigs.append(sig)
    
    html += """<div class="container"><div class="row"><div class='col-sm col'><label for="search_msg" class="col-form-label">Search Messages:</label>
            <input type="text" onkeyup="searchBroadcasts()" placeholder="Search messages..." class="form-control" id="search_msg"></div>
            <div class="col-sm"><label for="search_user" class="col-form-label">Search Users:</label>
            <input type="text" onkeyup="searchBroadcasts()" placeholder="Search for messages from user..." class="form-control" id="search_user"></div></div></div> """
    html += "<div class=\"d-flex justify-content-center\"><h1>Public Broadcasts</h1></div>"
    print(blockedUsers)
    for row in broadcasts:
        
        message = row[1]
        signature = row[3]
        if any(string.lower() in message.lower() for string in filter_strings):
            continue
        if (message.lower().startswith("!meta")):
            continue
        fav_count = fav_sigs.count(signature)
        fav_string = "!Meta:favourite_broadcast:" + signature
        username = row[0].split(',')[0]
        if(any(username.lower() in blockedUser.lower() for blockedUser in blockedUsers)):
            continue
        timestamp = row[2]
        int_timestamp = int(float(timestamp))
        
        readable_timestamp = time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime(int_timestamp))

        html += """ <div class="broadcast_container container">
	                <p>"""
        html +=  markdown.markdown(message) 
        html +=  "</p>"        
        html +=  """  <span class="time-right">""" 
        html += cgi.escape(username) 
        html += ": " 
        html += readable_timestamp 
        html += """</span><span class="time-left"><form action="/broadcast" method="post" enctype="multipart/form-data">
                    <button type='submit' class='btn' name='message' value='""" + fav_string + """'>❤ """ +  str(fav_count) + """</button>
                    </form>""" + """</span>
        	     </div> """
                
    return html

def displayUserList(userList):
    html = html_strings.userlist_head

    for user in userList:
        html += "<tr>"
        username = cgi.escape((user[0]))
        timeSinceActivity =  cgi.escape(str(round((time.time() - float(user[5]))/60)) + "minutes ago")
        connection_address = cgi.escape(user[1])
        connection_location = cgi.escape(str(user[2]))
        pubkey = cgi.escape(user[3])
        status = cgi.escape(user[4])
        reachable = cgi.escape(user[6])
        html += "<th scope=\"row\">" + username + "</th>"
        html +=  "<td>" + """<button type="button" class="btn btn-primary" data-toggle="modal" data-target="#messagemodal" data-username=\"""" + username +  "\">Message</button></td>"
        html += "<td>" + connection_address + "</td>"
        html += "<td>" + connection_location + "</td>"
        html += "<td>" + pubkey + "</td>"
        html += "<td>" + timeSinceActivity + "</td>"
        html += "<td>" + status + "</td>"
        html += "<td><img src='static/img/" + reachable + ".gif' alt='" + reachable + "' width='32' height='32'></td>"
        html += "</tr>"
    
    html += html_strings.messagemodal
    return html

def encodeKey(key):
    '''Encodes the given key to a hexadecimal string'''

    key_hex = key.encode(encoder=nacl.encoding.HexEncoder) 
    key_hex_str = key_hex.decode('utf-8')  
    return key_hex_str

def send_private_message(username, message):
    #Sends a private message to a user of given username
    try:
        userinfo = sql_funcs.getUserFromUserList(username)[0]
    except:
        print("user not found")
        return
    #Grab pubkey of reciever
    signing_key = cherrypy.session['private_key']
    receiving_pubkey = nacl.signing.VerifyKey(userinfo[3], encoder=nacl.encoding.HexEncoder)
    receiving_pubkey = receiving_pubkey.to_curve25519_public_key()
    box = nacl.public.SealedBox(receiving_pubkey)


    

    encrypted = box.encrypt(bytes(message, 'utf-8'), encoder=nacl.encoding.HexEncoder)
    enc_message = encrypted.decode('utf-8')

    loginserver_record= cherrypy.session['loginserver_record']
    address = userinfo[1]
    url = ''
    if(address == SERVER_IP):
       url =  "http://localhost:10000/api/rx_privatemessage"
    else:
        url = "http://" + address + "/api/rx_privatemessage"
    target_pubkey = userinfo[3]
    timestamp = str(time.time())

    sig_msg = loginserver_record + target_pubkey + username + enc_message + timestamp
    sig_bytes = bytes(sig_msg, encoding='utf-8')  
    sig_hex = signing_key.sign(sig_bytes, encoder=nacl.encoding.HexEncoder) 
    signature_hex_str = sig_hex.signature.decode('utf-8')

    payload = {
        "loginserver_record" : loginserver_record,
        "target_pubkey" : target_pubkey,
        "target_username" : username,
        "encrypted_message" : enc_message,
        "sender_created_at" : timestamp,
        "signature" : signature_hex_str
    }
    header = http_funcs.getAuthenticationHeader(cherrypy.session['username'], cherrypy.session['api_key'])
    data = http_funcs.sendJsonRequest(url, payload=payload, header=header)
    #Send to my own server in case offline
    send_away = Thread(target=http_funcs.sendJsonRequest, args=["http://localhost:10000/api/rx_privatemessage", payload, header])
    send_away.start()
    sql_funcs.addLocalPrivateMessage(cherrypy.session['username'], username, message, timestamp)
    print("Message SENT")
    print(data)


    return 1

def displayPrivateMessages():
    username = cherrypy.session['username']
    message_rows = sql_funcs.getMessagesToUser(username)
    html = "<div class=\"container\"><div class=\"row\">"
    html += """ <div class="nav flex-column nav-pills" id="v-pills-tab" role="tablist" aria-orientation="vertical"> """
    messageList = getConversations(username)
    
    conversationUsers = [msg['receiver'] for msg in messageList]
    conversationUsers = conversationUsers + [msg['sender'] for msg in messageList]
    conversationUsers = set(conversationUsers)

    filter_strings = sql_funcs.getFilterWordForUser(cherrypy.session['username'])
    filter_strings = [word[0] for word in filter_strings]


    #Disgusting HTML Stuff
    for user in conversationUsers:
        html += """<a class="nav-link" id="v-pills-""" + user + """-tab" data-toggle="pill" href="#v-pills-""" + user + """" role="tab" aria-controls="v-pills-""" + user + """" aria-selected="false">""" + user + """</a>"""   
    html += """</div>"""
    html += """<div class="tab-content mx-auto" id="v-pills-tabContent" style="height: 100%;">"""
    for user in conversationUsers:
        
        html += """ <div class="tab-pane fade w-80" id="v-pills-""" + user +"""" role="tabpanel" aria-labelledby="v-pills-""" + user + """-tab">"""
        for msg in messageList:
            if any(string.lower() in msg['message'].lower() for string in filter_strings):
                continue
            if (user == username):
                if(msg['receiver'] == user and msg['sender'] == user):
                    html += """ <div class="broadcast_container container">
                        <p>"""
                    html +=  markdown.markdown(msg['message']) 
                    html +=  """</p>
                        <span class="time-right">""" 
                    html += msg['sender']
                    html += ": " 
                    html += str(time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime(int(float(msg['timestamp'])))))

                    html += """</span>
                            </div> """

            elif(msg['receiver'] == user):
                html += """ <div class="broadcast_container container">
	                <p>"""
                html +=  markdown.markdown(msg['message']) 
                html +=  """</p>
	                <span class="time-right">""" 
                html += msg['sender']
                html += ": " 
                html += str(time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime(int(float(msg['timestamp'])))))
                html += """</span>
        	            </div> """
            elif (msg['sender'] == user):
                html += """ <div class="broadcast_container container darker ">
	                <p>"""
                html +=  markdown.markdown(msg['message']) 
                html +=  """</p>
	                <span class="time-left">""" 
                html += msg['sender']
                html += ": " 
                html += str(time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime(int(float(msg['timestamp'])))))
                html += """</span>
        	            </div> """
        html += "<form action=\"/send_private\" method=\"post\" enctype=\"multipart/form-data\">"
        html += """<div class="form-group">
                    <label for="message"><strong>Message:</strong></label>
                    <input type="hidden" id="prevurl" name="previous" value="private">
                    <input type="hidden" id="recipient" name="recipient" value=\"""" + user + """\">
                    <textarea class="form-control" class="rounded" rows="5" id="message" name="message"></textarea>
                    </div>"""
        html += '<input type="submit" value="Send"/></form>'
        html += """</div>"""

    html += """</div>
                </div>
                </div>"""    
    return html

def decryptString(message_string, privatekey_hex_str):
    try:
        privkey = nacl.signing.SigningKey(privatekey_hex_str, encoder=nacl.encoding.HexEncoder)
        privkey = privkey.to_curve25519_private_key()
        msg = bytes(message_string, 'utf-8')
        unseal = nacl.public.SealedBox(privkey)
        msg = unseal.decrypt(msg, encoder=nacl.encoding.HexEncoder)
        msg = msg.decode('utf-8')
        return msg
    except Exception as e:
        print(e)
        return False



#Returns a messages involving the user in order of timestamp
def getConversations(username):
    localmessages = sql_funcs.getLocalPrivateMessagesfromUser(username)
    externalmessages = sql_funcs.getMessagesToUser(username)
    messageList = []
    for message in localmessages:
        content = {
            "sender" : message[0],
            "receiver" : message[1],
            "message" : message[2],
            "timestamp" : message[3]
        }
        messageList.append(content)
    for message in externalmessages:
        enc_message = message[3]
        target_pubkey = message[1]
        keypairs = sql_funcs.getKeyPairsforUser(username)
        privkey = ''

        for keypair in keypairs:
            if(keypair[0] == target_pubkey):
                privkey = keypair[1]
                break
        if(privkey):
            msg = decryptString(enc_message, privkey)
        else:
            msg= "**NO KEY FOR MSG: CANNOT DISPLAY**"

        content = {
            "sender" : message[0].split(",")[0],
            "receiver" : message[2],
            "message" : msg,
            "timestamp" : message[4]
        }
        messageList.append(content)
    messageList = sorted(messageList, key=lambda k: k['timestamp'])
  
    return messageList

def getKeysforUser(username):
    keypairs =  sql_funcs.getKeyPairsforUser(username)
    if(len(keypairs) > 0):
        return keypairs
    else:
        return False
def displayAccountInfo():
    filterWords = [word[0] for word in sql_funcs.getFilterWordForUser(cherrypy.session['username'])]
    blockedUsers = [user[0] for user in sql_funcs.getBlockedUsers(cherrypy.session['username'])]
    html =  """<div class="jumbotron text-center" style="background-color: #e3f2fd;">
                <h1>Account Settings</h1>
                </div>
            """
    html += "<div class='container'><div class='row'><h2>Set Report Status</h2></div>"
    statuses = ['online', 'away', 'busy', 'offline']
    html += "<div class='row'>"
    for status in statuses:
        html += """<div class='col'><form action="/setstatus" method="post" enctype="multipart/form-data">
                    <button type='submit' class='btn btn-primary' name='status' value='""" + status + "'>" + status + """</button>
                    </form></div>"""
    html += "</div>"


    html += "<div class='row'><h2>Message/Broadcast Filtering</h2></div>"
    html += "<div class='row'><p>Any messages or broadcasts containing the filter words will not be displayed</p></div>"
    html += """<div class='row'><div class='col-lg'><form action="/addfilter" method="post" enctype="multipart/form-data">
          <div class="form-group">
            <label for="filter-word" class="col-form-label">Word to add:</label>
            <input type="text" name="filterstring" class="form-control" id="filter-word">
            <button type="submit" class="btn btn-primary">Add Filter</button>
          </div>
    </form>"""
    html += """<form action="/removefilter" method="post" enctype="multipart/form-data">
          <div class="form-group">
            <label for="filter-word" class="col-form-label">Word to remove:</label>
            <input type="text" name="filterstring" class="form-control" id="filter-word">
            <button type="submit" class="btn btn-primary">Remove Filter</button>
          </div>
    </form></div>"""
    html += "<div class='col-lg><table class='table'><thead><th scope='col'><strong>Filtered Words:</strong></th></thead><tbody>"
    for word in filterWords:
        html += "<tr><td><p>" + word + "</p></td></tr>"
    html += "</tbody></table></div></div>"
    html += "<div class='row'><h2>User Filtering</h2></div>"
    html += """<div class='row'><div class='col-lg'><form action="/blockuser" method="post" enctype="multipart/form-data">
          <div class="form-group">
            <label for="filter-word" class="col-form-label">User to block:</label>
            <input type="text" name="blockeduser" class="form-control" id="filter-word">
            <input type="hidden" name="unblock" value="0">
            <button type="submit" class="btn btn-primary">Block User</button>
          </div>
    </form>"""
    html += """<form action="/blockuser" method="post" enctype="multipart/form-data">
          <div class="form-group">
            <label for="filter-word" class="col-form-label">Users to unblock:</label>
            <input type="text" name="blockeduser" class="form-control" id="filter-word">
            <input type="hidden" name="unblock" value="1">
            <button type="submit" class="btn btn-primary">Unblock User</button>
          </div>
    </form></div>"""
    html += "<div class='col-lg><table class='table'><thead><th scope='col'><strong>Blocked Users:</strong></th></thead><tbody>"
    for user in blockedUsers:
        html += "<tr><td><p>" + user + "</p></td></tr>"
    html += "</tbody></table></div></div>"
    return html
    
def encryptPrivateData(password):
    return 1