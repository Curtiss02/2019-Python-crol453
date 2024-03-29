import sql_funcs
import http_funcs
import os
import nacl
import http_funcs
import json
import loginserver_api
import time
import traceback
from threading import Thread
import concurrent.futures
import socket


#Reads in the IP/Location from the config file
#used for reporting user status to login server
IP = socket.gethostbyname(socket.gethostname()) + ":10000"
LOCATION = '0'


#with open('cfg/ip.ini') as json_file:
#    ip_data = json.load(json_file)
#    IP = ip_data['SERVER_IP']
#    LOCATION = ip_data['SERVER_LOCATION']

#Contains all the functions called by the reporter
def main():
    updateStatus()
    updateUserList()
    pingcheck = Thread(target=pingCheckAll)
    pingcheck.start()
    #checkmessage = Thread(target=checkMessagesAll)
    #checkmessage.start()

    #checkmessage.join(30)
    pingcheck.join()

    

#Ping checks every user on the user list, doing 20 at a time using a threadpool
def pingCheckAll():
    userList = sql_funcs.getUserList()
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        executor.map(pingCheck, userList)

#Checks for missed broadcasts/messages from other users, using a threadpool
def checkMessagesAll():
    userList = sql_funcs.getUserList()
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        executor.map(checkMessages, userList)

#Checks for missed messages and broadcasts at the given ip    
def checkMessages(userinfo):
    mytime = time.time()
    url = "http://" + userinfo[1] + "/api/checkmessages"
    payload = {
        "since" : mytime
    }
    try:
        data = http_funcs.sendJsonRequest(url, payload=payload)

    except Exception as e:
        return
    try:
        if[data['response'] == 'ok']:
            broadcasts = data['broadcasts']
            messages = data['private_messages']
            for broadcast in broadcasts:
                data = http_funcs.sendJsonRequest("http://localhost:10000/api/rx_broadcast", payload=broadcast)
            for message in messages:
                data = http_funcs.sendJsonRequest("http://localhost:10000/api/rx_privatemessage", payload=message)
        else:
            return
    except Exception as e:
        print(e)
        return
#Performs a pingcheck on the given user
def pingCheck(userinfo):
    #Cant ping_check login server
    #print("Ping checking: " + userinfo[0])
    try:
        url = "http://" + userinfo[1] + "/api/ping_check"
        if(userinfo[0] == "admin"):
            try:
                data = loginserver_api.ping()
                if(data['response'] == 'ok'):
                    sql_funcs.updateUserReachable(userinfo[0], "Yes!")
                else:
                    sql_funcs.updateUserReachable(userinfo[0], "Error")
                return
            except:
                sql_funcs.updateUserReachable(userinfo[0], "No")
                return
        #Cant reach server via own external ip on host machine
        if(userinfo[1] == IP):
            url = "http://localhost:10000/api/ping_check"    
        mytime = time.time()
        payload = {
            "my_time" : str(mytime),
            "my_active_usernames" : "a",
            "connection_address" : IP,
            "connection_location" : LOCATION
            }
        try:
            data =  http_funcs.sendJsonRequest(url, payload=payload)
            if(data['response'] == 'ok'):
                sql_funcs.updateUserReachable(userinfo[0], "Yes!")
                return
        except:
            sql_funcs.updateUserReachable(userinfo[0], "No")
            return
    except:
        pass

#Updates the userlist page in the background, to prevent long load times for users
def updateUserList():
    #Can only do if atleast one user is online
    online_users = sql_funcs.get_all_client_users()
    
    if(online_users):
        #grab the first user, use credentials to update user list in background
        user = online_users[0]
        api_key = user[1]
        username = user[0]
        try:
            headers = http_funcs.getAuthenticationHeader(username, api_key)
            data = loginserver_api.list_users(headers)
            userList = data['users']
            sql_funcs.updateUserList(userList)
            print("updated user list!")
        except Exception as e:
            print("userlist update failed")
            print(e)
            
        

#Updates clients users' status to whatever they have set on their account preferences: defaults to online
def updateStatus():
    onlineUsers = sql_funcs.get_all_client_users()
    for user in onlineUsers:
        publicKey = user[2]
        api_key = user[1]
        username = user[0]
        status = user[4]
        #create HTTP BASIC authorization header
        headers = http_funcs.getAuthenticationHeader(username, api_key)
        data = loginserver_api.report(LOCATION, str(IP), publicKey, status, headers)
        if(data == 1):
            sql_funcs.remove_client_user(username)

