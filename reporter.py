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

IP = ''
LOCATION = ''
with open('cfg/ip.ini') as json_file:
    ip_data = json.load(json_file)
    IP = ip_data['SERVER_IP']
    LOCATION = ip_data['SERVER_LOCATION']


def main():
    updateStatus()
    updateUserList()
    pingCheckAll()

def pingCheckAll():
    userList = sql_funcs.getUserList()
    usernames = [user[0] for user in userList]
    print(usernames)
    for userinfo in userList:
        print("Ping checking " + userinfo[0])
        pingthread = Thread(target=pingCheck, args=[userinfo, usernames])
        pingthread.start()
        

def pingCheck(userinfo, usernames):
    #Cant ping_check login server
    url = "http://" + userinfo[1] + "/api/ping_check"
    print(userinfo)
    if(userinfo[0] == "admin"):
        try:
            data = loginserver_api.ping()
            print(data)
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
        url = "http://localhost:8080/api/ping_check"    
    mytime = time.time()
    payload = {
        "my_time" : str(mytime),
        "my_active_usernames" : "a",
        "connection_address" : IP,
        "connection_location" : LOCATION
        }
    try:
        data =  http_funcs.sendJsonRequest(url, payload=payload)
        print(data)
        if(data['response'] == 'ok'):
            sql_funcs.updateUserReachable(userinfo[0], "Yes!")
            return
    except:
        sql_funcs.updateUserReachable(userinfo[0], "No")
        return
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
            
        


def updateStatus():
    onlineUsers = sql_funcs.get_all_client_users()
    for user in onlineUsers:
        publicKey = user[2]
        api_key = user[1]
        username = user[0]
        #create HTTP BASIC authorization header
        headers = http_funcs.getAuthenticationHeader(username, api_key)
        data = loginserver_api.report(LOCATION, str(IP), publicKey, "online", headers)
