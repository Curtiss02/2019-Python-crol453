import sql_funcs
import http_funcs
import os
import nacl
import http_funcs
import json
import loginserver_api

IP = ''
LOCATION = ''
with open('cfg/ip.ini') as json_file:
    ip_data = json.load(json_file)
    IP = ip_data['SERVER_IP']
    LOCATION = ip_data['SERVER_LOCATION']


def main():
    updateStatus()


def updateStatus():
    onlineUsers = sql_funcs.get_all_users()
    for user in onlineUsers:
        publicKey = user[2]
        api_key = user[1]
        username = user[0]
        #create HTTP BASIC authorization header
        headers = http_funcs.getAuthenticationHeader(username, api_key)
        data = loginserver_api.report(LOCATION, str(IP), publicKey, "online", headers)
