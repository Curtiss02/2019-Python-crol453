#!/usr/bin/python3
""" main.py

    COMPSYS302 - Software Design - Example Client Webapp
    Current Author/Maintainer: Hammond Pearce (hammond.pearce@auckland.ac.nz)
    Last Edited: March 2019

    This program uses the CherryPy web server (from www.cherrypy.org).
"""
# Requires:  CherryPy 18.0.1  (www.cherrypy.org)
#            Python  (We use 3.5.x +)

import os

import socket

import cherrypy

import server

import api

import sqlite3

import reporter

from sqlite3 import Error


# The address we listen for connections on
 
#Grabs the primary local IP for the system in order to host the server

LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 10000

def runMainApp():
    #set up the config
    conf = {
        '/': {
            'tools.staticdir.root': os.getcwd(),
            'tools.encode.on': True, 
            'tools.encode.encoding': 'utf-8',
            'tools.sessions.on': True,
            'tools.sessions.timeout':60* 1, #timeout is in minutes, * 60 to get hours

            # The default session backend is in RAM. Other options are 'file',

        },

        #configuration for the static assets directory
        '/static': { 
            'tools.staticdir.on': True,
            'tools.staticdir.dir': 'static',
        },
        
        #once a favicon is set up, the following code could be used to select it for cherrypy
        '/favicon.ico': {
            'tools.staticfile.on': True,
            'tools.staticfile.filename': os.getcwd() + '/static/favicon.ico',
        },

    }

    cherrypy.site = {
        'base_path': os.getcwd()
    }

    # Create an instance of MainApp and tell Cherrypy to send all requests under / to it. (ie all of them)
    cherrypy.tree.mount(server.MainApp(), "/", conf)
    #Mount API handler
    cherrypy.tree.mount(api.MainApp(), "/api/", conf)

    # Tell cherrypy where to listen, and to turn autoreload on
    cherrypy.config.update({'server.socket_host': LISTEN_IP,
                            'server.socket_port': LISTEN_PORT,
                            'engine.autoreload.on': True,
                           })

    #cherrypy.tools.auth = cherrypy.Tool('before_handler', auth.check_auth, 99)

    print("crol453 Python Webserver")                 

    #Start the routine background tasks
    cherrypy.engine.reporter = cherrypy.process.plugins.BackgroundTask(120, reporter.main)
    cherrypy.engine.reporter.start()
    # Start the web server
    cherrypy.engine.start()

    # And stop doing anything else. Let the web server take over.
    cherrypy.engine.block()
 
def setupDB():
    db = os.getcwd() + '/db/stuff.db'     


    db_commands=[
        """CREATE TABLE IF NOT EXISTS broadcasts (
    loginserver_record TEXT,
    message            TEXT,
    timestamp          REAL,
    signature          TEXT,
    UNIQUE (
        message,
        timestamp
    )
    ON CONFLICT REPLACE
);
""",
"""CREATE TABLE IF NOT EXISTS filter (
    username TEXT,
    string   TEXT
);
""",
"""CREATE TABLE IF NOT EXISTS keys (
    username   TEXT,
    publickey  TEXT UNIQUE ON CONFLICT REPLACE,
    privatekey TEXT PRIMARY KEY
                    UNIQUE ON CONFLICT REPLACE
);
""",
"""CREATE TABLE IF NOT EXISTS localprivatemessages (
    sender    TEXT,
    receiver  TEXT,
    message   TEXT,
    timestamp REAL
);
""",
"""CREATE TABLE IF NOT EXISTS privatemessages (
    loginserver_record TEXT,
    target_pubkey      TEXT,
    target_username    TEXT,
    encrypted_message  TEXT,
    timestamp          REAL,
    signature          TEXT,
    UNIQUE (
        target_pubkey,
        target_username,
        encrypted_message,
        timestamp
    )
    ON CONFLICT REPLACE
);
""",
"""CREATE TABLE IF NOT EXISTS userlist (
    Username            TEXT PRIMARY KEY ON CONFLICT REPLACE,
    connection_address  TEXT DEFAULT unknown
                             NOT NULL ON CONFLICT IGNORE,
    connection_location TEXT,
    publickey           TEXT,
    status              TEXT,
    lastseen            TEXT,
    reachable           TEXT DEFAULT Unknown
);
""",
"""CREATE TABLE IF NOT EXISTS users (
    username           TEXT PRIMARY KEY ON CONFLICT REPLACE
                            NOT NULL,
    api_key            TEXT,
    public_key         TEXT,
    loginserver_record TEXT,
    status             TEXT DEFAULT online
);
""",
"""CREATE TABLE IF NOT EXISTS blockedusers (
    username    TEXT,
    blockeduser TEXT,
    UNIQUE (
        username,
        blockeduser
    )
    ON CONFLICT REPLACE
);
"""
    ]  
    try:
        conn = sqlite3.connect(db)
        for sql in db_commands:
            cur = conn.cursor()
            cur.execute(sql)
            conn.commit()
                                        
    except Error as e:
        print(e)
    finally:
        conn.close()


if __name__ == '__main__':
    setupDB()
    runMainApp()
