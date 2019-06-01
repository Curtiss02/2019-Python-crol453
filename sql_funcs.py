import sqlite3
import os
db = os.getcwd() + '/db/stuff.db'   



def create_user(username):


    conn = sqlite3.connect(db)
    sql = ''' INSERT INTO users(username)
              VALUES(?) '''
    cur = conn.cursor()
    cur.execute(sql, username)
    conn.commit()


def add_broadcast(record, message, timestamp, signature):
    """
    Adds a new broadcast into the broadcast table
    In future will not add duplicate/same timestamp broadcasts
    """
    data = (record, message, timestamp, signature)
    conn = sqlite3.connect(db)
    sql = ''' INSERT INTO broadcasts(loginserver_record, message, timestamp, signature)
              VALUES(?,?,?,?) '''
    cur = conn.cursor()
    cur.execute(sql, data)
    conn.commit()
    print("\nSQL DONE BOSS\n")
        
    return 1
def add_user_info(username, apikey, OTPsecret = None):
    return 1

def updateUserList(userList):
    for user in userList:

        username = user['username']
        lastActive = str(user['connection_updated_at'])
        connection_address = user['connection_address']
        connection_location = str(user['connection_location'])
        pubkey = user['incoming_pubkey']
        status = user['status']

        data = (username, connection_address, connection_location, pubkey, status, lastActive)
        conn = sqlite3.connect(db)
        sql = ''' INSERT INTO userlist (Username, connection_address, connection_location, publickey, status, lastseen)
              VALUES(?,?,?,?,?,?) '''
        cur = conn.cursor()
        cur.execute(sql, data)
        conn.commit()
        

def get_broadcasts():
    conn = sqlite3.connect(db)
    sql = "SELECT * FROM broadcasts ORDER BY timestamp DESC"
    cur = conn.cursor()
    cur.execute(sql)
    rows = cur.fetchall()
    conn.commit()
    return rows