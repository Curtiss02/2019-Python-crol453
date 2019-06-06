import sqlite3
import os
db = os.getcwd() + '/db/stuff.db'   



def add_client_user(username, api_key, public_key, private_key, loginserver_record):

    data = (username, api_key, public_key, private_key, loginserver_record)
    conn = sqlite3.connect(db)
    sql = ''' INSERT INTO users(username, api_key, public_key, private_key, loginserver_record)
              VALUES(?,?,?,?,?) '''
    cur = conn.cursor()
    cur.execute(sql, data)
    conn.commit()
def remove_client_user(username):

    sql = '''DELETE FROM users WHERE username=?'''
    conn = sqlite3.connect(db)
    cur = conn.cursor()
    cur.execute(sql, [username])
    conn.commit()
def get_client_user(username):
    sql = '''SELECT * FROM users WHERE username=?'''
    conn = sqlite3.connect(db)
    cur = conn.cursor()
    cur.execute(sql, [username])
    user = cur.fetchall()
    conn.commit()
    return user
def get_all_client_users():
    sql = '''SELECT * FROM users'''
    conn = sqlite3.connect(db)
    cur = conn.cursor()
    cur.execute(sql)
    users = cur.fetchall()
    conn.commit()
    return users

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


    return 1


def updateUserList(userList):
    try:
        conn = sqlite3.connect(db)
        cur = conn.cursor()
        sql = "DELETE FROM userlist"
        cur.execute(sql)
        conn.commit()
        for user in userList:

            username = user['username']
            lastActive = str(user['connection_updated_at'])
            connection_address = user['connection_address']
            connection_location = str(user['connection_location'])
            pubkey = user['incoming_pubkey']
            status = user['status']

            data = (username, connection_address, connection_location, pubkey, status, lastActive)
            
            sql = ''' INSERT INTO userlist (Username, connection_address, connection_location, publickey, status, lastseen)
                VALUES(?,?,?,?,?,?) '''
            cur.execute(sql, data)

        conn.commit()
        print("SUCCESS")
    except Exception as e:
        print(e)
        return 1
def updateUserReachable(username, reachable):
    conn = sqlite3.connect(db)
    sql = """ UPDATE userlist
              SET reachable = ?
              WHERE Username = ?"""
    data = (reachable, username)
    cur = conn.cursor()
    cur.execute(sql, data)
    rows = cur.fetchall()
    conn.commit()
    print("REACHABLE UPDATED TO:", reachable, "for", username)
        
def getUserList():
    conn = sqlite3.connect(db)
    sql = "SELECT * FROM userlist"
    cur = conn.cursor()
    cur.execute(sql)
    rows = cur.fetchall()
    conn.commit()
    return rows
    
def getUserFromUserList(username):
    conn = sqlite3.connect(db)
    sql = "SELECT * FROM userlist WHERE Username = ?"
    cur = conn.cursor()
    cur.execute(sql, [username])
    rows = cur.fetchall()
    conn.commit()
    return rows

def get_broadcasts():
    conn = sqlite3.connect(db)
    sql = "SELECT * FROM broadcasts ORDER BY timestamp DESC"
    cur = conn.cursor()
    cur.execute(sql)
    rows = cur.fetchall()
    conn.commit()
    return rows
def addKeyPair(username,publicKey, privateKey):
    data = (username, privateKey, publicKey)
    conn = sqlite3.connect(db)
    sql = ''' INSERT INTO keys(username, publickey, privatekey)
              VALUES(?,?,?) '''
    cur = conn.cursor()
    cur.execute(sql, data)
    conn.commit()
def addPrivateMessage(loginserver_record, target_pubkey, target_username, encrypted_message, timestamp, signature):
    data = (loginserver_record, target_pubkey, target_username, encrypted_message, timestamp, signature)
    conn = sqlite3.connect(db)
    sql = ''' INSERT INTO privatemessages(loginserver_record, target_pubkey, target_username, encrypted_message, timestamp, signature)
              VALUES(?,?,?,?,?,?) '''
    cur = conn.cursor()
    cur.execute(sql, data)
    conn.commit()
def getKeyPairsforUser(username):
    data = [username]
    conn = sqlite3.connect(db)
    sql = '''SELECT publickey, privatekey FROM keys WHERE username = ?'''
    cur = conn.cursor()
    cur.execute(sql, data)
    rows = cur.fetchall()
    conn.commit()
    return rows
def getMessagesToUser(username):
    data = [username]
    conn = sqlite3.connect(db)
    sql = '''SELECT * FROM privatemessages WHERE target_username = ?'''
    cur = conn.cursor()
    cur.execute(sql, data)
    rows = cur.fetchall()
    conn.commit()
    return rows
def addLocalPrivateMessage(sender, receiver, message, timestamp):
    data = (sender, receiver, message, timestamp)
    conn = sqlite3.connect(db)
    sql = ''' INSERT INTO localprivatemessages(sender, receiver, message, timestamp)
              VALUES(?,?,?,?) '''
    cur = conn.cursor()
    cur.execute(sql, data)
    conn.commit()
def getLocalPrivateMessagesfromUser(sender):
    data = [sender]
    conn = sqlite3.connect(db)
    sql = ''' SELECT * FROM localprivatemessages WHERE sender=?'''
    cur = conn.cursor()
    cur.execute(sql, data)
    rows = cur.fetchall()
    conn.commit()
    return rows