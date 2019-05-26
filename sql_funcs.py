import sqlite3
import os
db = os.getcwd() + '/db/stuff.db'   

def create_user(username):
    """
    Create a new project into the projects table
    :param conn:
    :param project:
    :return: project id
    """

    conn = sqlite3.connect(db)
    sql = ''' INSERT INTO users(username)
              VALUES(?,?,?) '''
    cur = conn.cursor()
    cur.execute(sql, username)
    conn.commit()
    return cur.lastrowid


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