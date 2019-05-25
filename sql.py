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
    return conn
    sql = ''' INSERT INTO users(username)
              VALUES(?,?,?) '''
    cur = conn.cursor()
    cur.execute(sql, username)
    return cur.lastrowid