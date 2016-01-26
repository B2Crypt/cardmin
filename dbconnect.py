import MySQLdb

def connection():
    conn = MySQLdb.connect(host="", port=, user="", passwd="", db="trondheim") 
    c = conn.cursor()

    return c,conn
