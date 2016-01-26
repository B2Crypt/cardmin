import MySQLdb

def confconnection():
    conn = MySQLdb.connect(host="", port=, user="", passwd="", db="582_config")
    c = conn.cursor()

    return c,conn
