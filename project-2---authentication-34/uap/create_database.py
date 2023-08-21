import sqlite3
from sqlite3 import Error
import os
import sys

def create_connection(db_file):
    conn = None
    try:
        conn = sqlite3.connect(db_file)
        return conn
    except Error as e:
        print(e)

    return conn


def create_table(conn, create_table):
    try:
        c = conn.cursor()
        c.execute(create_table)
    except Error as e:
        print(e)


def main():
    
    baseDir = os.path.dirname(os.path.abspath(__file__))
    database = os.path.join(baseDir, sys.argv[1])
    print(database)

    users_table = """CREATE TABLE IF NOT EXISTS accounts (
                                    user_id integer PRIMARY KEY AUTOINCREMENT,
                                    user text NOT NULL,
                                    password text NOT NULL,
                                    dns text NOT NULL,
                                    iv text NOT NULL,
                                    salt text NOT NULL
                                );"""                                                                                         

    # create a database connection
    conn = create_connection(database)

    # create tables
    if conn is not None:

        # create tables
        create_table(conn, users_table)

    else:
        print("Error! cannot create the database connection.")



if __name__ == '__main__':
    main()