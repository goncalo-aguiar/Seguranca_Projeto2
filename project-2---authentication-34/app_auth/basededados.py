import sqlite3
from sqlite3 import Error
import os

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
    database = os.path.join(baseDir, 'shop.db')

    comments_table = """CREATE TABLE IF NOT EXISTS comments (
                                    commentary_id integer PRIMARY KEY AUTOINCREMENT,
                                    comment text NOT NULL,
                                    author text NOT NULL
                                );"""

    users_table = """CREATE TABLE IF NOT EXISTS users (
                                    user_id integer PRIMARY KEY AUTOINCREMENT,
                                    user text NOT NULL,
                                    password text NOT NULL,
                                    balance integer
                                );"""  

    products_table =  """CREATE TABLE IF NOT EXISTS products (
                                    product_id integer PRIMARY KEY AUTOINCREMENT,
                                    name text NOT NULL,
                                    price integer
                                ); """

    orders_table = """  CREATE TABLE IF NOT EXISTS orders (
                                    order_id integer PRIMARY KEY AUTOINCREMENT,
                                    client integer,
                                    product integer,
                                    quantity integer,
                                    UNIQUE(product)
                                ); """ 

    files_table = """ CREATE TABLE IF NOT EXISTS files(
                        id integer PRIMARY KEY AUTOINCREMENT,
                        user text NOT NULL,
                        file BLOB 
                        ); """                            
    load_banana = "INSERT INTO products(name,price) values('banana',1);"
    load_maca="INSERT INTO products(name,price) values('maca',2);"
    load_laranja="INSERT INTO products(name,price) values('laranja',3);"
    load_pera="INSERT INTO products(name,price) values('pera',4);"
    load_manga="INSERT INTO products(name,price) values('manga',5);"
    load_kiwi="INSERT INTO products(name,price) values('kiwi',6);"
    
    check_products = "SELECT * FROM products"                                                                   

    # create a database connection
    conn = create_connection(database)

    # create tables
    if conn is not None:

        # create tables
        create_table(conn, comments_table)
        create_table(conn, users_table)
        create_table(conn, products_table)
        create_table(conn, orders_table)
        create_table(conn, files_table)

    else:
        print("Error! cannot create the database connection.")
    
    
    with sqlite3.connect(database) as conn:
        r=conn.execute(check_products)
        s = r.fetchall()
        if s==[]:
            r=conn.execute(load_banana)
            r=conn.execute(load_maca)
            r=conn.execute(load_laranja)
            r=conn.execute(load_pera)
            r=conn.execute(load_manga)
            r=conn.execute(load_kiwi)


if __name__ == '__main__':
    main()