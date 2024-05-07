import sqlite3
import os
import pyperclip
from Security import (hash_password, verify_password, generate_masterkey,
                      encrypt, decrypt)

database_name = "PasswordManager.db"

# connects to database and returns the connection and cursor
def connect_to_db(database):
    try:
        con = sqlite3.connect(database)
        cur = con.cursor()
        return con, cur
    except Exception as e:
        print("Error connecting to db:", e)

# creates a database if it doesn't already exist
def initialize_database(database_name):
    if not os.path.exists(database_name):   
        con, cur = connect_to_db(database_name)
        con.execute("PRAGMA foreign_keys = 1")
        """
        ID - unique number
        username - username
        masterpassword - password used to authenticate user
        masterkey - key derived from the master password that is used
                    to encrypt/decrypt service passwords
        salt - salt used when generating masterkey
        """
        cur.execute("""CREATE TABLE users (
                ID INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                masterpassword TEXT NOT NULL,
                masterkey TEXT NOT NULL,
                salt TEXT NOT NULL
                );""")
    
        cur.execute("""CREATE TABLE servicepasswords (
                masteruser TEXT NOT NULL,
                servicename TEXT NOT NULL,
                serviceuser TEXT NOT NULL,
                password TEXT NOT NULL
                );""")
        con.commit()
        con.close()
        print("Database", database_name, "created")
    else:
        print(database_name, "already exists")
       
#adds a service to the servicepasswords databse
def add_service(masteruser, servicename, serviceusername, servicepass):
    if len(servicename) < 1:
        print("Service name can't be empty")
        return
    
    con, cur = connect_to_db(database_name)
    cur.execute("SELECT * FROM servicepasswords WHERE masteruser=? AND servicename =?", (masteruser,servicename))
    service_exists = cur.fetchone()
    if service_exists:
        print("you already have a password for the service")
    else:
        cur.execute("SELECT masterkey FROM users WHERE username=?", (masteruser,))
        masterkey = cur.fetchone()[0]
        enc_password = encrypt(masterkey, servicepass)
        cur.execute("INSERT INTO servicepasswords (masteruser, servicename, serviceuser, password) VALUES (?, ?, ?, ?)", 
                    (masteruser, servicename ,serviceusername, enc_password))
        con.commit()
        print("Service added")
    con.close()
 
# deletes the specified service from the database
def delete_service(masteruser, servicename):
    con, cur = connect_to_db(database_name)
    cur.execute("SELECT * FROM servicepasswords WHERE masteruser=? AND servicename=?", (masteruser,servicename))
    service_exists = cur.fetchone()
    if service_exists:
        #cur.execute("DELETE * FROM servicepasswords WHERE masteruser=? AND servicename=?", (masteruser,servicename))
        cur.execute("DELETE FROM servicepasswords WHERE masteruser=? AND servicename=?", (masteruser,servicename))
        con.commit()
        print("Service and its data deleted")
    else:
        print("Service doesn't exist")
    con.close()
   
#retrieves and decrypts the password
def get_service_pass(masteruser, servicename):
    con, cur = connect_to_db(database_name)
    
    cur.execute("SELECT masterkey FROM users WHERE username=?", (masteruser,))
    masterkey_exists = cur.fetchone()
    #this should never happen
    if masterkey_exists == None:
        print("User is missing master key")
        return
    else:
        masterkey = masterkey_exists[0]
    
    enc_pass = cur.execute("SELECT password FROM servicepasswords WHERE masteruser=? and servicename=?", (masteruser,servicename))
    #cur.fetchone() == None if service doesn't exist
    service_exists = cur.fetchone()

    if service_exists is None:
        print("No such service.")
        con.close()
    else:
        enc_pass = cur.execute("SELECT password FROM servicepasswords WHERE masteruser=? and servicename=?", (masteruser,servicename))
        enc_pass = cur.fetchone()[0]
        dec_pass = decrypt(masterkey, enc_pass)
        con.close()
        pyperclip.copy(dec_pass)
        print("Password copied to clipboard")

#adds the user and checks that the credentials adhere to the specified rules
def add_user(username, password):
    if not 1 <= len(username) <= 24:
        print("Username too short or too long")
        return
    if not 8 <= len(password) <= 64:
        print("Password too short or too long")
        return
        
    con, cur = connect_to_db(database_name)
    cur.execute("SELECT * FROM users WHERE username=?", (username,))
    existing_user = cur.fetchone()
    if existing_user:
        #TODO fix error message to give less info
        print("User already exists")
    else:
        hashed_password = hash_password(password)
        salt = os.urandom(16)
        masterkey = generate_masterkey(password, salt)
        cur.execute("INSERT INTO users (username, masterpassword, masterkey, salt) VALUES (?, ?, ?, ?)", (username, hashed_password, masterkey, salt))
        con.commit()
        print("User added")
    con.close()
 
#aunthenticates the user by comparing the argon2id hashes
def authenticate_user(username, provided_password):
    con, cur = connect_to_db(database_name)
    cur.execute("SELECT * FROM users WHERE username=?", (username,))
    user_data = cur.fetchone()
    con.close()
    if user_data:
        #compare provided hash with saved hash of password
        stored_hashed_password = user_data[2] #3rd column
        # Comparing the hashed passwords
        if verify_password(stored_hashed_password, provided_password):
            print("Authentication success. Logged in.")
            return True
        else:
            #No information about whether the account exists or about the password should
            #be given in error messages
            print("Authentication failed.")
            return False
    else:
        print("Authentication failed.")
        return False

#deletes all user services. Called when deleting a user.
def delete_all_user_services(username):
    con, cur = connect_to_db(database_name)
    cur.execute("SELECT * FROM servicepasswords WHERE masteruser=?", (username,))
    service_exists = cur.fetchone()
    if service_exists:
        cur.execute("DELETE FROM servicepasswords WHERE masteruser=?", (username,))
        con.commit()
    #else:
    #    print("Error deleting: User doesn't exist")
    con.close()

#gets all user services. Used by view services command    
def get_all_user_services(username):
    con, cur = connect_to_db(database_name)
    cur.execute("SELECT * FROM servicepasswords WHERE masteruser=?", (username,))
    userdata = cur.fetchall()
    #print("debug", userdata)
    if userdata == []:
        print("No services")
    else:
        for user in userdata:
            print(user[1])
    #print(userdata)
    con.close()
    

#deletes the services and then the user  
def delete_user(username):
    #delete user and all services associated with it
    confirmation = input("Are you sure you want to delete the user and all " \
                         "data associated with it? (Y/N) ")
    if confirmation != "Y":
        print("User not deleted.")
        return False
    delete_all_user_services(username)
    con, cur = connect_to_db(database_name)
    cur.execute("SELECT * FROM users WHERE username=?", (username,))
    user_exists = cur.fetchone()
    if user_exists:
        cur.execute("DELETE FROM users WHERE username=?", (username,))
        con.commit()
        print("User deleted.")
        con.close()
        return True
    else:
        print("Error deleting user")
        con.close()
        return False
    
def view_all_tables(database):
    con, cur = connect_to_db(database)
    sql_query = """SELECT name FROM sqlite_master WHERE type='table';"""
    cur.execute(sql_query)
    print(cur.fetchall())
    con.close()
    
def get_all_user_data(username):
    con, cur = connect_to_db(database_name)
    cur.execute("SELECT * FROM users WHERE username=?", (username,))
    user_data = cur.fetchall()
    print(user_data)
    con.close()
    
def get_all_users():
    con, cur = connect_to_db(database_name)
    cur.execute("SELECT * FROM users",)
    user_data = cur.fetchall()
    print(user_data)
    con.close()

def get_all_service_data():
    con, cur = connect_to_db(database_name)
    cur.execute("SELECT * FROM servicepasswords")
    user_data = cur.fetchall()
    print(user_data)
    con.close()
    
def delete_db(database):
    os.remove(database)
    
def drop_tables(database):
    con, cur = connect_to_db(database)
    con.execute("DROP TABLE users")
    con.execute("DROP TABLE servicepasswords")
    con.close()
