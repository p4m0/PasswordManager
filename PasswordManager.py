# -*- coding: utf-8 -*-
"""
Created on Thu Mar  7 12:20:06 2024

@author: PM
"""
import sys
from getpass import getpass
import os
import pyperclip
from GeneratePassword import generate_password
from DatabaseFunctions import (connect_to_db, initialize_database, add_service,
 delete_service, get_service_pass, add_user, authenticate_user, delete_all_user_services,
 get_all_user_services, delete_user, view_all_tables, get_all_user_data, get_all_users,
 get_all_service_data)

database_name = "PasswordManager.db"
 
def is_empty(username, password):
    if (len(username)) == 0 or (len(password)) == 0:
        print("Username or password can't be empty")
        return False
    else:
        return True
    
def main():
    initialize_database(database_name)
    info_message = """Password manager commands:
    (commands) - display this info message
    (exit) - exit the program
    (add user) - create a new user
    (log in) - login with an existing user
    
    requires login
    (log out) - log out the current user
    (delete user) - deletes user and all associated services, requires to be logged in
    (add service) - add service to the currently logged in user
    (delete service) - delete service from the currently logged in user'
    (get service password) - gets the password for the service and copies it to clipboard
    (view services) - views all of the user's services
    
    ### DEBUG COMMANDS BELOW ###
    These would be deleted in the final product, but I'd rather leave them here
    for testing purposes. Try them!
    debug:
        (at) alltables
        (as) allservices
        (au) allusers
          
    """
    print(info_message)
    logged_in_as = None
    not_logged_in_cmds = ["add user", "log in", "exit"]
    logged_in_cmds = ["log out", "delete user", "add service", "get service password", "view services", "delete service", "exit"]
    debug_cmds = ["at", "as", "au"]
    while True:
        cmd = input("> Enter command: ")
        if cmd == "at":
            view_all_tables(database_name)
        elif cmd == "as":
            get_all_service_data()
        elif cmd == "au":
            get_all_users()
        elif cmd == "exit":
            sys.exit(0)
        elif cmd == "commands":
            print(info_message)
            continue
        
        #invalid: invalid command
        if (cmd not in logged_in_cmds) and (cmd not in not_logged_in_cmds) and \
            (cmd not in debug_cmds):
            print("Invalid command")
        #invalid: using logged in commands when not logged in
        elif logged_in_as == None and (cmd in logged_in_cmds):
            print("You must be logged in")
        #invalid: using unlogged commands when logged in
        elif logged_in_as != None and (cmd in not_logged_in_cmds):
            print("This operation can only be done when you're not logged in.")
        elif (cmd in not_logged_in_cmds) and logged_in_as == None:
            if cmd == "add user":
                username = input("Username: ")
                gen_pass = input("Would you like to generate a safe password? (Y/N) ")
                if gen_pass == "Y" or gen_pass == "y":
                    password = generate_password()
                    pyperclip.copy(password)
                    print("Password copied to clipboard. Save it somewhere!")
                elif gen_pass == "N" or gen_pass == "n":
                    password = getpass("Password: ")
                else:
                    print("Invalid input.")
                    continue
                add_user(username, password)
                continue
            elif cmd == "log in":
                username = input("Username: ")
                password = getpass("Password: ")
                if authenticate_user(username, password):
                    logged_in_as = username
                else:
                    continue
            #TODO LOGGED FUNC
        elif (cmd in logged_in_cmds) and logged_in_as != None:
            if cmd == "delete user":
                if  delete_user(logged_in_as):
                    logged_in_as = None
            elif cmd == "add service":
                servicename = input("Service name: ")
                serviceusername = input("Service username: ")
                servicepass = getpass("Service password: ")
                add_service(logged_in_as, servicename, serviceusername, servicepass)
                
            elif cmd == "get service password":
                servicename = input("Service name: ")
                get_service_pass(logged_in_as, servicename)
            elif cmd == "view services":
                get_all_user_services(logged_in_as)
            elif cmd == "delete service":
                servicename = input("Service name: ")
                delete_service(logged_in_as, servicename)
            elif cmd == "log out":
                logged_in_as = None
                print("Logged out")
            else:
                print("Invalid command") 

if __name__ == "__main__":
    main()


