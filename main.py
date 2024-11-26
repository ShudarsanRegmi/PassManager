from cryptography.fernet import Fernet
from pprint import pprint
import sqlite3
from sqlite3.dbapi2 import Cursor,OperationalError
import pyperclip
import hashlib
import random
import string
from getpass import getpass
import os
from subprocess import Popen, PIPE


encoding = "UTF-8"

print("""
-----------------------------------------------
 ____                                     _
|  _ \ __ _ ___ _____      _____  _ __ __| |
| |_) / _` / __/ __\ \ /\ / / _ \| '__/ _` |
|  __/ (_| \__ \__ \\ V  V / (_) | | | (_| |
|_|   \__,_|___/___/ \_/\_/ \___/|_|  \__,_|

 __  __
|  \/  | __ _ _ __   __ _  __ _  ___ _ __
| |\/| |/ _` | '_ \ / _` |/ _` |/ _ \ '__|
| |  | | (_| | | | | (_| | (_| |  __/ |
|_|  |_|\__,_|_| |_|\__,_|\__, |\___|_|
                          |___/
---------------------------------------------
 """)

class PasswordManager():
    @staticmethod
    def saveNewData(appName,username,password):
        try:
            appName =  bytes.decode(cipher_suite.encrypt(bytes(appName,encoding)),encoding)
            username = bytes.decode(cipher_suite.encrypt(bytes(username,encoding)),encoding)
            password = bytes.decode(cipher_suite.encrypt(bytes(password,encoding)),encoding)
            insertQuery = f"""INSERT INTO accounts (app,username,password) values ("{appName}","{username}","{password}")"""
            conn.execute(insertQuery)
            conn.commit()
            print("---------------------------------------")
            print("Credentials were saved successfully!! ")
            print("---------------------------------------")
        except OperationalError as e:
            print("[ERROR: ]",e)
    @staticmethod
    def getUserPassword(appListNo):
        fetchQuery = f"""SELECT * FROM accounts WHERE pwId={appListNo}"""
        try:
            result = conn.execute(fetchQuery).fetchall()
            #displayig the fetched result
            #print(result)
            return (pm.decrypt(result[0][1]),pm.decrypt(result[0][2]),pm.decrypt(result[0][3]))
        except IndexError:
            print("No credentials found")
        except Exception as e:
           print(e)
    @staticmethod
    def getServicelists():
        searchListQuery = "SELECT * FROM accounts"
        try:
            result = conn.execute(searchListQuery)
            dataList = result.fetchall()
            return dataList
        except Exception as e:
            print(e)
    @staticmethod
    def updateAccountDetails(accountNo):
        newUsername = input("Enter new username or Press Enter to unchange: ")
        # newPassword = input("Enter new password: ")
        if(newUsername == None or newUsername == "" or newUsername == " " or newUsername == "    "):
            service,Oldusername,Oldassword = pm.getUserPassword(accountNo)
            #service was unpacked for another feature
            newUsername = Oldusername
        newUsername = pm.encrypt(newUsername)
        print("Would you like to use randomly generated password? ")
        passGenInp = input("Press [ENTER] to generate..")
        if(passGenInp == None or passGenInp == "" or passGenInp == " " or passGenInp == "   "):
            #user want to use radomly generated password
            newPassword = pm.generatePassword()
        else:
            #user want to use his/her own password
            newPassword = input("Enter password: ")
        newPassword = pm.encrypt(newPassword)
        updateQuery = f"""UPDATE accounts SET username="{newUsername}" , password="{newPassword}" WHERE pwId={accountNo}"""
        conn.execute(updateQuery)
        conn.commit()
        print("-------------------------------------------")
        print("Credentials were updated successfully")
        print("-------------------------------------------")
    @staticmethod
    def deleteAccount(accountNo):
        deleteQuery = f"""DELETE FROM accounts WHERE pwId={accountNo}"""
        try:
            conn.execute(deleteQuery)
            conn.commit()
            print("-------------------------------------------")
            print("Account was deelted successfully")
            print("-------------------------------------------")
        except Exception as e:
            print(e)

    @staticmethod
    def changeMasterPassword():
        mpFetchQuery = "SELECT masterPassword from masterPasswordTable"
        result = conn.execute(mpFetchQuery).fetchall()
        masterPassword = result[0][0]
        # enteredMasterPassword = input("Enter current master password: ")
        enteredMasterPassword = getpass("Enter your current master password: ",stream=None)

        if(masterPassword == hashlib.sha256(bytes(enteredMasterPassword,encoding)).hexdigest()):
            #print("master password matched")

            newPassword1 = getpass("Enter your master password: ",stream=None)
            newPassword2 = getpass("Confirm your new master password: ",stream=None)

            if(newPassword1 == newPassword2):
                print("password was confirmed")
                #updating new password to the databse
                newHashedPassword = hashlib.sha256(bytes(newPassword2,encoding)).hexdigest()
                mpUpdateQuery = f"""UPDATE masterPasswordTable SET masterPassword = "{newHashedPassword}" """
                conn.execute(mpUpdateQuery)
                conn.commit()
                print("--------------------------------------------")
                print("Master password changed successfully")
                print("--------------------------------------------")
            else:
                print("Password didn't match")
        else:
            print("Incorrect master password")
    @staticmethod
    def generatePassword():
            password = ""
            while True:
                passwordLength = int(input("Enter the length of password: "))
                if(isinstance(passwordLength,int)):
                    break
            #datas
            lcaseLetters = string.ascii_lowercase
            ucaseLetters = string.ascii_uppercase
            numbers = string.digits
            puncs = string.punctuation
            while len(password) <= passwordLength:
                randomLowerCaseIndex = random.randrange(0,len(lcaseLetters))
                randomUpperCaseIndex = random.randrange(0,len(ucaseLetters))
                randomNumberIndex = random.randrange(0,len(numbers))
                randompuncIndex = random.randrange(0,len(puncs))
                password += lcaseLetters[randomLowerCaseIndex] + ucaseLetters[randomUpperCaseIndex] + numbers[randomNumberIndex] + puncs[randompuncIndex]
            password = password[:passwordLength]
            print("Generated Password = " + password)
            return password

    @staticmethod
    def decrypt(cipherText):
        return  cipher_suite.decrypt(bytes(cipherText,encoding)).decode(encoding)
    @staticmethod
    def encrypt(plainText):
        return cipher_suite.encrypt(bytes(plainText,encoding)).decode(encoding)
    @staticmethod
    def copy(data):
        with Popen(['xclip','-selection', 'clipboard'], stdin=PIPE) as pipe:
            pipe.communicate(input=data.encode('utf-8'))
pm = PasswordManager()

#creating/opening database
#os.chdir("/progs/passwordManager/")
conn = sqlite3.connect("database.db")
# creating a table to store data
try:
    conn.execute("""
                CREATE TABLE IF NOT EXISTS accounts (
                    pwId INTEGER PRIMARY KEY AUTOINCREMENT,
                    app varchar(250),
                    username varchar(250),
                    password varchar(500),
                    createdDate varchar(20) default current_timestamp
                )
                 """)
except OperationalError as e:
    print(e)
    #print("table already exists")
try:
    conn.execute("""
                 CREATE TABLE IF NOT EXISTS key (
                     key varchar(255)
                 )
                 """)
except Exception as e:
    print(e)
try:
    conn.execute("""
                 CREATE TABLE IF NOT EXISTS masterPasswordTable(
                     masterPassword varchar(255)
                 )
                 """)
except Exception as e:
    print(e)

try:
    result = conn.execute("""SELECT key FROM key""").fetchall()
    if(len(result) == 0):
        #if the key is not stored  yet
        key = Fernet.generate_key()
        stringKey = key.decode(encoding)
        keyInsertquery = f"""INSERT INTO key (key) VALUES ("{stringKey}")"""
        conn.execute(keyInsertquery)
        conn.commit()
        # print("First Insertion was success")
    else:
        key = bytes(result[0][0],encoding)
        # print("using already generated key..")

except Exception as e:
    print(e)
#creating master  password
try:
    enteredPassword = getpass("Enter your master password: ",stream=None)
    result = conn.execute(f"""SELECT masterPassword FROM masterPasswordTable""").fetchall()
    enteredPasswordhashed = hashlib.sha256(bytes(enteredPassword,encoding)).hexdigest()
    if(len(result) == 0):
        passwordInsertQuery = f"""INSERT INTO masterPasswordTable (masterPassword) VALUES ("{enteredPasswordhashed}")"""
        conn.execute(passwordInsertQuery)
        conn.commit()
        authenticated = True
        # print("password has been added to the database")
        # print("User entered password has been saved to the database for first time")
    else:
        # print("password is already there in the database")
        masterPasswordHash = result[0][0]
        if(enteredPasswordhashed == masterPasswordHash):
            authenticated = True
        else:
            authenticated = False

except KeyboardInterrupt:
    print("\nBye!")
    exit()
except Exception as e:
    print(e)
# exit()
try:
    if(authenticated):
        cipher_suite = Fernet(key)
    #initial variable
        #main loop of menu
        logtoshow = False
        while True:
            back2 = False
            if not logtoshow:
                os.system("clear")
            choice = input("""
-----MAIN MENU------
    1) Get Credentials
    2) Create Credentials
    3) Update Credentials
    4) Delete Credentials
    5) Change Master Password
    6) Quit
: """)
            if(choice == "1"):
                logtoshow = False
                serviceLists = pm.getServicelists()
                #print(serviceLists)
                for item in serviceLists:
                    print(f"[PRESS] {item[0]} to get credentials of {pm.decrypt(item[2])} on {pm.decrypt(item[1])}")
                print("[PRESS] (b) to go back")
                while True:
                    try:
                        if(back2):
                            break
                        choice2 = input("Enter your choice  : ")
                        if(choice2 != "b"):
                            service,username,password = pm.getUserPassword(choice2)
                            #print(username,password)
                            # goBack = False
                            while True:
                                choiceToCopy =  input(f"""
    ---MAIN MENU >> {service} 
    1) Get password
    2) Get username
    3) Back
    4) Quit
: """)
                                try:
                                    if(choiceToCopy == "1"):
                                        #pyperclip.copy(password)
                                        pm.copy(password);
                                        print("--------------------------------------------")
                                        print("Password has been copied to clipboard")
                                        print("--------------------------------------------")
                                    elif choiceToCopy == "2":
                                        pm.copy(username);
                                        print("--------------------------------------------")
                                        print("Username has been copied to clipboard")
                                        print("--------------------------------------------")
                                    elif choiceToCopy == "3":
                                        back2 = True
                                        break
                                    elif choiceToCopy == "4" or choiceToCopy == "q" or choiceToCopy == "Q":
                                        print("Bye!")
                                        exit()
                                    elif choiceToCopy == "b" or choiceToCopy=="back":
                                        break
                                    else:
                                        break
                                except ValueError:
                                    print("Invalid Option")
                                    break
                        elif choice2=="b":
                            # goBack = True
                            break
                    except TypeError:
                        print("Invalid Option")

            if(choice == "2"):
                appName = input("Enter app/service name: ")
                username = input("Enter username: ")
                print("Would you like to use randomly generated password? ")
                passGenInp = input("Press [ENTER] to generate..")
                if(passGenInp == None or passGenInp == "" or passGenInp == " " or passGenInp == "   "):
                    #user want to use radomly generated password
                    print("User want to use randomly generated password")
                    password = pm.generatePassword()
                else:
                    #user want to use his/her own password
                    password = input("Enter password: ")

                pm.saveNewData(appName,username,password)
                logtoshow = True


            if(choice == "3"):
                serviceLists = pm.getServicelists()
                for item in serviceLists:
                    print(f"Press {item[0]} to update credentials of {pm.decrypt(item[2])} on {pm.decrypt(item[1])}")
                choice = input(": ")
                pm.updateAccountDetails(choice)
                logtoshow = True

            if(choice == "4"):
                serviceLists = pm.getServicelists()
                for item in serviceLists:
                    print(f"Press {item[0]} to delete account {pm.decrypt(item[2])} on {pm.decrypt(item[1])}")
                choice = input(": ")
                pm.deleteAccount(choice)
                logtoshow = True

            if(choice == "5"):
                pm.changeMasterPassword()
                logtoshow = True
            if choice == "6":
                print("Bye!")
                break
    else:
        print("Incorrect Password")
except KeyboardInterrupt:
    print("\nBye!")
except Exception as e:
    print(e)
    print("Something Went Wrong!!")

