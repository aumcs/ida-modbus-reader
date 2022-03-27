"""
    Tawannnnnnnn :)
    modbus_ida - webapp.py
    Main Python scripts for web application & modbus TCP/IP reader from
    * NECTEC's uRCONNECT.
    * Power meter that connected to uRCONNECT.
    * Melsec C Intelligent database.
"""

import os
import re
import sys
import glob
import time
import json
import wget
import random
import string
import struct
import pyping
import logging
import requests
import platform
import win_inet_pton
import mysql.connector as MySQL

from threading import Thread
from pytz import timezone, utc
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from ConfigParser import SafeConfigParser
from pyModbusTCP.client import ModbusClient
from logging.handlers import RotatingFileHandler
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_required ,UserMixin, login_user, logout_user, current_user
from flask import Flask, render_template, request, redirect, url_for, flash, url_for, redirect, session

CURRENT_DIRECTORY = os.path.dirname(os.path.abspath(__file__))
POWERMETER = os.path.join(CURRENT_DIRECTORY, "powermeter", "")
POWERMETER_LIBRARY = os.path.join(CURRENT_DIRECTORY, "powermeter")
APP_CONFIG = os.path.join(os.path.dirname(CURRENT_DIRECTORY), "app_config.ini")
KEY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cert", "key.pem")
CERT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cert", "cert.pem") # Self signed
LOGFILE_DIR = os.getenv("CAF_APP_LOG_DIR", "/tmp")
sys.path.append(POWERMETER)
appconfig = SafeConfigParser()
appconfig.read(APP_CONFIG)

# Establish MySQL connection to database server.
def databaseConnection():
    connection = MySQL.connect(host= DB_IP,
                           user = DB_USERNAME,
                           passwd = DB_PASSWORD,
                           port = DB_PORT,
                           db = DB_SCHEMA)
    return connection

# Establish MySQL connection to database server.
def cintelDbConnection():
    connection = MySQL.connect(host= CINTEL_DB_IP,
                           user = CINTEL_DB_USERNAME,
                           passwd = CINTEL_DB_PASSWORD,
                           port = CINTEL_DB_PORT,
                           db = CINTEL_DB_SCHEMA)
    return connection

"""
    Create table "urconnect_address" if it isn't exists.
    * id = PK, id number
    * unitid = unitid of uRCONNECT
    * module = module of uRCONNECT (1down, 2up, 2down, 3up, 3down)
    * channel = module's channel of uRCONNECT (1-8)
    * type = modbus function code (FC01-FC04)
    * name = sensor name (you can change if you need.)
    * startingAddress = starting address that script need to read from uRCONNECT.
    * quantity = amount of address that script need to read from uRCONNECT. (e.g. 00001, 2 = read from address 00001 to 00002)
    * ip = ip address is ip address, yeah i mean it.
    * displayAddress = address that you can see from uRCONNECT documents.
    * cardtype = card type (e.g. 4-20mA, digital input, relay)
    * unit = unit of value (e.g. mA, V, Celcius)
    * status = read or not read that address.
"""
def createUrconnectAddress():
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = ("CREATE TABLE IF NOT EXISTS urconnect_address (id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, unitid VARCHAR(2) NOT NULL, module VARCHAR(5) NOT NULL, "
    "channel VARCHAR(1) NOT NULL, type VARCHAR(2) NOT NULL, name VARCHAR(30) NOT NULL, startingAddress VARCHAR(5) NOT NULL, "
    "quantity VARCHAR(5) NOT NULL, urconnect VARCHAR(40) NOT NULL, displayAddress VARCHAR(6) NOT NULL, cardtype VARCHAR(20) NOT NULL, unit VARCHAR(20), status VARCHAR(20))")
    cursor.execute(executeCommand)
    connection.commit()
    try:
        connection.close()
    except:
        pass

"""
    Create table "powermeter" if it isn't exists.
    * id = PK, id number
    * metername = name of power meter.
    * tablinks = active status of tablinks in powermeter.html
    * urconnect = urconnect name
"""
def createPowermeter():
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = ("CREATE TABLE IF NOT EXISTS powermeter (id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, metername VARCHAR(40) NOT NULL UNIQUE, "
    "tablinks VARCHAR(30) NOT NULL, urconnect VARCHAR(50) NOT NULL)")
    cursor.execute(executeCommand,)
    connection.commit()
    try:
        connection.close()
    except:
        pass

"""
    Create table "powermeter_address" if it isn't exists.
    * id = PK, id number
    * name = name of address that u need to read from powermeter.
    * address = start address that u need to read from powermeter.
    * quantity = amount of address that script need to read from powermeter. (e.g. 00001, 2 = read from address 00001 to 00002)
    * datatype = data type of value that u need to convert to. (e.g. uint32 = convert 2 uint16 to uint32)
    * realaddress = REAL ADDRESS THAT MY SCRIPT USE TO READ FROM URCONNECT (ALWAYS MINUS ONE FROM address)
    * modbustype = modbus function code (FC01-FC04)
    * multiplier = just a multiplier. (converted data MULTIPLIED BY multiplier)
    * unit = unit of value (e.g. mA, V, Celcius)
"""
def createPowermeterAddress():
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = ("CREATE TABLE IF NOT EXISTS powermeter_address (id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, name VARCHAR(40) NOT NULL, address VARCHAR(6), "
    "quantity VARCHAR(3), datatype VARCHAR(30) NOT NULL, realaddress VARCHAR(6), metername VARCHAR(50) NOT NULL, modbustype VARCHAR(3) NOT NULL, multiplier VARCHAR(20) NOT NULL, unit VARCHAR(20))")
    cursor.execute(executeCommand,)
    connection.commit()
    try:
        connection.close()
    except:
        pass

"""
    Create table "cintel" if it isn't exists.
    * id = PK, id number
    * cintelname = C Intelligent name.
    * tablinks = active status of tablinks in cintel.html
    * nexpieauth = Nexpie credentials.
"""
def createCintel():
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = ("CREATE TABLE IF NOT EXISTS cintel (id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, cintelname VARCHAR(40) NOT NULL, "
    "tablinks VARCHAR(40) NOT NULL, nexpieauth VARCHAR(50) NOT NULL)")
    cursor.execute(executeCommand,)
    connection.commit()
    try:
        connection.close()
    except:
        pass

"""
    Create table "cintel_address" if it isn't exists.
    * id = PK, id number
    * source = Value come from C Intelligent name? (just for reminder)
    * plcaddress = PLC Address (just for reminder)
    * cintelname = name of C Intelligent.
    * datatable = C Intelligent address. (idk why vendor named "datatable" for cintel address)
    * dataname = C Intelligent address name. (e.g. Voltage1, Temperature_Plant1)
    * datatype = data type of value that u need to convert to. (e.g. uint32 = convert two uint16 to uint32)
    * multiplier = just a multiplier. (converted data MULTIPLIED BY multiplier)
    * unit = unit of value (e.g. mA, V, Celcius)
    * quantity = 1 or 2 (depends on datatype)
"""
def createCintelAddress():
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = ("CREATE TABLE IF NOT EXISTS cintel_address (id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, source VARCHAR(40) NOT NULL, plcaddress VARCHAR(10), cintelname VARCHAR(40) NOT NULL,"
    "datatable VARCHAR(10), dataname VARCHAR(50), datatype VARCHAR(30) NOT NULL, unit VARCHAR(20), multiplier VARCHAR(20) NOT NULL, quantity VARCHAR(10))")
    cursor.execute(executeCommand,)
    connection.commit()
    try:
        connection.close()
    except:
        pass

"""
    Create table "nexpie_auth" if it isn't exists.
    * name = NEXPIE device name (it's just a name, don't mind)
    * clientid = NEXPIE device's client id
    * token = NEXPIE device's username (token on nexpie.io)
    * secret = NEXPIE device's password (secret on nexpie.io)
"""
def createNexpieAuth():
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "CREATE TABLE IF NOT EXISTS nexpie_auth (id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, name VARCHAR(50) NOT NULL, clientid VARCHAR(36) NOT NULL, token VARCHAR(32) NOT NULL, secret VARCHAR(32) NOT NULL)"
    cursor.execute(executeCommand)
    connection.commit()
    try:
        connection.close()
    except:
        pass

"""
    Create table "user" if it isn't exists.
    If table return null then create user using username, password and name from app_config.ini
    * username = username for login to web application.
    * name = factory name.
    * password = password for login to web application.
"""
def createUser():
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "CREATE TABLE IF NOT EXISTS user (id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, username VARCHAR(20) NOT NULL UNIQUE, password VARCHAR(100) NOT NULL, name VARCHAR(45) NOT NULL UNIQUE)"
    cursor.execute(executeCommand)
    connection.commit()
    executeCommand = "SELECT * FROM user"
    cursor.execute(executeCommand)
    result = cursor.fetchall()
    if result == []:
        USERNAME = appconfig.get('LOGIN', 'username')
        PASSWORD = appconfig.get('LOGIN', 'password')
        NAME = appconfig.get('LOGIN', 'name')
        ENCRYPTED = generate_password_hash(PASSWORD, method='sha256')
        executeCommand = "INSERT INTO user (username, password, name) VALUES (%s, %s, %s)"
        cursor.execute(executeCommand, (USERNAME, ENCRYPTED, NAME,))
        connection.commit()
    try:
        connection.close()
    except:
        pass

"""
    Create table "config" if it isn't exists.
    * unitid = uRCONNECT's unit id.
    * ip = uRCONNECT's ip address.
    * note = **deprecated**
    * status = enable or disable
    * tablinks = tablinks active or tablinks (tablinks active will active after load config page (index.html))
    * name = uRCONNECT's name
"""
def createConfig():
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = ("CREATE TABLE IF NOT EXISTS config (id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, unitid VARCHAR(2) NOT NULL UNIQUE, ip VARCHAR(15) NOT NULL UNIQUE, "
    "note VARCHAR(15) NOT NULL, status VARCHAR(10) NOT NULL, tablinks VARCHAR(40) NOT NULL, urconnect VARCHAR(40) NOT NULL UNIQUE, nexpieauth VARCHAR(50))")
    cursor.execute(executeCommand)
    connection.commit()
    try:
        connection.close()
    except:
        pass

"""
    Setup logging for the current module and dependent libraries based on
    values available in config.
"""
def setup_logging():
    # Set a format which is simpler for console use
    formatter = logging.Formatter('[%(asctime)s] %(levelname)-8s> %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

    # Set log level based on what is defined in package_config.ini file
    loglevel = appconfig.getint("LOGGING", "log_level")
    logger.setLevel(loglevel)

    # Create a console handler only if console logging is enabled
    ce = appconfig.getboolean("LOGGING", "console")
    if ce:
        console = logging.StreamHandler()
        console.setLevel(loglevel)
        console.setFormatter(formatter)
        # Add the handler to the root logger
        logger.addHandler(console)

    def customTime(*args):
        utc_dt = utc.localize(datetime.utcnow())
        my_tz = timezone("Asia/Bangkok")
        converted = utc_dt.astimezone(my_tz)
        return converted.timetuple()

    logging.Formatter.converter = customTime

    # The default is to use a Rotating File Handler

    if platform.system() == "Windows":
        log_file_path = os.path.join(CURRENT_DIRECTORY, "modbus_app.log")
    else:
        log_file_path = os.path.join(LOGFILE_DIR, "modbus_app.log")

    # Define cap of the log file at 1 MB x 3 backups.
    rfh = RotatingFileHandler(log_file_path, maxBytes=3096*3096, backupCount=3)
    rfh.setLevel(loglevel)
    rfh.setFormatter(formatter)
    logger.addHandler(rfh)

# Write time interval to old app_config.ini if not exist. (version 1.1)
def initInterval():
    try:
        TIME_INTERVAL = int(appconfig.get('TIME_INTERVAL', 'timeInterval'))
    except:
        cfgfile = open(APP_CONFIG, "w")
        appconfig.add_section("TIME_INTERVAL")
        appconfig.set("TIME_INTERVAL", "timeInterval", "60")
        appconfig.write(cfgfile)

# Load config from app_config.ini
DB_USERNAME = appconfig.get('SQLALCHEMY_CONFIG', 'username')
DB_PASSWORD = appconfig.get('SQLALCHEMY_CONFIG', 'password')
DB_IP = appconfig.get('SQLALCHEMY_CONFIG', 'ip')
DB_PORT = appconfig.get('SQLALCHEMY_CONFIG', 'port')
DB_SCHEMA = appconfig.get('SQLALCHEMY_CONFIG', 'schema')
NEXPIE_URL = appconfig.get('NEXPIE', 'shadow_url')
jsondata = []
# C Intelligent is optional.
try:
    CINTEL_DB_USERNAME = appconfig.get('C_INTELLIGENT', 'username')
    CINTEL_DB_PASSWORD = appconfig.get('C_INTELLIGENT', 'password')
    CINTEL_DB_IP = appconfig.get('C_INTELLIGENT', 'ip')
    CINTEL_DB_PORT = appconfig.get('C_INTELLIGENT', 'port')
    CINTEL_DB_SCHEMA = appconfig.get('C_INTELLIGENT', 'schema')
except:
    pass

logger = logging.getLogger("modbus_ida")
setup_logging()
initInterval() # Create time interval config (if not exist.)

# Test connection and connect to database server.
# Initialize application.
initChecker = True
while initChecker == True:
    r = pyping.ping(str(DB_IP))
    if r.ret_code == 0:
        try:
            connection = MySQL.connect(host= DB_IP,
                                       user = DB_USERNAME,
                                       passwd = DB_PASSWORD,
                                       port = DB_PORT)
            cursor = connection.cursor()
            executeCommand = "CREATE DATABASE IF NOT EXISTS " + DB_SCHEMA
            cursor.execute(executeCommand)
            connection.commit()
            connection.close()

            createUser() # Create user if table "user" have nothing.
            createUrconnectAddress()
            createNexpieAuth()
            createConfig()
            createPowermeter()
            createPowermeterAddress()
            createCintelAddress()
            createCintel()

            app = Flask(__name__)
            db = SQLAlchemy()
            db.pool_recycle = 300
            app.config['SECRET_KEY'] = appconfig.get('APP_INIT', 'secretkey')
            app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+mysqlconnector://" + DB_USERNAME + ":" + DB_PASSWORD + "@" + DB_IP + ":" + DB_PORT + "/" + DB_SCHEMA
            app.config["SQLALCHEMY_POOL_SIZE"] = 20
            app.config['PERMANENT_SESSION_LIFETIME'] =  timedelta(minutes=15)
            app.config['SESSION_REFRESH_EACH_REQUEST'] = True
            db.init_app(app)

            login_manager = LoginManager()
            login_manager.login_view = 'login'
            login_manager.init_app(app)
            initChecker = False
        except Exception as e:
          logger.error("Exception occurred", exc_info=True)
    else:
        logger.info("Ping database server: Failed")

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True) # primary keys are required by SQLAlchemy
    username = db.Column(db.String(20), unique=True)
    password = db.Column(db.String(30))
    name = db.Column(db.String(100))

@login_manager.user_loader
def load_user(user_id):
    # since the user_id is just the primary key of our user table, use it in the query for the user.
    return User.query.get(int(user_id))

######################################################################################################################
# Database &
######################################################################################################################

# Load uRCONNECT default config from database server.
def urconnectSettings():
    connection = MySQL.connect(host= DB_IP,
                           user = DB_USERNAME,
                           passwd = DB_PASSWORD,
                           port = DB_PORT,
                           db = "urconnect_settings")
    return connection

# Close database connection
def closeConnection(connection):
    try:
        connection.close()
    except:
        pass

# Change web application's credentials.
def changePassword(encryptedPassword, name):
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "UPDATE user SET password = %s WHERE name = %s"
    cursor.execute(executeCommand, (encryptedPassword, name,))
    connection.commit()
    closeConnection(connection)

# Delete registered device from database.
def deleteConfig(urconnect):
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "SELECT id FROM powermeter WHERE urconnect = %s"
    cursor.execute(executeCommand, (urconnect,))
    result = cursor.fetchall()
    # If selected urconnect not used by any powermeter, then delete urconnect config.
    if result == []:
        executeCommand = "DELETE FROM config WHERE urconnect = %s"
        cursor.execute(executeCommand, (urconnect,))
        executeCommand = "DELETE FROM urconnect_address WHERE urconnect = %s"
        cursor.execute(executeCommand, (urconnect,))
        executeCommand = "UPDATE config SET tablinks = %s LIMIT 1"
        cursor.execute(executeCommand, ("tablinks active",))
        connection.commit()
        try:
            connection.close()
        except:
            pass
        return("deleted")
    elif result != []:
        return("not delete")
    else:
        return("failed")

# Get list of power meter from database.
def getPowermeter():
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "SELECT * FROM powermeter"
    cursor.execute(executeCommand)
    result = cursor.fetchall()
    closeConnection(connection)
    return(result)

# Get list of power meter address from database.
def getPowermeterAddress():
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "SELECT * FROM powermeter_address"
    cursor.execute(executeCommand)
    result = cursor.fetchall()
    closeConnection(connection)
    return(result)

# Get list of C Intelligent from database.
def getCintel():
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "SELECT * FROM cintel"
    cursor.execute(executeCommand)
    result = cursor.fetchall()
    closeConnection(connection)
    return(result)

# Get list of C Intelligent modbus address from database.
def getCintelAddress():
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "SELECT id, cintelname, source, plcaddress, datatype , datatable, dataname, unit, multiplier FROM cintel_address"
    cursor.execute(executeCommand)
    result = cursor.fetchall()
    closeConnection(connection)
    return(result)

def newCintel(cintelname, nexpieauth):
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "SELECT tablinks FROM cintel WHERE tablinks = %s"
    cursor.execute(executeCommand, ("tablinks active",))
    result = cursor.fetchall()
    # Note: tablinks active = show this tab after GET config page (index.html)
    if result == []:
        tablinks = "tablinks active"
    else:
        tablinks = "tablinks"
    executeCommand = ("INSERT INTO cintel (cintelname, tablinks, nexpieauth) VALUES (%s, %s, %s)")
    cursor.execute(executeCommand, (cintelname, tablinks, nexpieauth))
    # Create address for powermeter.
    for i in range(0, 15):
        randomname = randomAddressname()
        executeCommand = ("INSERT INTO cintel_address (source, cintelname, dataname, datatype, multiplier) VALUES (%s, %s, %s, %s, %s)")
        cursor.execute(executeCommand, ("source", cintelname , randomname, "none", "-"),)
    connection.commit()
    closeConnection(connection)

# Random power meter address name.
def randomAddressname():
    randomstring = random.sample(string.ascii_letters, 6)
    for i in range(0, 6):
        if i == 0:
            randomname = ""
        randomname = randomname + randomstring[i]
    return(randomname)

# Add new powermeter to database.
def newPowermeter(powermetername, urconnect):
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "SELECT tablinks FROM powermeter WHERE tablinks = %s"
    cursor.execute(executeCommand, ("tablinks active",))
    result = cursor.fetchall()
    # Note: tablinks active = show this tab after GET config page (index.html)
    if result == []:
        tablinks = "tablinks active"
    else:
        tablinks = "tablinks"
    executeCommand = ("INSERT INTO powermeter (metername, tablinks, urconnect) VALUES (%s, %s, %s)")
    cursor.execute(executeCommand, (powermetername, tablinks, urconnect))
    # Create address for powermeter.
    for i in range(0, 15):
        randomname = randomAddressname()
        executeCommand = ("INSERT INTO powermeter_address (name, datatype, metername, modbustype, multiplier) VALUES (%s, %s, %s, %s, %s)")
        cursor.execute(executeCommand, (randomname, "none", powermetername, "00", "-"),)
    connection.commit()
    closeConnection(connection)
    return(result)

# Get NEXPIE credentials from database.
def getNexpieAuth():
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "SELECT id, name, clientid, token, secret FROM nexpie_auth"
    cursor.execute(executeCommand)
    result = cursor.fetchall()
    closeConnection(connection)
    return(result)

# Get NEXPIE device name from database.
def getCredentialsName():
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "SELECT name FROM nexpie_auth"
    cursor.execute(executeCommand)
    result = cursor.fetchall()
    closeConnection(connection)
    return(result)

# Delete NEXPIE device from database.
def deleteCredentials(nexpiename):
    try:
        connection = databaseConnection()
        cursor = connection.cursor()
        executeCommand = "DELETE FROM nexpie_auth WHERE name = %s"
        cursor.execute(executeCommand, (nexpiename,))
        connection.commit()
        closeConnection(connection)
    except:
        return("failed")
    return("success")

# Get id of NEXPIE device from database. (not clientid)
def getNexpieID():
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "SELECT id FROM nexpie_auth"
    cursor.execute(executeCommand)
    result = cursor.fetchall()
    closeConnection(connection)
    return result

# Get list of urconncet from database.
def getConfig():
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "SELECT * FROM config"
    cursor.execute(executeCommand)
    data = cursor.fetchall()
    closeConnection(connection)
    return data

# Get value that define tab(s) in config page.
def getTab():
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "SELECT tablinks, id, urconnect FROM config WHERE note = %s"
    cursor.execute(executeCommand, ("config",))
    result = cursor.fetchall()
    closeConnection(connection)
    return result

# Get value that define tab(s) in config page.
def getPowermeterTab():
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "SELECT tablinks, id, metername FROM powermeter"
    cursor.execute(executeCommand,)
    result = cursor.fetchall()
    closeConnection(connection)
    return result

# Get value that define tab(s) in config page.
def getCintelTab():
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "SELECT tablinks, id, cintelname FROM cintel"
    cursor.execute(executeCommand,)
    result = cursor.fetchall()
    closeConnection(connection)
    return result

# Get list of urconnect name from database.
def getUrconnect():
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "SELECT urconnect FROM config"
    cursor.execute(executeCommand)
    data = cursor.fetchall()
    closeConnection(connection)
    return data

# Get value that define unitid in config page.
def getConfigID():
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "SELECT id FROM config WHERE note = %s"
    cursor.execute(executeCommand, ("config",))
    result = cursor.fetchall()
    closeConnection(connection)
    return result

# Add new urconnect to database.
def newDevice(ip, unitid, checkbox, devicename, nexpieauth):
    # Note: enabled = get value from urconnect, convert to json and send to NEXPIE.
    if checkbox != "enabled":
        checkbox = "disabled"
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "SELECT * FROM config"
    cursor.execute(executeCommand)
    result = cursor.fetchall()
    # Note: tablinks active = show this tab after GET config page (index.html)
    if result == []:
        number = str(0)
        tablinks = "tablinks active"
    else:
        executeCommand = "SELECT id FROM config ORDER BY id DESC LIMIT 1"
        cursor.execute(executeCommand)
        result = cursor.fetchall()
        number = str(result[0][0])
        tablinks = "tablinks"
    stringunitid = "UnitID:" + str(unitid)
    executeCommand = ("INSERT INTO config (unitid, ip, note, status, tablinks, urconnect, nexpieauth) VALUES (%s, %s, %s, %s, %s, %s, %s)")
    cursor.execute(executeCommand, (unitid, ip, "config", checkbox, tablinks, devicename, nexpieauth))
    connection.commit()
    closeConnection(connection)

# Update urconnect's config (ip, unitid, device name, nexpie device & status enable or disable) to database
def updateConfig(ip, unitid, devicename, oldunitid, oldip, oldname, checkbox, nexpieauth):
    if checkbox != "enabled":
        checkbox = "disabled"
    connection = databaseConnection()
    cursor = connection.cursor()
    devicename = devicename.replace(" ", "_")
    # 1st: Update urconnect name in "urconnect_address"
    executeCommand = "UPDATE urconnect_address SET urconnect = %s, unitid = %s WHERE unitid = %s and urconnect = %s"
    cursor.execute(executeCommand, (devicename, unitid, oldunitid, oldname,))
    connection.commit()
    # 2nd: Update ip, unitid, device name, nexpie device & status enable or disable.
    executeCommand = "UPDATE config SET ip = %s, unitid = %s, urconnect = %s, status = %s, nexpieauth = %s WHERE unitid = %s and ip = %s and urconnect = %s"
    cursor.execute(executeCommand, (ip, unitid, devicename, checkbox, nexpieauth, oldunitid, oldip, oldname,))
    connection.commit()
    # 3rd: Update name of urconnect in powereter database.
    executeCommand = "UPDATE powermeter SET urconnect = %s WHERE urconnect = %s"
    cursor.execute(executeCommand, (devicename, oldname,))
    connection.commit()
    # 4th: Get id of urconnect_address that you need to change value/data.
    executeCommand = "SELECT id FROM urconnect_address WHERE urconnect = %s" # We only need length of unitid = %s
    cursor.execute(executeCommand, (devicename,))
    result = cursor.fetchall()
    return(result)

# Update NEXPIE credentials to database.
def updateNexpieCredentials(id, name, clientid, token, secret):
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "UPDATE nexpie_auth SET name = %s, clientid = %s, token = %s, secret = %s WHERE id = %s"
    cursor.execute(executeCommand, (name, clientid, token, secret, id))
    connection.commit()
    closeConnection(connection)

# Add new NEXPIE device to database.
def addNexpieCredentials(name, clientid, token, secret):
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = ("INSERT INTO nexpie_auth (name, clientid, token, secret) VALUES (%s, %s, %s, %s)")
    cursor.execute(executeCommand, (name, clientid, token, secret))
    connection.commit()
    closeConnection(connection)

"""
    * Check type and correction of input before update to database.
    * If its duplicate or error, then return error and skip update.
"""
def inputChecker(ip, unitid, devicename, oldip, oldunitid, oldname, nexpieauth):
    if ip == "":
        return("Failed: IP address cannot be blank.")
    if unitid == "":
        return("Failed: Unit id or device name cannot be blank.")
    if devicename == "":
        return("Failed: Device name cannot be blank.")
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "SELECT id FROM config WHERE ip = %s and unitid = %s and urconnect = %s"
    cursor.execute(executeCommand, (oldip, oldunitid, oldname))
    result = cursor.fetchall()
    id = result[0][0]
    executeCommand = "SELECT ip FROM config WHERE ip = %s and id <> %s"
    cursor.execute(executeCommand, (ip, id))
    result = cursor.fetchall()
    if result != []:
        return("Failed: The IP address '" + ip + "' is already used in database.")
    executeCommand = "SELECT unitid FROM config WHERE unitid = %s and id <> %s"
    cursor.execute(executeCommand, (unitid, id))
    result = cursor.fetchall()
    if result != []:
        return("Failed: The unit id '" + unitid + "' is already used in database.")
    executeCommand = "SELECT urconnect FROM config WHERE urconnect = %s and id <> %s"
    cursor.execute(executeCommand, (devicename, id))
    result = cursor.fetchall()
    if result != []:
        return("Failed: The name '" + devicename + "' is already used in database.")
    # Check nexpieauth usage in C Intelligent.
    executeCommand = "SELECT cintelname FROM cintel WHERE nexpieauth = %s"
    cursor.execute(executeCommand, (nexpieauth,))
    result = cursor.fetchall()
    if result != []:
        return("Failed: '" + nexpieauth + "' is already used in C Intelligent.")
    closeConnection(connection)
    return("Passed")

"""
    * Check type and correction of input before update to database.
    * If its duplicate or error, then return error and skip update.
"""
def inputCheckerNewDevice(ip, unitid, devicename):
    if ip == "":
        return("Failed: IP address cannot be blank.")
    if unitid == "":
        return("Failed: Unit id or device name cannot be blank.")
    if devicename == "":
        return("Failed: Device name cannot be blank.")
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "SELECT ip FROM config WHERE ip = %s"
    cursor.execute(executeCommand, (ip,))
    result = cursor.fetchall()
    if result != []:
        return("Failed: The IP address '" + ip + "' is already used in database.")
    executeCommand = "SELECT unitid FROM config WHERE unitid = %s"
    cursor.execute(executeCommand, (unitid,))
    result = cursor.fetchall()
    if result != []:
        return("Failed: The unit id '" + unitid + "' is already used in database.")
    executeCommand = "SELECT urconnect FROM config WHERE urconnect = %s"
    cursor.execute(executeCommand, (devicename,))
    result = cursor.fetchall()
    if result != []:
        return("Failed: The name '" + devicename + "' is already used in database.")
    executeCommand = "SELECT cintelname FROM cintel WHERE nexpieauth = %s"
    cursor.execute(executeCommand, (nexpieauth,))
    result = cursor.fetchall()
    if result != []:
        return("Failed: '" + nexpieauth + "' is already used in C Intelligent.")
    closeConnection(connection)
    return("Passed")

# Check correction of client id before update to database.
def clientidChecker(clientid):
    for i in range(0, len(clientid)):
        if i == 8 or i == 13 or i == 18 or i == 23:
            if clientid[i] != "-":
                return(False)
        else:
            if clientid[i] == "-":
                return(False)
    return(True)

# Check connection between application and urconnect before update to database.
# This mean u cannot change urconnect data w/o connect to urconnect.
def checkUrconnect(ip, unitid):
    PORT_NUMBER = 502
    try:
        client = ModbusClient(auto_open=True, timeout=3, host=ip, port=PORT_NUMBER, unit_id=unitid, debug=True)
        client.host(ip)
        client.port(PORT_NUMBER)
        client.unit_id(unitid)
        client.debug()
        if not client.is_open():
            if not client.open():
                return("Failed: Can't connect to " + ip + ", unit id " + unitid)
        if client.is_open():
                return("Passed")
    except:
        return("Failed: Can't connect to " + ip + ", unit id " + unitid)

# Read cardtype from uRCONNECT.
def readCard(ip, unitid):
    PORT_NUMBER = 502
    client = ModbusClient(auto_open=True, timeout=3, host=ip, port=PORT_NUMBER, unit_id=unitid, debug=True)
    client.host(ip)
    client.port(PORT_NUMBER)
    client.unit_id(unitid)
    client.debug()
    if not client.is_open():
        if not client.open():
            return("Failed: Can't connect to " + ip + ", unit id " + unitid)
    # if open() is ok, read register (modbus function FC03)
    if client.is_open():
        data = client.read_holding_registers(501, 5)
        for i in range(0,len(data)):
            if data[i] not in [80, 81, 82, 83, 84, 85, 86, 87, 0]:
                data[i] = 0
        return data

# Get modbus function from database using card type.
def getModbusType(name, cardList):
    connection = MySQL.connect(host= DB_IP,
                           user = DB_USERNAME,
                           passwd = DB_PASSWORD,
                           port = DB_PORT,
                           db = "urconnect_settings")
    cursor = connection.cursor()
    typeList = []
    moduleList = ["1down", "2up", "2down", "3up", "3down"]
    resultList = []
    for i in range (0, len(cardList)):
        cursor = connection.cursor()
        executeCommand = "SELECT type, cardtype FROM cardtype WHERE value = %s" #cardType = result[0][1]
        cursor.execute(executeCommand, (cardList[i],))
        cardtypeList = cursor.fetchall()
        executeCommand = "SELECT * FROM urconnect_address WHERE type = %s AND module = %s"
        cursor.execute(executeCommand, (cardtypeList[0][0], moduleList[i],))
        result = cursor.fetchall()
        for i in range (0, len(result)):
            result[i] = result[i] + (cardtypeList[0][1],)
            resultList.append(result[i])
    closeConnection(connection)
    return(resultList)

# Write time interval to app_config.ini
def writeInterval(interval, wait):
    if interval == "" or wait == "":
        return("Failed: Modbus polling interval or nexpie wait timer cannot be blank.")
    try:
        tempInterval = int(interval)
        tempWait = int(wait)
    except:
        return("Failed: Interval can only be numeric character(s).")
    cfgfile = open(APP_CONFIG, "w")
    appconfig.set("TIME_INTERVAL", "timeInterval", interval)
    appconfig.set("TIME_INTERVAL", "delayBeforeNexpie", wait)
    appconfig.write(cfgfile)
    ## write to database.

    return("Passed")

# Check nexpie device usage before delete from database.
def chkCredentialUsage(nexpiename):
    try:
        connection = databaseConnection()
        cursor = connection.cursor()
        executeCommand = "SELECT urconnect FROM config WHERE nexpieauth = %s"
        cursor.execute(executeCommand, (nexpiename,))
        result = cursor.fetchall()
        closeConnection(connection)
        if result != []:
            return("used")
        else:
            return("not used")
    except:
        return("failed")

"""
    Select quantity from datatype.
    e.g. uint32 need 2x uint16 > quantity = 2
"""
def datatypeQuantity(datatype):
    datatypeBits = datatype[-2:]
    if datatypeBits == "32":
        quantity = "2"
    elif datatypeBits == "16":
        quantity = "1"
    elif datatypeBits == "64":
        quantity = "4"
    else:
        quantity = "none"
    return(quantity)

# Check power meter address before add/change to database.
def powermeterAddressChecker(name, modbustype, startaddr, multiplier, datatype):
    # If multiplier or address isn't in number format => code in "except" will work.
    try:
        floatMultiplier = float(multiplier)
        intaddress = int(startaddr)
        if name == "" or name == " " or intaddress <= 0 or modbustype == "00":
            return("Not Passed", "0", "-")
        nameFirstchar = name[:1]
        # need to check first character of name. because NEXPIE will reject JSON data if first character of name is number.
        firstcharIsdigit = nameFirstchar.isdigit()
        if firstcharIsdigit == True:
            return("Not Passed", "0", "-")
        # realAddress = address that use in pyModbusTCP.
        realaddress = intaddress - 1
        if datatype != "none":
            quantity = datatypeQuantity(datatype)
        return("Passed", realaddress, quantity)
    except:
        return("Not Passed", "0", "-")

# Check C Intelligent address before add/change to database.
def cintelAddressChecker(source, datatable, dataname, datatype , multiplier, unit):
    # If multiplier or address isn't in number format => code in "except" is goin' to work.
    try:
        floatMultiplier = float(multiplier)
        datatable = int(datatable)
        if dataname == "" or dataname == " " or datatable <= 0 or datatable == None:
            return("Not Passed", "-")
        nameFirstchar = dataname[:1]
        # Need to check first character of name. because NEXPIE will reject JSON data if the first character of name is number.
        firstcharIsdigit = nameFirstchar.isdigit()
        if firstcharIsdigit == True:
            return("Not Passed", "-")
        if datatype != "none":
            quantity = datatypeQuantity(datatype)
        return("Passed", quantity)
    except:
        return("Not Passed", "-")

"""
    * Check Nexpie credential before add/change to C Intelligent database.
    * Cannot use same credential w/ urconnect & power meter.
"""
def cintelDbChecker(nexpieauth):
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "SELECT urconnect FROM config WHERE nexpieauth = %s"
    cursor.execute(executeCommand, (nexpieauth,))
    result = cursor.fetchall()
    if result == []:
        return("Passed" , "")
    else:
        flashmsg = "Failed: " + nexpieauth + " has been used."
        return(" Not Passed", flashmsg)

"""
    * Add blank input in "powermeter.html"
    e.g. if u add 13 address to "powermeter_address". this function will generate blank input to 15 again.
"""
def updateBlankInput(metername):
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "SELECT id FROM powermeter_address WHERE metername = %s and modbustype = %s"
    cursor.execute(executeCommand, (metername, "00",))
    result = cursor.fetchall()
    # Always keep 15 blank input per power meter
    blankinput = int(len(result))
    if blankinput < 15:
        blankinput = 15 - blankinput
        for i in range(0, blankinput):
            randomname = randomAddressname()
            executeCommand = ("INSERT INTO powermeter_address (name, datatype, metername, modbustype, multiplier) VALUES (%s, %s, %s, %s, %s)")
            cursor.execute(executeCommand, (randomname, "none", metername, "00", "-"),)
    elif blankinput > 15:
        blankinput = blankinput - 15
        strBlankinput = str(blankinput)
        executeCommand = "SELECT id FROM powermeter_address WHERE modbustype = %s and metername = %s ORDER BY id DESC LIMIT " + strBlankinput
        cursor.execute(executeCommand, ("00", metername),)
        result = cursor.fetchall()
        for i in range(0, len(result)):
            id = result[i][0]
            executeCommand = ("DELETE FROM powermeter_address WHERE id = %s")
            cursor.execute(executeCommand, (id),)
    else:
        pass
    connection.commit()
    closeConnection(connection)

# Read function name. i mean it :D
def updatePowermeter(metername, urconnect, oldmetername):
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "UPDATE powermeter_address SET metername = %s WHERE metername = %s"
    cursor.execute(executeCommand, (metername, oldmetername,))
    executeCommand = "UPDATE powermeter SET metername = %s, urconnect = %s WHERE metername = %s"
    cursor.execute(executeCommand, (metername, urconnect, oldmetername,))
    connection.commit()
    closeConnection(connection)

# Delete power meter from database.
def deletePowermeter(metername):
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "DELETE FROM powermeter WHERE metername = %s"
    cursor.execute(executeCommand, (metername,))
    executeCommand = "DELETE FROM powermeter_address WHERE metername = %s"
    cursor.execute(executeCommand, (metername,))
    executeCommand = "UPDATE powermeter SET tablinks = %s LIMIT 1"
    cursor.execute(executeCommand, ("tablinks active",))
    connection.commit()
    closeConnection(connection)

# Delete power meter from database.
def deleteCintel(cintelname):
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "DELETE FROM cintel WHERE cintelname = %s"
    cursor.execute(executeCommand, (cintelname,))
    executeCommand = "DELETE FROM cintel_address WHERE cintelname = %s"
    cursor.execute(executeCommand, (cintelname,))
    executeCommand = "UPDATE cintel SET tablinks = %s LIMIT 1"
    cursor.execute(executeCommand, ("tablinks active",))
    connection.commit()
    closeConnection(connection)

# Read function name. i mean it :D
def updateCintel(cintelname, nexpieauth, oldcintelname):
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "UPDATE cintel_address SET cintelname = %s WHERE cintelname = %s"
    cursor.execute(executeCommand, (cintelname, oldcintelname,))
    executeCommand = "UPDATE cintel SET cintelname = %s, nexpieauth = %s WHERE cintelname = %s"
    cursor.execute(executeCommand, (cintelname, nexpieauth, oldcintelname,))
    connection.commit()
    closeConnection(connection)

"""
    Add blank input in "cintel.html"
    e.g. if u add 13 address to "cintel_address". this function will generate blank input to 15 again.
"""
def updateBlankCintel(cintelname):
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "SELECT id FROM cintel_address WHERE cintelname = %s and datatable IS NULL"
    cursor.execute(executeCommand, (cintelname,))
    result = cursor.fetchall()
    # Always keep 15 blank input per powermeter
    blankinput = int(len(result))
    if blankinput < 15:
        blankinput = 15 - blankinput
        for i in range(0, blankinput):
            randomname = randomAddressname()
            executeCommand = ("INSERT INTO cintel_address (source, dataname, datatype, cintelname, multiplier) VALUES (%s, %s, %s, %s, %s)")
            cursor.execute(executeCommand, ("source", randomname, "none", cintelname, "-"),)
    elif blankinput > 15:
        blankinput = blankinput - 15
        strBlankinput = str(blankinput)
        executeCommand = "SELECT id FROM cintel_address WHERE cintelname = %s and datatable IS NULL ORDER BY id DESC LIMIT " + strBlankinput
        cursor.execute(executeCommand, (cintelname,))
        result = cursor.fetchall()
        for i in range(0, len(result)):
            id = result[i][0]
            executeCommand = ("DELETE FROM cintel_address WHERE id = %s")
            cursor.execute(executeCommand, (id,))
    else:
        pass
    connection.commit()
    closeConnection(connection)

# Get datatypes from database.
def getDatatype():
    connection = urconnectSettings()
    cursor = connection.cursor()
    executeCommand = "SELECT name, symbol FROM datatypes"
    cursor.execute(executeCommand,)
    datatypeSelector = cursor.fetchall()
    closeConnection(connection)
    return(datatypeSelector)

# Check webapp's password and database's password before edit app_config.ini
def checkPasswordDB(webusername, webpassword, currentpassword):
    passwordResult = check_password_hash(current_user.password, webpassword)
    if passwordResult == False or webusername != current_user.username or currentpassword != DB_PASSWORD:
        return(False)
    return(True)

# Write database's password, username, schema, port and ip address.
def dbcfgWriter(ip, port, username, password, schema):
    if ip == "" or port == "":
        return("Failed: IP address and port cannot be blank.")
    elif username == "" or password == "" or schema == "":
        return("Failed: Please check your database config.")

    # Open app_config.ini then update config.
    try:
        cfgfile = open(APP_CONFIG, "w")
        appconfig.set("SQLALCHEMY_CONFIG", "username", username)
        appconfig.set("SQLALCHEMY_CONFIG", "password", password)
        appconfig.set("SQLALCHEMY_CONFIG", "ip", ip)
        appconfig.set("SQLALCHEMY_CONFIG", "port", port)
        appconfig.set("SQLALCHEMY_CONFIG", "schema", schema)
        appconfig.write(cfgfile)
        writerChecker = True
    except:
        writerChecker = False
    # Revert to old value if update failed.
    if writerChecker == True:
        return("app_config updated successfully.")
    else:
        cfgfile = open(APP_CONFIG, "w")
        appconfig.set("SQLALCHEMY_CONFIG", "username", DB_USERNAME)
        appconfig.set("SQLALCHEMY_CONFIG", "password", DB_PASSWORD)
        appconfig.set("SQLALCHEMY_CONFIG", "ip", DB_IP)
        appconfig.set("SQLALCHEMY_CONFIG", "port", DB_PORT)
        appconfig.set("SQLALCHEMY_CONFIG", "schema", DB_SCHEMA)
        appconfig.write(cfgfile)
        return("Failed: Cannot write to config file.")

######################################################################################################################
# Flask
######################################################################################################################

"""
    index.html
    * Display current uRCONNECT's config.
"""
@app.route("/index")
@login_required
def index():
    # Check table "urconnect_address"
    connection = databaseConnection()
    data = getConfig()
    tab = getTab()
    credentials = getCredentialsName()
    cursor = connection.cursor()
    executeCommand = "SELECT * FROM urconnect_address"
    cursor.execute(executeCommand)
    result = cursor.fetchall()
    interval = int(appconfig.get('TIME_INTERVAL', 'timeInterval'))
    wait = int(appconfig.get('TIME_INTERVAL', 'delayBeforeNexpie'))
    closeConnection(connection)
    return render_template('index.html', name=current_user.name, result=result, tab=tab, data=data, interval=interval, credentials=credentials, wait=wait)

"""
    POST index.html
    * Update uRCONNECT's config.
"""
@app.route("/index", methods=['POST'])
@login_required
def index_post():
    name = current_user.name
    idTuple = getConfigID()
    for i in range (0,len(idTuple)):
        """
            * Get unit id from input, then compare it.
            * Selected device => got unit id from input, if not => got None from input.
        """
        htmlUnitid = "id_unitid" + str(idTuple[i][0])
        unitid = request.form.get(htmlUnitid)
        """
            * Check type and correction of input before update to database.
            * If its duplicate or error, then return error and skip update.
            * oldip, oldunitid, oldname == ip, unitid, name in database.
        """
        if unitid != None:
            number = str(idTuple[i][0])
            ipForm = "ip" + str(number)
            ip = request.form.get(ipForm)
            oldunitidForm = "oldunitid" + str(number)
            oldunitid = request.form.get(oldunitidForm)
            oldipForm = "oldip" + str(number)
            oldip = request.form.get(oldipForm)
            oldnameForm = "oldname" + str(number)
            oldname = request.form.get(oldnameForm)
            checkboxForm = "checkbox" + str(number)
            checkbox = request.form.get(checkboxForm)
            devicenameForm = "devicename" + str(number)
            devicename = request.form.get(devicenameForm)
            nexpieauthForm = "nexpieauth" + str(number)
            nexpieauth = request.form.get(nexpieauthForm)
            checked = checkUrconnect(ip, unitid)
            if checked != "Passed":
                flash(checked)
                return redirect('index')
            checked = inputChecker(ip, unitid, devicename, oldip, oldunitid, oldname, nexpieauth)
            if checked != "Passed":
                flash(checked)
                return redirect('index')
            interval = str(request.form.get("interval"))
            wait = str(request.form.get("wait"))
            checked = writeInterval(interval, wait)
            if checked != "Passed":
                flash(checked)
                return redirect('index')
            # Update name, unit and status(enable or disable) of address.
            result = updateConfig(ip, unitid, devicename, oldunitid, oldip, oldname, checkbox, nexpieauth)
            connection = databaseConnection()
            cursor = connection.cursor()
            for i in range(0, len(result)):
                id = result[i][0]
                nameForm = "name" + str(id)
                name = request.form.get(nameForm)
                unitForm = "unit" + str(id)
                unit = request.form.get(unitForm)
                checkboxForm = "checkbox" + str(id)
                checkbox = request.form.get(checkboxForm)
                if name == "":
                    pass
                else:
                    try:
                        if checkbox != "enabled":
                            checkbox = "disabled"
                        unit = str(unit)
                        executeCommand = "UPDATE urconnect_address SET name = %s, unit = %s, status = %s WHERE id = %s"
                        cursor.execute(executeCommand, (name, unit, checkbox, id,))
                        connection.commit()
                    except:
                        pass
            closeConnection(connection)
            flash("Updated Successfully")
            logger.info('User: ' + current_user.name + ' - "' + devicename + '" updated.')
            return redirect('index')

"""
    powermeter.html
    * Display powermeter's address that use in IDA Platform.
"""
@app.route("/powermeter")
@login_required
def powermeter():
    try:
        # uRCONNECT tab
        powermeter = getPowermeter()
        #data = getConfig()
        # powermeter tab
        urconnect = getUrconnect()
        powermeterAddress = getPowermeterAddress()
        powermeterTab = getPowermeterTab()
        datatypeSelector = getDatatype()
    except:
        return render_template("powermeter.html", name=current_user.name)
    return render_template("powermeter.html", name=current_user.name, urconnect=urconnect, powermeter=powermeter,
    powermeterTab=powermeterTab, powermeterAddress=powermeterAddress, datatypes=datatypeSelector)

"""
    POST powermeter.html
    * Update powermeter address that need to collect data from uRCONNECT.
"""
@app.route("/powermeter", methods=['POST'])
@login_required
def powermeter_post():
    try:
        # Update powermeter name & urconnect.
        name = current_user.name
        oldmetername = request.form.get("oldmetername")
        metername = request.form.get("metername")
        metername = metername.replace(" ", "_")
        urconnect = request.form.get("urconnect")
        # Update powermeter address.
        connection = databaseConnection()
        cursor = connection.cursor()
        executeCommand = "SELECT id FROM powermeter_address WHERE metername = %s"
        cursor.execute(executeCommand, (oldmetername,))
        result = cursor.fetchall()
        """
            Short note about "Type"
            * 00: None
            * 03: Read Holding Register
            * 04: Read Input Register
            * 99: Delete
        """
        for i in range(0, len(result)):
            id = result[i][0]
            modbustypeForm = "type" + str(id)
            modbustype = request.form.get(modbustypeForm)
            if modbustype == "99":
                executeCommand = "DELETE FROM powermeter_address WHERE id = %s"
                cursor.execute(executeCommand, (id,))
            elif modbustype != "00":
                nameForm = "name" + str(id)
                startaddrForm = "startaddr" + str(id)
                datatypeForm = "datatype" + str(id)
                multiplierForm = "multiplier" + str(id)
                unitForm = "unit" + str(id)

                name = request.form.get(nameForm)
                modbustype = request.form.get(modbustypeForm)
                startaddr = request.form.get(startaddrForm)
                datatype = request.form.get(datatypeForm)
                multiplier = request.form.get(multiplierForm)
                unit = request.form.get(unitForm)
                unit = str(unit)
                # Check if address & quantity are integer, then update database.
                checkerResult, realaddress, quantity = powermeterAddressChecker(name, modbustype, startaddr, multiplier, datatype)
                if checkerResult == "Passed":
                    executeCommand = "UPDATE powermeter_address SET name = %s, modbustype = %s, address = %s , multiplier = %s, datatype = %s, realaddress = %s, quantity = %s, unit = %s WHERE id = %s"
                    cursor.execute(executeCommand, (name, modbustype, startaddr, multiplier, datatype, realaddress, quantity, unit, id,))
                else:
                    pass
        connection.commit()
        updatePowermeter(metername, urconnect, oldmetername)
        updateBlankInput(metername)
        closeConnection(connection)

        flash("Updated Successfully")
        logger.info('User: ' + current_user.name + ' - "' + metername + '" powermeter config updated.')
        return redirect(url_for('powermeter'))
    except:
        flash("Updated failed")
        return redirect(url_for('powermeter'))

"""
    POST powermeter.html (powermeter/add)
    * Add new powermeter that connected to uRCONNECT.
"""
@app.route("/powermeter/add", methods=['POST'])
@login_required
def powermeter_add_post():
    try:
        metername = request.form.get("powermetername")
        urconnect = request.form.get("newurconnect")
        newPowermeter(metername, urconnect)
        flash('"' + metername + '" added successfully.')
    except:
        flash('Failed: Cannot add "' + metername + '" to database.')
    return redirect(url_for('powermeter'))

"""
    POST powermeter.html (powermeter/delete)
    * Add new powermeter that connected to uRCONNECT.
"""
@app.route("/powermeter/delete", methods=['POST'])
@login_required
def powermeter_delete_post():
    try:
        metername = request.form.get("metername")
        deletePowermeter(metername)
        flash('"' + metername + '" deleted successfully.')
        return redirect(url_for('powermeter'))
    except:
        flash('Failed: Cannot delete "' + metername + '" from database.')
    return redirect(url_for('powermeter'))

"""
    cintel.html
    * Display added C Intelligent module.
"""
@app.route("/cintel")
@login_required
def cintel():
    """
        1) getCintel() = Get C Intelligent name from database.
        2) getCintelAddress() = Get C Intelligent address from database.
        3) getCredentialsName() = Get Nexpie credentials list.
        4) getCintelTab() = Get C Intelligent name tab status (tablinks or tablinks active).
        5) getDatatype() = Get datatype list from database.
    """
    try:
        cintel = getCintel()
        cinteldata = getCintelAddress()
        credentials = getCredentialsName()
        cintelTab = getCintelTab()
        datatypeSelector = getDatatype()
    except:
        return render_template("cintel.html", name=current_user.name)
    return render_template("cintel.html", name=current_user.name, cintel=cintel, cinteldata=cinteldata, cintelTab=cintelTab,
                            credentials=credentials, datatypes=datatypeSelector)

"""
    POST cintel.html
    * Edit C Intelligent module reader address to application's database.
"""
@app.route("/cintel", methods=['POST'])
@login_required
def cintel_post():
    try:
        # Update cintel in database
        name = current_user.name
        oldcintelname = request.form.get("oldcintelname")
        cintelname = request.form.get("cintelname")
        cintelname = cintelname.replace(" ", "_")
        nexpieauth = request.form.get("nexpieauth")
        # Check used Nexpie credentials. (Cannot use same credentials w/ urconnect & power meter.)
        result, flashmsg = cintelDbChecker(nexpieauth)
        if result == "Not Passed":
            flash(flashmsg)
            redirect(url_for('cintel'))
        # Update C Intelligent address in database
        connection = databaseConnection()
        cursor = connection.cursor()
        executeCommand = "SELECT id FROM cintel_address WHERE cintelname = %s"
        cursor.execute(executeCommand, (oldcintelname,))
        result = cursor.fetchall()
        for i in range(0, len(result)):
            id = result[i][0]
            sourceForm = "source" + str(id)
            plcaddressForm = "plcaddress" + str(id)
            datatableForm = "datatable" + str(id)
            datanameForm = "dataname" + str(id)
            datatypeForm = "datatype" + str(id)
            unitForm = "unit" + str(id)
            multiplierForm = "multiplier" + str(id)

            source = request.form.get(sourceForm)
            plcaddress = request.form.get(plcaddressForm)
            datatable = request.form.get(datatableForm)
            dataname = request.form.get(datanameForm)
            datatype = request.form.get(datatypeForm)
            multiplier = request.form.get(multiplierForm)
            unit = request.form.get(unitForm)
            unit = str(unit)
            checkResult, quantity = cintelAddressChecker(source, datatable, dataname, datatype ,multiplier, unit)
            if checkResult == "Passed":
                executeCommand = "UPDATE cintel_address SET source = %s, plcaddress = %s, datatable = %s, dataname = %s , datatype = %s, unit = %s, multiplier = %s, quantity = %s WHERE id = %s"
                cursor.execute(executeCommand, (source, plcaddress, datatable, dataname, datatype, unit, multiplier, quantity, id,))
            else:
                pass
        connection.commit()
        """
            * updateCintel = update C Intelligent name & Nexpie credentials to database.
            * updateBlankCintel = add blank address to C Intelligent address database.
        """
        updateCintel(cintelname, nexpieauth, oldcintelname)
        updateBlankCintel(cintelname)
        closeConnection(connection)

        flash("Updated Successfully")
        logger.info('User: ' + current_user.name + ' - "' + cintelname + '" C Intelligent config updated.')
        return redirect(url_for('cintel'))
    except:
        flash("Updated failed")
        return redirect(url_for('cintel'))

"""
    POST cintel.html (cintel/add)
    * Add C Intelligent module to application's database.
"""
@app.route("/cintel/add", methods=['POST'])
@login_required
def cintel_add_post():
    try:
        cintelname = request.form.get("cintelname")
        nexpieauth = request.form.get("newnexpieauth")
        result, flashmsg = cintelDbChecker(nexpieauth)
        if result == "Passed":
            newCintel(cintelname, nexpieauth)
            flash('"' + cintelname + '" added successfully.')
        else:
            flash(flashmsg)
    except:
        flash('Failed: Cannot add "' + cintelname + '" to database.')
    return redirect(url_for('cintel'))

"""
    POST cintel.html (cintel/delete)
    * Delete C Intelligent module from application's database.
"""
@app.route("/cintel/delete", methods=['POST'])
@login_required
def cintel_delete_post():
    try:
        cintelname = request.form.get("cintelname")
        deleteCintel(cintelname)
        flash('"' + cintelname + '" deleted successfully.')
        return redirect(url_for('cintel'))
    except:
        flash('Failed: Cannot delete "' + cintelname + '" from database.')
    return redirect(url_for('cintel'))

"""
    POST index.html (index/add)
    * Add new uRCONNECT to database.
"""
@app.route("/index/add", methods=['POST'])
@login_required
def newdevice_post():
    ip = request.form.get("newip")
    unitid = request.form.get("newunitid")
    checkbox = request.form.get("newcheckbox")
    devicename = request.form.get("newdevicename")
    nexpieauth = request.form.get("newnexpieauth")
    checked = inputCheckerNewDevice(ip, unitid, devicename, nexpieauth)
    if checked != "Passed":
        flash(checked)
        return redirect(url_for('index'))
    try:
        # Read cardtype from uRCONNECT.
        cardList = readCard(ip, unitid)
    except:
        cardList = "Failed: Can't connect to " + ip + ", unit id " + unitid
    if cardList == "Failed: Can't connect to " + ip + ", unit id " + unitid:
        flash(cardList)
        return redirect(url_for('index'))
    # Add new uRCONNECT to database
    newDevice(ip, unitid, checkbox, devicename, nexpieauth)
    resultList = getModbusType("urconnect_settings", cardList)
    connection = databaseConnection()
    cursor = connection.cursor()
    # Add address to database.
    for i in range(0, len(resultList)):
        name = "ch" + str(resultList[i][2]) + "_" + str(resultList[i][1])
        executeCommand = ("INSERT INTO urconnect_address (unitid, module, channel, type, name, startingAddress, quantity, urconnect, "
        "displayAddress, cardtype, status) VALUES ( %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)")
        cursor.execute(executeCommand, (unitid, resultList[i][1], resultList[i][2], resultList[i][0], name, resultList[i][3], resultList[i][4], devicename, resultList[i][5], resultList[i][6], "disabled"))
    connection.commit()
    closeConnection(connection)
    flash('"' + devicename + '" added successfully.')
    logger.info('User: ' + current_user.name + ' - ' + devicename + "(" + ip + ", " + unitid + ') added to database.')
    return redirect(url_for('index'))

"""
    credentials.html
    * Display current NEXPIE credentials.
"""
@app.route("/credentials")
@login_required
def credentials():
    result = getNexpieAuth()
    if result == []:
        haveData = False
        return render_template('credentials_false.html', name=current_user.name)
    else:
        haveData = True
        return render_template('credentials.html', name=current_user.name, result=result)

"""
    POST credentials.html
    * Update NEXPIE credential to database.
"""
@app.route("/credentials", methods=['POST'])
@login_required
def credentials_post():
    name = current_user.name
    nexpieid = getNexpieID()
    for i in range(0,len(nexpieid)):
        currentNexpieid = str(nexpieid[i][0])
        checkbox = "checkbox" + currentNexpieid
        currentCheckbox = request.form.get(checkbox)
        if currentCheckbox == "checked":
            currentName = request.form.get("name" + currentNexpieid)
            currentClientID = request.form.get("clientid" + currentNexpieid)
            currentToken = request.form.get("token" + currentNexpieid)
            currentSecret = request.form.get("secret" + currentNexpieid)
            if currentName != None and len(currentClientID) == 36 and len(currentToken) == 32 and len(currentSecret) == 32:
                currentChecker = clientidChecker(currentClientID)
                if currentChecker == True:
                    updateNexpieCredentials(currentNexpieid, currentName, currentClientID, currentToken, currentSecret)
                    flash("Nexpie credentials updated successfully.")
                    logger.info('User: ' + current_user.name + ' - Update NEXPIE credentials.')
                    logger.info('User: ' + current_user.name + ' - Name (' + currentName + ') updated.')
                    logger.info('User: ' + current_user.name + ' - Clientid (' + currentClientID + ') updated.')
                    logger.info('User: ' + current_user.name + ' - Token (' + currentToken + ') updated.')
                    logger.info('User: ' + current_user.name + ' - Secret (' + currentSecret + ') updated.')
                else:
                    flash("Failed: Please recheck client id format.")
            elif len(currentClientID) != 36:
                flash("Failed: Client ID must be 36 characters.")
            elif len(currentToken) != 32:
                flash("Failed: Token must be 32 characters.")
            elif len(currentSecret) != 32:
                flash("Failed: Secret must be 32 characters.")
    return redirect(url_for('credentials'))

"""
    POST credentials.html (credentials/delete)
    * Delete NEXPIE credential from database.
"""
@app.route("/credentials/delete", methods=['POST'])
@login_required
def credentials_delete_post():
    try:
        nexpiename = request.form['deletebutton']
        usageResult = chkCredentialUsage(nexpiename)
        # Check library usage before delete.
        # Script cannot delete library if it used in any powermeter.
        if usageResult == "used":
            flash('Failed:  "' + nexpiename +'" is currently in use. Please deactivate uRCONNECT that using "'+ nexpiename + '".')
            return redirect(url_for('credentials'))
        elif usageResult == "not used":
            pass
        else:
            flash('Failed: Cannot delete "' + nexpiename + '" from database.')
            return redirect(url_for('credentials'))

        # If it not used, then delete nexpie credentials.
        result = deleteCredentials(nexpiename)
        if result == "success":
            flash('"' + nexpiename + '" deleted successfully.')
            return redirect(url_for('credentials'))
        else:
            flash("Failed: Can't delete " + nexpiename + '" from database.')
            return redirect(url_for('credentials'))
    except:
        flash("Failed: Can't delete selected devicename from database.")
        return redirect(url_for('credentials'))

"""
    POST credentials.html (credentials/add)
    * Add NEXPIE credential to database.
"""
@app.route("/credentials/add", methods=['POST'])
@login_required
def credentials_add_post():
    name = current_user.name
    newDevicename = request.form.get("newDevicename")
    newClientID = request.form.get("newClientID")
    newToken = request.form.get("newToken")
    newSecret = request.form.get("newSecret")
    if newDevicename != None and len(newClientID) == 36 and len(newToken) == 32 and len(newSecret) == 32:
        resultChecker = clientidChecker(newClientID)
        if resultChecker == True:
            addNexpieCredentials(newDevicename, newClientID, newToken, newSecret)
            flash("Nexpie credentials: " + newDevicename + " added successfully.")
            logger.info('User: ' + current_user.name + ' - Add new NEXPIE credentials.')
            logger.info('User: ' + current_user.name + ' - Name (' + newDevicename + ') Added.')
        else:
            flash("Failed: Please recheck client id format.")
    elif newDevicename == None:
        flash("Failed: Devicename cannot be blank.")
    elif len(newClientID) != 36:
        flash("Failed: Client ID must be 36 characters.")
    elif len(newToken) != 32:
        flash("Failed: Token must be 32 characters.")
    elif len(newSecret) != 32:
        flash("Failed: Secret must be 32 characters.")
    return redirect(url_for('credentials'))

@app.route('/')
def page():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    else:
        return redirect(url_for('login'))

"""
    login.html
    * Display web application login page.
"""
@app.route('/login')
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    else:
        return render_template("login.html")

"""
    POST login.html
    * Get username and password from HTML form and check matching between form and database.
"""
@app.route('/login', methods=['POST'])
def login_post():
    # Get username and password from login form.
    username = request.form.get('username')
    password = request.form.get('password')
    # Query username and password in database.
    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password, password):
        flash('Please check your login details and try again.')
        return redirect(url_for('login')) # if the user doesn't exist or password is wrong, reload the page.
    login_user(user)
    logger.info('User: ' + current_user.name + ' - Successfully logged in.')
    return redirect(url_for('index'))

"""
    POST deleteconfig, GET index.html
    * Delete uRCONNECT from database.
"""
@app.route('/index/delete', methods=['POST'])
@login_required
def deleteconfig_post():
    urconnect = request.form.get('urconnect')
    result = deleteConfig(urconnect)
    if result == "deleted":
        flash('"' + urconnect + '" deleted successfully.')
    elif result == "not delete":
        flash('Failed:  "' + urconnect +'" is currently in use. Please deactivate powermeter that using '+ urconnect + '.')
    else:
        flash('Cannot delete "' + urconnect + '".')
    logger.info('User: ' + current_user.name + ' - "' + str(urconnect) + '" deleted successfully.')
    return redirect(url_for('index'))

"""
    user.html
    * Display current log and password changer page.
"""
@app.route('/user')
@login_required
def user():
    if platform.system() == "Windows":
        logpath = os.path.join(CURRENT_DIRECTORY, "modbus_app.log")
    else:
        logpath = os.path.join(LOGFILE_DIR, "modbus_app.log")
    with open(logpath, "r") as f:
        log = f.read()
    return render_template('user.html', name=current_user.name, content=log)

"""
    POST user.html
    * Update new password to database.
    * Return to login page if password changed successfully.
"""
@app.route('/user' , methods=['POST'])
@login_required
def user_post():
    currentpasswordInput = request.form.get('currentpassword')
    checkingResult = check_password_hash(current_user.password, currentpasswordInput)
    if checkingResult == True:
        password = request.form.get('password')
        repassword = request.form.get('repassword')
        if password == "" and repassword == "":
            flash("Failed: Password cannot be blank.")
        elif password == repassword:
            encryptedPassword = generate_password_hash(password, method='sha256')
            changePassword(encryptedPassword, current_user.name)
            flash("Password changed successfully.")
            logger.info('User: ' + current_user.name + ' - Successfully changed password.')
            logger.info('User: ' + current_user.name + ' - Successfully logged out.')
            logout_user()
            return redirect(url_for('login'))
        else:
            flash("Failed: Those password didn't match.")
    else:
        flash("Failed: Current password didn't match.")
    return redirect(url_for('user'))

"""
    dbcfg.html
    * Update database's password, username, schema, port and ip address.
"""
@app.route('/dbcfg')
@login_required
def dbcfg():
    return render_template('dbcfg.html', name=current_user.name)

"""
    POST dbcfg.html
    * Update database's password, username, schema, port and ip address.
"""
@app.route('/dbcfg' , methods=['POST'])
@login_required
def dbcfg_post():
    webusername = request.form.get('webusername')
    webpassword = request.form.get('webpassword')
    # currentpassword = current database password.
    currentdbpassword = request.form.get('currentpassword')
    checkedResult = checkPasswordDB(webusername, webpassword, currentdbpassword)
    if checkedResult == True:
        ip = request.form.get('ip')
        port = request.form.get('port')
        username = request.form.get('dbusername')
        password = request.form.get('dbpassword')
        schema = request.form.get('schema')
        result = dbcfgWriter(ip, port, username, password, schema)
        flash(result)
    else:
        flash("Failed: Username or password do not match.")
    return render_template('dbcfg.html', name=current_user.name)

"""
    logout
    * Remove current user session from application, then redirect to login page.
"""
@app.route('/logout')
@login_required
def logout():
    name = current_user.name
    logger.info('User: ' + current_user.name + ' - Successfully logged out.')
    logout_user()
    return redirect(url_for('login'))

######################################################################################################################
# Modbus Reader & C Intelligent.
######################################################################################################################

"""
    * Start modbus thread
    * Note: read enabled device from DB. => get NEXPIE credentials from DB => read value from uRCONNECT
      => convert to JSON => send to NEXPIE.
    * IMPORTANT! : After update uRCONNECT settings and/or NEXPIE credential. You need to restart application to take effect.
    ***************************************************************************************************************************
    * Q: Why we need to query data from database only 1 time (when start application)?
    * A: Our database server hardware & internet connection isn't stable enough for multiple concurrent connections.
"""
def threadedModbus():
    logger.info("Thread: modbusReader started.")
    """
        1) Read data from database. (address, name, datatype, unit multiplier, time interval and credentials)
        2) Read data from uRCONNECT using pyModbusTCP and/or read collected value from C Intelligent module.
        3) Append readed data to JSON variable
        4) Send JSON to NEXPIE.
        5) Wait for x second(s) [x = time interval]
        6) Read 1) again :P
    """
    try:
        preparedList, meternameList = prepareAddress()
        cintelList = prepareCintel()
        logger.info('uRCONNECT: ' + str(urconnectList))
    except:
        pass

    while True:
        try:
            TIME_INTERVAL = int(appconfig.get('TIME_INTERVAL', 'timeInterval'))
            DELAY_BEFORE_NEXPIE = int(appconfig.get('TIME_INTERVAL', 'delayBeforeNexpie'))
            if preparedList != []:
                modbus2Nexpie(preparedList, meternameList, DELAY_BEFORE_NEXPIE)
            if cintelList != []:
                cintel2Nexpie(cintelList, DELAY_BEFORE_NEXPIE)
            time.sleep(TIME_INTERVAL)
        except:
            logger.debug("Modbus reader error - Please check your configuration or NEXPIE server status.")
            time.sleep(15)

"""
    * Read data from database. (address, name, datatype, unit multiplier, time interval and credentials)
    * Dump to JSON data, then append to array.
    * Structure example. =>
        [{
            "credentials" : {
                "nexpiename": nexpiename,
                "clientid": clientid,
                "token": token,
                "secret": secret
            },
            "urconnect" : [{
                "urconnectname": urconnectname,
                "unitid": unitid,
                "ip": ip,
                "modulename": ["name": addressname, "startaddr": startaddr, "quantity": quantity, "modbustype": modbustype, "unit": unit}],
                "powermeter" ["name": addressname, "quantity": quantity, "datatype": datatype, "startaddr": startaddr, "modbustype": modbustype, "multiplier": multiplier, "unit": unit}]
            }]
        }]
"""
def prepareAddress():
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "SELECT nexpieauth FROM config WHERE status = %s"
    cursor.execute(executeCommand, ("enabled",))
    urconnectList = cursor.fetchall()
    tempNexpieList = []
    # Pick nexpie credential from "config" table.
    for i in range(0,len(urconnectList)):
        urconnectNexpiename = str(urconnectList[i][0])
        nexpieauth = getNexpieCredentials(urconnectNexpiename)
        nexpiename = nexpieauth[0][0]
        clientid = nexpieauth[0][1]
        token = nexpieauth[0][2]
        secret = nexpieauth[0][3]
        tempNexpieList.append([nexpiename, clientid, token, secret])
    nexpieList = []
    """
        * Remove duplicate nexpie credentials.
        * e.g. [[nexpiename0, clientid0, token0, secret0], [nexpiename1, clientid1, token1, secret1] , [nexpiename2, clientid2, token2, secret2]]
    """
    for i in range(0,len(tempNexpieList)):
        if i not in nexpieList:
            nexpieList.append(tempNexpieList[i])
    meternameList = []
    preparedList = []
    for numNexpieList in range(0,len(nexpieList)):
        # {"nexpiename": "xxx", "clientid": "xxx", "token": "xxx", "secret": "xxx"}
        nexpiename = nexpieList[numNexpieList][0] # nexpiename0
        clientid = nexpieList[numNexpieList][1] # clientid0
        token = nexpieList[numNexpieList][2] # token0
        secret = nexpieList[numNexpieList][3] # secret0
        addressDict = {}
        addressDict["credentials"] = {}
        addressDict["credentials"]["nexpiename"] = nexpiename
        addressDict["credentials"]["clientid"] = clientid
        addressDict["credentials"]["token"] = token
        addressDict["credentials"]["secret"] = secret
        addressDict["urconnect"] = []

        # Query urconnect list.
        connection = databaseConnection()
        cursor = connection.cursor()
        executeCommand = "SELECT unitid, ip, urconnect, nexpieauth FROM config WHERE status = %s and nexpieauth = %s"
        cursor.execute(executeCommand, ("enabled", nexpiename))
        urconnectList = cursor.fetchall()
        for i in range(0,len(urconnectList)):
            unitid = urconnectList[i][0]
            ip = urconnectList[i][1]
            urconnectname = urconnectList[i][2]
            tempdict = {"urconnectname": urconnectname, "unitid": unitid, "ip": ip}
            moduleList = ["1down", "2up", "2down", "3up", "3down"]
            # Query address from module.
            for n in range(0,len(moduleList)):
                executeCommand = ('SELECT type, name, startingAddress, quantity, cardtype, module, channel, unit FROM urconnect_address WHERE unitid = %s and urconnect = %s and status = %s and module = %s')
                cursor.execute(executeCommand, (unitid, urconnectname, "enabled", moduleList[n]))
                addressList = cursor.fetchall()
                modulename = "module_" + moduleList[n]
                tempdict[modulename] = []
                # Extract address tuple into dictionary.
                for m in range(0,len(addressList)):
                    modbustype = str(addressList[m][0])
                    addressname = str(addressList[m][1])
                    startaddr = int(addressList[m][2])
                    quantity = int(addressList[m][3])
                    #cardtype = str(addressList[m][4])
                    module = str(addressList[m][5])
                    #channel = str(addressList[m][6])
                    unit = str(addressList[m][7])
                    tempaddress = {"name": addressname, "startaddr": startaddr, "quantity": quantity, "modbustype": modbustype, "unit": unit}
                    tempdict[modulename].append(tempaddress)

            executeCommand = "SELECT metername, urconnect FROM powermeter WHERE urconnect = %s"
            cursor.execute(executeCommand, (urconnectname,))
            meterList = cursor.fetchall()
            tempmeternameList = []
            for n in range(0, len(meterList)):
                metername = str(meterList[n][0])
                tempmeternameList.append(metername)
                tempdict[metername] = []
                executeCommand = "SELECT name, quantity, datatype, realaddress, metername, modbustype, multiplier, unit FROM powermeter_address WHERE metername = %s and modbustype <> %s"
                cursor.execute(executeCommand, (metername, "00",))
                meteraddress = cursor.fetchall()
                for m in range(0, len(meteraddress)):
                    addressname = str(meteraddress[m][0])
                    quantity = int(meteraddress[m][1])
                    datatype = str(meteraddress[m][2])
                    startaddr = int(meteraddress[m][3])
                    METERNAME_POWERMETER_ADDR = str(meteraddress[m][4])
                    modbustype = str(meteraddress[m][5])
                    multiplier = float(meteraddress[m][6])
                    unit = str(meteraddress[m][7])
                    temppowermeter = {"name": addressname, "quantity": quantity, "datatype": datatype, "startaddr": startaddr, "modbustype": modbustype, "multiplier": multiplier, "unit": unit}
                    tempdict[metername].append(temppowermeter)
            meternameList.append(tempmeternameList)
            addressDict["urconnect"].append(tempdict)
        preparedList.append(addressDict)
    closeConnection(connection)
    return(preparedList, meternameList)

"""
    * Read C Intelligent data from database.
    * Dump to JSON data, then append to array same as urconnect & power meter.
    * Structure example. =>
        [{
            "credentials" : {
                "nexpiename": nexpiename,
                "clientid": clientid,
                "token": token,
                "secret": secret
            },
            "cintel" : [{
                "cintelname": cintelname,
                "cintel_example": [{"datatable": datatable, "dataname": dataname, "datatype": datatype, "unit": unit, "multiplier": multiplier, "quantity": quantity}]
            }]
        }]
"""
def prepareCintel():
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "SELECT nexpieauth FROM cintel"
    cursor.execute(executeCommand)
    cintelList = cursor.fetchall()
    tempNexpieList = []
    # Pick nexpie credential from "config" table.
    for i in range(0,len(cintelList)):
        cintelNexpiename = str(cintelList[i][0])
        nexpieauth = getNexpieCredentials(cintelNexpiename)
        nexpiename = nexpieauth[0][0]
        clientid = nexpieauth[0][1]
        token = nexpieauth[0][2]
        secret = nexpieauth[0][3]
        tempNexpieList.append([nexpiename, clientid, token, secret])
    nexpieList = []
    """
        * Remove duplicate nexpie credentials.
        * e.g. [[nexpiename0, clientid0, token0, secret0], [nexpiename1, clientid1, token1, secret1] , [nexpiename2, clientid2, token2, secret2]]
    """
    for i in range(0,len(tempNexpieList)):
        if tempNexpieList[i] not in nexpieList:
            nexpieList.append(tempNexpieList[i])
    meternameList = []
    preparedList = []
    for numNexpieList in range(0,len(nexpieList)):
        nexpiename = nexpieList[numNexpieList][0] # nexpiename0
        clientid = nexpieList[numNexpieList][1] # clientid0
        token = nexpieList[numNexpieList][2] # token0
        secret = nexpieList[numNexpieList][3] # secret0
        cintelDict = {}
        cintelDict["credentials"] = {}
        cintelDict["credentials"]["nexpiename"] = nexpiename
        cintelDict["credentials"]["clientid"] = clientid
        cintelDict["credentials"]["token"] = token
        cintelDict["credentials"]["secret"] = secret
        cintelDict["cintel"] = []

        # Query cintel list.
        connection = databaseConnection()
        cursor = connection.cursor()
        executeCommand = "SELECT cintelname FROM cintel WHERE nexpieauth = %s"
        cursor.execute(executeCommand, (nexpiename,))
        cintelList = cursor.fetchall()
        for i in range(0,len(cintelList)):
            cintelname = cintelList[i][0]
            tempdict = {"cintelname": cintelname}
            executeCommand = ('SELECT datatable, dataname, datatype, unit, multiplier, quantity FROM cintel_address WHERE datatable IS NOT NULL and dataname IS NOT NULL and cintelname = %s ')
            cursor.execute(executeCommand, (cintelname,))
            cintelAddressList = cursor.fetchall()
            tempdict[cintelname] = []
            # Extract address tuple into dictionary.
            for m in range(0,len(cintelAddressList)):
                datatable = str(cintelAddressList[m][0])
                dataname = str(cintelAddressList[m][1])
                datatype = str(cintelAddressList[m][2])
                unit = str(cintelAddressList[m][3])
                multiplier = float(cintelAddressList[m][4])
                quantity = int(cintelAddressList[m][5])
                tempaddress = {"datatable": datatable, "dataname": dataname, "datatype": datatype, "unit": unit, "multiplier": multiplier, "quantity": quantity }
                tempdict[cintelname].append(tempaddress)
            cintelDict["cintel"].append(tempdict)
        preparedList.append(cintelDict)
    closeConnection(connection)
    return(preparedList)

"""
    * Read current active uRCONNECT from database.
    * Return value that pyModbusTCP need.
"""
def readAddress():
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "SELECT unitid, ip, urconnect, nexpieauth FROM config WHERE status = %s"
    cursor.execute(executeCommand, ("enabled",))
    urconnectList = cursor.fetchall()
    addressList = []
    ipList = []
    powermeterList = []
    powermeteraddressList = []
    STATUS_ENABLED = "enabled"
    for i in range(0,len(urconnectList)):
        executeCommand = ('SELECT type, name, startingAddress, quantity, cardtype, module, channel, unit FROM urconnect_address WHERE unitid = %s and urconnect = %s and status = %s')
        UNIT_ID = int(urconnectList[i][0])
        IP_ADDRESS = str(urconnectList[i][1])
        URCONNECT_NAME = str(urconnectList[i][2])
        cursor.execute(executeCommand, (UNIT_ID, URCONNECT_NAME, STATUS_ENABLED,))
        result = cursor.fetchall()
        addressList.append(result)
        ipList.append(IP_ADDRESS)
        powermeterList, powermeteraddressList = readPowermeter(URCONNECT_NAME, powermeterList, powermeteraddressList)
    closeConnection(connection)
    return(urconnectList, addressList, powermeterList, powermeteraddressList)

"""
    * Read current active uRCONNECT from database.
"""
def readPowermeter(urconnect, powermeterList, powermeteraddressList):
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "SELECT metername, urconnect FROM powermeter WHERE urconnect = %s"
    cursor.execute(executeCommand, (urconnect,))
    result = cursor.fetchall()
    for i in range(0,len(result)):
        powermeterList.append(result[i]) # append tuple (metername, urconnect) instead of [(metername0, urconnect0), (metername1, urconnect1)]
        metername = str(result[i][0])
        executeCommand = "SELECT name, quantity, datatype, realaddress, metername, modbustype, multiplier, unit FROM powermeter_address WHERE metername = %s and modbustype <> %s"
        cursor.execute(executeCommand, (metername, "00",))
        meteraddress = cursor.fetchall()
        powermeteraddressList.append(meteraddress) # [[(addr_0), (addr_1), ..., (addr_n)], [(addr_0), (addr_1), ..., (addr_n)]]
    closeConnection(connection)
    return(powermeterList, powermeteraddressList)

"""
    * Convert C Intelligent value to readable format.
"""
def cintelConverter(valueArray, datatype, multiplier):
    if datatype == "uint32":
        data = getUint32(valueArray, multiplier)
    elif datatype == "uint32sw":
        data = getUint32swapped(valueArray, multiplier)
    elif datatype == "float32":
        data = getFloat32(valueArray, multiplier)
    elif datatype == "float32sw":
            data = getFloat32swapped(valueArray, multiplier)
    elif datatype  == "uint16":
        data = getUint16(valueArray, multiplier)
    """
    elif converter == "uint64":
        getUint64(startingAddress, IP_ADDRESS, UNIT_ID, multiplier)

    elif converter == "float64":
        getFloat64(startingAddress, IP_ADDRESS, UNIT_ID, multiplier)
    """
    return(data)

"""
    * Get specific C Intelligent value from C Intelligent database.
"""
def getDatatableValue(cintelname, datatable, datatype, quantity, multiplier):
    connection = cintelDbConnection()
    cursor = connection.cursor()
    templist = []
    quantity = int(quantity)
    for i in range(0, quantity):
        executeCommand = "SELECT value FROM " + cintelname + " WHERE datatable = %s"
        cursor.execute(executeCommand, (datatable,))
        result = cursor.fetchall()
        value = float(result[0][0])
        templist.append(value)
        datatable = str(int(datatable) + 1)
    connection.close()
    data = valueConverter(datatype, templist ,multiplier)
    return(data)

"""
    * Read value from uRCONNECT
    * Read every channel from every module (up to 40 channel) then convert to json format.
    * Structure example. =>
        {
            "currentTime": "01/01/2001 00:00:00"
            "urconnect_01": {
                "module_1down": {
                    "ch1_1down": {
                        "value": 220,
                        "unit": "V"
                    }
                },
                "powermeter_01": {
                    "Voltage": {
                        "value": 220.1,
                        "unit": "V"
                    },
                    "Temp": {
                        "value": 25,
                        "unit": "Celcius"
                    }
                },
                "detail": {
                    "ip": "192.168.1.1",
                    "unitid": 1
                }
            }
        }
"""
def modbus2Nexpie(addressList, meternameList, DELAY_BEFORE_NEXPIE):
    PORT_NUMBER = 502
    for nexpiename in range(0, len(addressList)):
        try:
            payloaddata = {"data":{}}
            # load urconnect data from addressList.
            nexpiedeviceName = addressList[nexpiename]['credentials']['nexpiename']
            for j in range(0, len(addressList[nexpiename]["urconnect"])):
                urconnectname = addressList[nexpiename]["urconnect"][j]["urconnectname"]
                IP_ADDRESS = addressList[nexpiename]["urconnect"][j]["ip"]
                UNIT_ID = addressList[nexpiename]["urconnect"][j]["unitid"]
                payloaddata["data"][urconnectname] = {}
                payloaddata["data"][urconnectname]['detail'] = {}
                payloaddata["data"][urconnectname]['detail']["ip"] = IP_ADDRESS
                payloaddata["data"][urconnectname]['detail']["unitid"] = UNIT_ID
                client = ModbusClient(auto_open=True, timeout=3, host=IP_ADDRESS, port=PORT_NUMBER, unit_id=UNIT_ID, debug=True)
                if not client.is_open():
                    if not client.open():
                        logger.error("unable to connect to " + IP_ADDRESS + ":" + str(PORT_NUMBER))
                if client.is_open():
                    for n in range(0,5):
                        moduleDict = {
                        0 : "module_1down",
                        1 : "module_2up",
                        2 : "module_2down",
                        3 : "module_3up",
                        4 : "module_3down"
                        }
                        module = moduleDict[n]
                        payloaddata["data"][urconnectname][module] = {}

                        for m in range(0, len(addressList[nexpiename]["urconnect"][j][module])):
                            modbustype = addressList[nexpiename]["urconnect"][j][module][m]['modbustype']
                            startaddr = addressList[nexpiename]["urconnect"][j][module][m]['startaddr']
                            quantity = addressList[nexpiename]["urconnect"][j][module][m]['quantity']
                            addressname = addressList[nexpiename]["urconnect"][j][module][m]['name']
                            unit = addressList[nexpiename]["urconnect"][j][module][m]['unit']
                            payloaddata["data"][urconnectname][module][addressname] = {}
                            # Read value from address.
                            # type = FC (e.g. type 04 == FC04: Read Input Register)
                            try:
                                data = modbusReader(modbustype, startaddr, quantity, client)
                                if modbustype == "04":
                                    data = getFloat32swapped(data, 1)
                                payloaddata["data"][urconnectname][module][addressname]["value"] = data
                                payloaddata["data"][urconnectname][module][addressname]["unit"] = unit
                            except:
                                pass
                    for n in range(0, len(meternameList[nexpiename])):
                        metername = meternameList[nexpiename][n]
                        payloaddata["data"][urconnectname][metername] = {}
                        for m in range(0, len(addressList[nexpiename]["urconnect"][j][metername])):
                            addressname = addressList[nexpiename]["urconnect"][j][metername][m]['name']
                            modbustype = addressList[nexpiename]["urconnect"][j][metername][m]['modbustype']
                            datatype = addressList[nexpiename]["urconnect"][j][metername][m]['datatype']
                            startaddr = addressList[nexpiename]["urconnect"][j][metername][m]['startaddr']
                            multiplier = addressList[nexpiename]["urconnect"][j][metername][m]['multiplier']
                            quantity = addressList[nexpiename]["urconnect"][j][metername][m]['quantity']
                            unit = addressList[nexpiename]["urconnect"][j][metername][m]['unit']
                            payloaddata["data"][urconnectname][metername][addressname] = {}
                            # Read value from powermeter.
                            try:
                                data = powermeterConverter(IP_ADDRESS, UNIT_ID, startaddr, quantity, modbustype, datatype, multiplier, client)
                                payloaddata["data"][urconnectname][metername][addressname]["value"] = data
                                payloaddata["data"][urconnectname][metername][addressname]["unit"] = unit
                            except:
                                pass
            now = datetime.now(tz=timezone('Asia/Bangkok'))
            currentTime = now.strftime("%d/%m/%Y %H:%M:%S")
            payloaddata["data"]["currentTime"] = currentTime
            nexpieShadow = json.dumps(payloaddata)
            clientid = addressList[nexpiename]["credentials"]["clientid"]
            token = addressList[nexpiename]["credentials"]["token"]
            secret = addressList[nexpiename]["credentials"]["secret"]
            time.sleep(DELAY_BEFORE_NEXPIE)
            payloadPost(nexpieShadow, clientid, token, secret)
        # Skip if cannot connect to uRCONNECT
        except:
            print("failed")
            pass

"""
    * Read value from C Intelligent's database.
    * Read selected value (that was config in webapp), then convert to json format.
    * Structure example. =>
        {
            "time": "01/01/2001 00:00:00"
            "cintel_name": {
                "Humid": {
                    "unit": "RH",
                    "value": 0
                },
                "Uncensored": {
                  "unit": "U",
                  "value": 8388608
                },
                "Voltage2": {
                  "unit": "V",
                  "value": 0
                }
            }
        }
"""
def cintel2Nexpie(cintelList, DELAY_BEFORE_NEXPIE):
    for nexpiename in range(0, len(cintelList)):
        try:
            payloaddata = {"data":{}}
            # load cintel data from cintelList.
            nexpieCintelName = cintelList[nexpiename]['credentials']['nexpiename']
            for j in range(0, len(cintelList[nexpiename]["cintel"])):
                cintelname = cintelList[nexpiename]["cintel"][j]["cintelname"]
                payloaddata["data"][cintelname] = {}
                # xd[2]['cintel'][0]['cintel_3']
                # xd[2]['cintel'][0]['cintel_3'][0]['quantity'])
                for n in range(0,len(cintelList[nexpiename]["cintel"][j][cintelname])):
                    dataname = cintelList[nexpiename]["cintel"][j][cintelname][n]['dataname']
                    datatable = cintelList[nexpiename]["cintel"][j][cintelname][n]['datatable']
                    datatype = cintelList[nexpiename]["cintel"][j][cintelname][n]['datatype']
                    unit = cintelList[nexpiename]["cintel"][j][cintelname][n]['unit']
                    quantity = cintelList[nexpiename]["cintel"][j][cintelname][n]['quantity']
                    multiplier = cintelList[nexpiename]["cintel"][j][cintelname][n]['multiplier']
                    # Get value from database.
                    try:
                        convertedData = getDatatableValue(cintelname, datatable, datatype, quantity, multiplier)
                        payloaddata["data"][cintelname][dataname] = {}
                        payloaddata["data"][cintelname][dataname]["value"] = convertedData
                        payloaddata["data"][cintelname][dataname]["unit"] = unit
                    except:
                        pass
            now = datetime.now(tz=timezone('Asia/Bangkok'))
            currentTime = now.strftime("%d/%m/%Y %H:%M:%S")
            payloaddata["data"]["time"] = currentTime
            nexpieShadow = json.dumps(payloaddata)
            clientid = cintelList[nexpiename]["credentials"]["clientid"]
            token = cintelList[nexpiename]["credentials"]["token"]
            secret = cintelList[nexpiename]["credentials"]["secret"]
            time.sleep(DELAY_BEFORE_NEXPIE)
            payloadPost(nexpieShadow, clientid, token, secret)
        except:
            pass

"""
    * Data converter.
"""
def getFloat32(valueArray, multiplier):
    packedUint16 = struct.pack('>HH', valueArray[0], valueArray[1])
    convertedFloat32 = struct.unpack('>f', packedUint16)
    multipliedValue = convertedFloat32[0] * float(multiplier)
    data = float("%.3f" % multipliedValue)
    return(data)

def getFloat32swapped(valueArray, multiplier):
    packedUint16 = struct.pack('>HH', valueArray[1], valueArray[0])
    convertedFloat32 = struct.unpack('>f', packedUint16)
    multipliedValue = convertedFloat32[0] * float(multiplier)
    data = float("%.3f" % multipliedValue)
    return(data)

def getUint32(valueArray, multiplier):
    packedUint16 = struct.pack('>HH', valueArray[0], valueArray[1])
    convertedUint32 = struct.unpack('>I', packedUint16)
    multipliedValue = float(convertedUint32[0]) * float(multiplier)
    data = float("%.3f" % multipliedValue)
    return(data)

def getUint32swapped(valueArray, multiplier):
    packedUint16 = struct.pack('>HH', valueArray[1], valueArray[0])
    convertedUint32 = struct.unpack('>I', packedUint16)
    multipliedValue = float(convertedUint32[0]) * float(multiplier)
    data = float("%.3f" % multipliedValue)
    return(data)

def getUint16(valueArray, multiplier):
    value = valueArray[0]
    data = float(valueArray[0]) * float(multiplier)
    return(data)

"""
    * Modbus Reader.
    * Read value from urconnect in selected type.
"""
def modbusReader(type, startaddr, quantity, client):
    if type == "01":
        data = client.read_coils(startaddr, quantity) # Return list that contains True or False.
        data = data[0]
    elif type == "02":
        data = client.read_discrete_inputs(startaddr, quantity) # Return list that contains True or False.
        data = data[0]
    elif type == "03":
        data = client.read_holding_registers(startaddr, quantity) # Return uint16 list.
    elif type == "04":
        data = client.read_input_registers(startaddr, quantity) # Return uint16 list.
    else:
        data = None
    return(data)

"""
    * Data converter.
    * y'know i mean it :P
"""
def valueConverter(datatype, valueArray, multiplier):
    if datatype == "uint32":
        data = getUint32(valueArray, multiplier)
    if datatype == "uint32sw":
        data = getUint32swapped(valueArray, multiplier)
    elif datatype == "float32":
        data = getFloat32(valueArray, multiplier)
    elif datatype == "float32sw":
        data = getFloat32swapped(valueArray, multiplier)
    elif datatype  == "uint16":
        data = getUint16(valueArray, multiplier)
    """
    elif converter == "uint64":
        getUint64(startingAddress, IP_ADDRESS, UNIT_ID, multiplier)

    elif converter == "float64":
        getFloat64(startingAddress, IP_ADDRESS, UNIT_ID, multiplier)
    """
    return(data)

def powermeterConverter(IP_ADDRESS, UNIT_ID, startaddr, quantity, modbustype, datatype, multiplier, client):
    valueArray = modbusReader(modbustype, startaddr, quantity, client)
    if valueArray == None:
        return(None)
    else:
        data = valueConverter(datatype, valueArray, multiplier)
        return(data)

"""
    * Get NEXPIE credential from database.
    * Return client id, username and password.
"""
def getNexpieCredentials(nexpiename):
    connection = databaseConnection()
    cursor = connection.cursor()
    executeCommand = "SELECT name, clientid, token, secret FROM nexpie_auth WHERE name = %s"
    cursor.execute(executeCommand, (nexpiename,))
    result = cursor.fetchall()
    try:
        connection.close()
    except:
        pass
    return(result)

"""
    * Send JSON data to NEXPIE using HTTPS Restful API
    * You can see result on nexpie.io
"""
def payloadPost(dataShadow, nexpieDeviceid, nexpieToken, nexpieSecret):
    basicAuthCredentials = (nexpieDeviceid, nexpieToken) # clientid & token
    response = requests.post(NEXPIE_URL, data=dataShadow, auth=basicAuthCredentials, timeout=5)
    try:
        logger.info('NEXPIE RestAPI response: ' + str(response.text))
    except:
        pass

######################################################################################################################
# Start Application.
######################################################################################################################

"""
    * Application init.
    * Note: create user if not exists. => ping NEXPIE & DB server => start modbusReader thread
      => start web application => :)
    * It's okay if u want to deploy web application, but i prefer to run script on server/device instead of deploy to server.
"""
if __name__ == '__main__':
    logger.info("Logger: Started.")
    #app.debug = True
    nexpieLoopChecker = True
    while nexpieLoopChecker == True:
        # You can change to selected server, but IDA Platform use NEXPIE shadow.
        try:
            r = pyping.ping('api.nexpie.io')
            if r.ret_code == 0:
                logger.info("Ping api.nexpie.io: Success!")

                nexpieLoopChecker = False
            else:
                logger.info("Ping api.nexpie.io: Failed!")
        except:
            time.sleep(5)
    webappLoopChecker = True
    while webappLoopChecker == True:
        try:
            r = pyping.ping(DB_IP)
            if r.ret_code == 0:
                logger.info("Ping database server: Success")

                webappLoopChecker = False
            else:
                logger.info("Ping database server: Failed")
        except:
            time.sleep(5)
    thread = Thread(target=threadedModbus)
    thread.daemon = True
    thread.start()
    logger.info("WebServer: Web application started.")
    app.run(host='0.0.0.0', port=6969, ssl_context=(CERT, KEY))
