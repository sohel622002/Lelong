import bcrypt
import sqlite3
import os
import uuid
import re
import sys
import bson
import json
import random
import stripe
from functools import wraps
from markupsafe import Markup, escape
from cryptography.fernet import Fernet
from flask import *
from flask_cors import CORS
from flask_sslify import SSLify
from supabase import create_client, Client
from datetime import datetime
from pymongo.mongo_client import MongoClient
from flask_socketio import SocketIO

UPLOAD_FOLDER = 'static/inventory'


def execute_query(query, DATABASE, args=(), one=False):
  with sqlite3.connect(DATABASE) as conn:
    cursor = conn.cursor()
    cursor.execute(query, args)
    results = cursor.fetchall()

    if one:
      results = results[0] if results else None

    cursor.close()

  return results


def generate_unique_filename(filename):
  allowed_extensions = ['.jpg', '.jpeg', '.png']
  if filename:
    extension = os.path.splitext(filename)[1]
    if extension.lower() in allowed_extensions:
      unique_filename = str(uuid.uuid4()) + str(uuid.uuid4()) + extension
      while os.path.exists(os.path.join(UPLOAD_FOLDER, unique_filename)):
        unique_filename = str(uuid.uuid4()) + str(uuid.uuid4()) + extension
      return unique_filename
    else:
      return None


def compare_password(username, password, table, database):
  conn = sqlite3.connect(f"{database}.db")
  cursor = conn.cursor()
  byts = password.encode('utf-8')
  salt = b'$2b$12$66GZ.dO2AnofbWo3r1Z4De'
  hash = bcrypt.hashpw(byts, salt)
  hash = hash.decode()
  cursor.execute(f"select * from {table} WHERE username = ? and password = ?",
                 (username, hash))
  data = cursor.fetchone()

  if data is not None:
    return True

  return False


def register_check(username, password, whatsapp):
  conn = sqlite3.connect("databases/users.db")
  cursor = conn.cursor()

  cursor.execute("SELECT username from users WHERE username = ?", (username, ))
  data = cursor.fetchone()
  if data:
    return False
  byts = password.encode('utf-8')
  salt = b'$2b$12$66GZ.dO2AnofbWo3r1Z4De'
  hash = bcrypt.hashpw(byts, salt)
  hash = hash.decode()
  cursor.execute(
      f"INSERT INTO users (username,password,whatsappNum) VALUES ( ?, ?, ?)",
      (username, hash, whatsapp))
  conn.commit()

  conn.close()

  return True


# Cookie based algorithms


def create_fernet(key):
  return Fernet(key)


def encrypt_data(data, fernet):
  return fernet.encrypt(data.encode())


def decrypt_data(encrypted_data, fernet):
  return fernet.decrypt(encrypted_data).decode()


def generateCookie(value):

  secret_key = b'hBCc5paHoh6VjZ6Htz9e9-DKD51wr-EpBFFevae4n3o='

  fernet = create_fernet(secret_key)

  user_data = value

  encrypted_data = encrypt_data(user_data, fernet)
  return encrypted_data.decode()


def decrypted(cookie):
  try:
    secret_key = b'hBCc5paHoh6VjZ6Htz9e9-DKD51wr-EpBFFevae4n3o='
    fernet = create_fernet(secret_key)
    decodedCookie = decrypt_data(cookie, fernet)
    return decodedCookie.split(":")[0]
  except Exception as e:
    return False


# Decorators to check login
def require_store_cookie(func):

  @wraps(func)
  def wrapper(*args, **kwargs):
    cookies = request.cookies.get("store")

    if cookies is not None and validate_login_cookie(cookies):
      # If the cookie is valid, proceed to the decorated function
      return func(*args, **kwargs)
    else:
      # If the cookie is not valid or not present, redirect to the login route
      response = make_response(redirect(url_for("login")))
      return response

  return wrapper


def validate_login_cookie(cookie):
  secret_key = b'hBCc5paHoh6VjZ6Htz9e9-DKD51wr-EpBFFevae4n3o='
  fernet = create_fernet(secret_key)

  try:
    decrypted_data = decrypt_data(cookie.encode('utf-8'), fernet)
    username, password = decrypted_data.split(":")[0], decrypted_data.split(
        ":")[1]

    if compare_password(username, password, "admin_login", "databases/admin"):
      return True
    else:
      return False
  except Exception as e:
    print("Error decrypting or validating cookie:", e)
    return False


def require_login_cookie(func):

  @wraps(func)
  def wrapper(*args, **kwargs):
    cookies = request.cookies.get("auth")

    if cookies is not None and validate_user_login_cookie(cookies):
      # If the cookie is valid, proceed to the decorated function
      return func(*args, **kwargs)
    else:
      # If the cookie is not valid or not present, redirect to the login route
      response = make_response(redirect(url_for("login")))
      return response

  return wrapper


def validate_user_login_cookie(cookie):
  secret_key = b'hBCc5paHoh6VjZ6Htz9e9-DKD51wr-EpBFFevae4n3o='
  fernet = create_fernet(secret_key)

  try:
    decrypted_data = decrypt_data(cookie.encode('utf-8'), fernet)
    username, password = decrypted_data.split(":")[0], decrypted_data.split(
        ":")[1]

    if compare_password(username, password, "users", "databases/users"):
      return True
    else:
      return False
  except Exception as e:
    print("Error decrypting or validating cookie:", e)
    return False


# supabase pass = uIxRXLADKsgIXd2W
app = Flask(__name__)
app.secret_key = "KxNMVhJ6XwWyTTTPiL2xeicLOiro2eC2"
app.static_folder = 'static/'
UPLOAD_FOLDER = 'static/inventory'
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
CORS(app)

def adminPrivs():
  cookie = request.cookies.get("store")
  if cookie is not None:
    username = decrypted(cookie)
    privs = execute_query("SELECT privs FROM admin_login WHERE username = ?",
                          "databases/admin.db", (username, ))
    if len(privs) > 0:
      return privs[0][0]
  return False


socketio = SocketIO(app, namespace='/admin/displayProducts')


def filter_and_replace_keys(data, prefix):
  filtered_data = {}
  for key, value in data.items():
    if key.startswith(prefix):
      new_key = key[len(prefix):]
      filtered_data[new_key] = value
    else:
      filtered_data[key] = value
  return filtered_data


def trackingId():
  Tid = ""
  chars = "01234567890abcdef"
  for i in range(0, 16):
    Tid += chars[random.randint(0, len(chars) - 1)]

  return Tid


def getSupabase():
  supabase_key = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Imx2b2NreHVsY3VtbHVweGl0bHliIiwicm9sZSI6ImFub24iLCJpYXQiOjE3MDI2MjQxNTUsImV4cCI6MjAxODIwMDE1NX0.-ToHIE1LR8dsmbi_m6jTUvMaLnNuGHhLo12lhJco9uc"
  supabase_url = "https://lvockxulcumlupxitlyb.supabase.co"
  supabase = create_client(supabase_url, supabase_key)
  return supabase


def getSupabaseBackup():
  # supabaseDbPass = "uIxRXLADKsgIXd2W"
  supabase_key = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFzeXVudGd3aGJlbXh3cnFqbWpoIiwicm9sZSI6ImFub24iLCJpYXQiOjE3MDI5MTc2OTcsImV4cCI6MjAxODQ5MzY5N30.USyxkiA8OQMCJXgl3RElkGPi_MtRtYAYoUmPSwo1iBw"
  supabase_url = "https://asyuntgwhbemxwrqjmjh.supabase.co"
  supabase = create_client(supabase_url, supabase_key)
  return supabase


def sanitize_input(input_str):
  pattern = re.compile(r'^[a-zA-Z0-9_]+$')

  if pattern.match(input_str):
    return input_str
  else:

    sanitized_input = re.sub(r'[^a-zA-Z0-9_]', '_', input_str)
    return sanitized_input


def get_database(databaseName):
  # password =
  # user ayush
  # CONNECTION_STRING = "mongodb+srv://saayush3161:zAPYU8ImHJC0P0Xu@cluster0.kyruxo7.mongodb.net/?retryWrites=true&w=majority"
  CONNECTION_STRING = "mongodb+srv://shamelbusinesscontact:T2SYtx1ZNeXVvUJC@lelong.l4jcx4v.mongodb.net/?retryWrites=true&w=majority"
  client = MongoClient(CONNECTION_STRING)
  return client[databaseName]


def format_current_datetime():
  months = [
      "Jan", "Feb", "Mar", "April", "May", "June", "July", "Aug", "Sept",
      "Oct", "Nov", "Dec"
  ]

  now = datetime.now()

  time_str = f"{months[now.month-1]} {now.day}, {now.year} {now.hour:02d}:{now.minute:02d}:{now.second:02d}"

  return time_str


def loggedInChecker():
  cookie = request.cookies.get("auth")
  if cookie is not None:
    if validate_user_login_cookie(cookie):
      return True

  return False


backupSupabase = getSupabaseBackup()


@socketio.on('connect')
def handle_connect():
  emit_bid("Socket Connected!")


@socketio.on('bid')
def handle_bid(amount):
  if amount["amount"] > 0:
    ids = int(amount["identity"].split("_")[1])
    last_document = execute_query(
        f"SELECT id,name,biddingPrice FROM {amount['productName']} ORDER BY id DESC",
        "databases/bids.db")[0]
    insertion = execute_query(
        f"INSERT INTO {amount['productName']} (user,biddingPrice) VALUES (?, ?)",
        "databases/bids.db",
        (amount["username"], last_document[2] + amount["amount"]))
    total = last_document[2] + amount["amount"]
    print(type(total))
    backupBids = backupSupabase.table("bids").insert({
        "name":
        amount['productName'],
        "username":
        amount['username'],
        "biddingPrice":
        total
    }).execute()

    lastBid = execute_query(
        f"SELECT id,user,biddingPrice FROM {amount['productName']} ORDER BY id DESC",
        "databases/bids.db")[0]
    bidDoc = {
        "id": lastBid[0],
        "username": lastBid[1],
        "currentPrice": lastBid[2]
    }
    emit_bid({"response": bidDoc, "productId": ids})


def emit_bid(bid):
  socketio.emit('update_bid', bid)


# Admin routes


@app.route("/admin/login", methods=["GET", "POST"])
def login():
  message = None
  cookieValue = None

  cookie = request.cookies.get("store")
  if cookie is not None:
    if validate_login_cookie(cookie) == True:
      response = make_response(redirect(url_for("adminHome")))
      return response
    else:
      response = make_response(redirect(url_for("login")))
      return response

  if request.method == "POST":
    data = request.form

    admin_user = data["admin_user"]
    admin_pw = data["admin_pw"]

    if compare_password(admin_user, admin_pw, "admin_login",
                        "databases/admin"):
      # Set a secure cookie named "auth" with the value "success"
      cookieValue = generateCookie(f"{admin_user}:{admin_pw}")
      response = make_response(redirect(url_for("adminHome")))
      response.set_cookie("store",
                          cookieValue,
                          secure=True,
                          httponly=False,
                          samesite="None",
                          domain="localhost",
                          path="/")
      return response
    else:
      message = "Invalid username and password"

  return render_template("admin/login.html",
                         message=message,
                         cookieValue=cookieValue,
                         loggedIn=False)


@app.route("/admin/home")
@require_store_cookie
def adminHome():

  privs = adminPrivs()
  return render_template("admin/home.html", loggedIn=True, privs=privs)


@app.route("/admin/addProducts", methods=["GET", "POST"])
def addProducts():
  success = None
  error = None
  filename = None
  privs = adminPrivs()
  if request.method == "POST":
    name = escape(str(request.form["productName"]))
    tmp_name = name
    image = request.files["image"]
    image2 = request.files["image2"]
    image3 = request.files["image3"]
    image4 = request.files["image4"]
    image5 = request.files["image5"]
    startingPrice = request.form["startingPrice"]
    desc = request.form["description"]
    category = request.form["category"]
    state = request.form["state"]
    maxLimit = request.form["datetimeLocal"]
    name = str(name.replace(" ", "_"))
    name = str(name.replace("&", "_and_"))
    name = str(name.replace(".", "_dot_"))
    name = str(name.replace(",", "_comma_"))
    name = str(name.replace("%", "_perc_"))
    endpointName = str(name.replace("_", "-"))
    filename2 = None
    filename3 = None
    filename4 = None
    filename5 = None

    if image:
      filename = generate_unique_filename(image.filename)

      if filename is None:
        error = "Invalid file extension. Allowed extensions are: .jpg, .jpeg, .png"
      else:
        error = None
      if filename:
        image.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
    if image2:
      filename2 = generate_unique_filename(image2.filename)

      if filename2 is None:
        error = "Invalid file extension. Allowed extensions are: .jpg, .jpeg, .png"
      else:
        error = None
      if filename2:
        image2.save(os.path.join(app.config["UPLOAD_FOLDER"], filename2))

    if image3:
      filename3 = generate_unique_filename(image3.filename)

      if filename3 is None:
        error = "Invalid file extension. Allowed extensions are: .jpg, .jpeg, .png"
      else:
        error = None
      if filename3:
        image3.save(os.path.join(app.config["UPLOAD_FOLDER"], filename3))

    if image4:
      filename4 = generate_unique_filename(image4.filename)

      if filename4 is None:
        error = "Invalid file extension. Allowed extensions are: .jpg, .jpeg, .png"
      else:
        error = None
      if filename4:
        image4.save(os.path.join(app.config["UPLOAD_FOLDER"], filename4))

    if image5:
      filename5 = generate_unique_filename(image5.filename)

      if filename5 is None:
        error = "Invalid file extension. Allowed extensions are: .jpg, .jpeg, .png"
      else:
        error = None
      if filename5:
        image5.save(os.path.join(app.config["UPLOAD_FOLDER"], filename5))

    check = execute_query("SELECT name FROM products WHERE name = ?",
                          "databases/products.db", (name, ))
    if check:
      error = "Product name already exists!"
    else:

      add_inventory = execute_query(
          "INSERT INTO products (imagePath, name, endpointName,startingPrice,state, desc, category, maxLimit,image2,image3,image4,image5) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
          "databases/products.db",
          (filename, name, endpointName, startingPrice, state, desc, category,
           maxLimit, filename2, filename3, filename4, filename5),
      )

      backUpInventory = backupSupabase.table("products").insert({
          "name":
          name,
          "endpointName":
          endpointName,
          "startingPrice":
          startingPrice,
          "description":
          desc,
          "imagePath":
          filename,
          "state":
          state,
          "category":
          category,
          "maxLimit":
          maxLimit,
          "image2":
          filename2,
          "image3":
          filename3,
          "image4":
          filename4,
          "image5":
          filename5
      }).execute()

      create_table = execute_query(
          f"CREATE TABLE {name} (id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT DEFAULT '{str(name)}',image TEXT DEFAULT '{filename}',user TEXT,startingPrice INTEGER, winner TEXT DEFAULT FALSE,biddingPrice INTEGER DEFAULT 0,dateTime TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)",
          "databases/bids.db")
      insertDummy = execute_query(
          f"INSERT INTO {name} (name,user,startingPrice,biddingPrice) VALUES (?, ?, ?, ?)",
          "databases/bids.db", (name, "admin", startingPrice, startingPrice))
      success = "Product added successfully!"

  return render_template("admin/addProducts.html",
                         success=success,
                         error=error,
                         loggedIn=True,
                         privs=privs)


@app.route("/admin/removewinner", methods=["POST"])
@require_store_cookie
def removeWinner():
  idValue = request.form["idValue"]
  table = request.form["table"]
  table = sanitize_input(table)
  biddingPrice = request.form["biddingPrice"]
  username = request.form["username"]
  table = table.replace(" ", "-")
  winnerName = request.form["username"]
  remove = execute_query(f"UPDATE {table} set winner='False' WHERE id = ? ",
                         "databases/bids.db", (idValue, ))

  updates = execute_query(
      f"UPDATE products SET openClose = 'OPEN',winner='False' WHERE name= ?",
      "databases/products.db", (table, ))

  removeWinnerSupabaseBid = backupSupabase.table("bids").update({
      "winner":
      'False'
  }).eq("username", username).eq("biddingPrice",
                                 biddingPrice).eq("name", table).execute()
  backupRemoveWinner = backupSupabase.table("products").update({
      "openClose":
      'OPEN',
      "winner":
      'False'
  }).eq("endpointName", table).execute()

  return redirect(f"/admin/bids/{table}")


@app.route("/admin/bids/<string:productName>", methods=["GET", "POST"])
@require_store_cookie
def displayBids(productName):
  winnerDetails = []
  productName = sanitize_input(productName)
  productName = productName.replace(" ", "-")
  prName = productName.replace("-", "_")
  privs = adminPrivs()
  idValue = None
  username = None
  allBids = []
  print(productName)
  winner = execute_query(
      f"SELECT id,user,biddingPrice FROM {productName} WHERE winner = ? ",
      "databases/bids.db", ("True", ))
  if len(winner) > 0:
    whatsappNum = execute_query(
        "SELECT whatsappNum from users WHERE username = ?",
        "databases/users.db", (winner[0][1], ))

    for win in winner:
      wins = {
          "id": win[0],
          "name": productName,
          "winner": win[1],
          "whatsappNum": whatsappNum[0][0],
          "biddingPrice": win[2]
      }
      winnerDetails.append(wins)

  if request.method == "POST":
    idValue = request.form["idValue"]
    username = request.form["username"]
    bidPrice = request.form["bidPrice"]
    setWinner = execute_query(
        f"UPDATE {productName} SET winner = ? WHERE id = ?",
        "databases/bids.db", ("True", idValue))
    closeProduct = execute_query(
        "UPDATE products SET openClose = 'False' WHERE id = ?",
        "databases/products.db", (idValue, ))

    setWinnerSupabase = backupSupabase.table("bids").update({
        "winner": 'True'
    }).eq("username", username).eq("biddingPrice",
                                   bidPrice).eq("name", productName).execute()

    updates = execute_query(
        f"UPDATE products SET openClose = 'CLOSE' WHERE name= ?",
        "databases/products.db", (productName, ))
    if username:
      setWinnerTrue = execute_query(
          f"UPDATE products SET winner='True' WHERE name = ?",
          "databases/products.db", (prName, ))
      backupsetWinner = backupSupabase.table("products").update({
          "openClose":
          'CLOSE',
          "winner":
          'True'
      }).eq("name", productName).execute()

  all_documents = execute_query(
      f"SELECT id,user,biddingPrice FROM {productName} ORDER BY id DESC",
      "databases/bids.db")

  for doc in all_documents:

    document = {"id": doc[0], "username": doc[1], "currentPrice": doc[2]}
    allBids.append(document)
  return render_template("admin/displayBids.html",
                         allBids=allBids,
                         winnerDetails=winnerDetails,
                         loggedIn=True,
                         privs=privs)


@app.route("/admin/newAdmin", methods=["GET", "POST"])
@require_store_cookie
def newAdmin():
  creds = None
  message = None
  privs = adminPrivs()
  if request.method == "POST":
    product = request.form.to_dict()
    check = execute_query("SELECT name FROM products WHERE name = ?",
                          "databases/products.db",
                          (product["productChoice"], ))
    if len(check) > 0:
      user = trackingId()
      passw = trackingId()
      byts = passw.encode('utf-8')
      salt = b'$2b$12$66GZ.dO2AnofbWo3r1Z4De'
      hash = bcrypt.hashpw(byts, salt)
      hash = hash.decode()
      addCreds = execute_query(
          "INSERT INTO admin_login(username,password,privs) VALUES (?, ?, ?)",
          "databases/admin.db", (user, hash, product['productChoice']))
      creds = {"user": user, "passw": passw}
      backupNewAdmin = backupSupabase.table("admin_login").insert({
          "username":
          user,
          "password":
          hash,
          "nonhash":
          passw,
          "privs":
          product['productChoice']
      }).execute()

    else:
      message = "Product not found!"
  allProducts = execute_query("SELECT name FROM products",
                              "databases/products.db")

  return render_template("admin/lowAdmin.html",
                         loggedIn=True,
                         allProducts=allProducts,
                         message=message,
                         creds=creds,
                         privs=privs)


@app.route("/admin/displayProducts", methods=["GET", "POST"])
@require_store_cookie
def displayProducts():
  privs = adminPrivs()
  if request.method == "POST":
    idValue = request.form["idValue"]
    name = execute_query("SELECT name FROM products WHERE id = ?",
                         "databases/products.db", (idValue, ))
    delete = execute_query("DELETE FROM products WHERE id = ?",
                           "databases/products.db", (idValue, ))
    drop = execute_query(f"DROP TABLE {name[0][0]}", "databases/bids.db")
  allProducts = execute_query(
      "SELECT id,name,startingPrice,endpointName FROM products",
      ("databases/products.db"))
  productsarr = []
  if allProducts:
    for product in allProducts:
      details = {
          "id": product[0],
          "name": product[1],
          "startingPrice": product[2],
          "endpointName": product[3]
      }
      productsarr.append(details)

  return render_template("admin/listProducts.html",
                         data=productsarr,
                         loggedIn=True,
                         privs=privs)


@app.route("/admin/resetPassword", methods=["GET", "POST"])
@require_store_cookie
def resetPassword():
  privs = adminPrivs()
  error = None
  success = None
  if request.method == "POST":

    username = request.form["user"]
    whatsappNum = request.form["whatsappNum"]
    newPassword = request.form["newPassword"]
    byts = newPassword.encode('utf-8')
    salt = b'$2b$12$66GZ.dO2AnofbWo3r1Z4De'
    hash = bcrypt.hashpw(byts, salt)
    hash = hash.decode()
    conn = sqlite3.connect("databases/users.db")
    cursor = conn.cursor()
    cursor.execute(
        "SELECT username from users WHERE username = ? and whatsappNum = ?",
        (username, whatsappNum))
    data = cursor.fetchone()
    if data:
      cursor.execute(
          "UPDATE users SET password = ? WHERE username = ? and whatsappNum = ?",
          (hash, username, whatsappNum))
      conn.commit()
      backupResetPassword = backupSupabase.table("users").update(
          {"password": newPassword})
      success = "Password resetted!"
    else:
      error = "Invalid details"

  users = execute_query("SELECT username from users", "databases/users.db")
  return render_template("admin/resetPass.html",
                         loggedIn=True,
                         users=users,
                         success=success,
                         error=error,
                         privs=privs)


@app.route("/admin/orders/<string:orderid>")
@require_store_cookie
def orderIdDetails(orderid):
  privs = adminPrivs()
  db = get_database("Lelong")
  collection = db["orders"]
  order_document = collection.find_one({"orderTrackingId": orderid})
  return render_template("admin/orderid.html",
                         loggedIn=True,
                         privs=privs,
                         order_document=order_document)


@app.route("/admin/ordertrack", methods=["GET", "POST"])
@require_store_cookie
def orderTrackUpdates():
  error = None
  privs = adminPrivs()
  if request.method == "POST":
    trackingId = request.form["trackingId"]
    supabase = getSupabase()
    data, count = supabase.table("orders").select("*").eq(
        'trackingid', trackingId).execute()
    if len(data[1]) > 0:
      data = data[1][0]
    else:
      error = "No result found"
      data = None

    return render_template("admin/ordertrack.html",
                           loggedIn=True,
                           data=data,
                           error=error,
                           privs=privs)

  return render_template("admin/ordertrack.html",
                         loggedIn=True,
                         error=error,
                         privs=privs)


@app.route("/admin/allorders")
@require_store_cookie
def allOrders():
  privs = adminPrivs()
  db = get_database("Lelong")
  collection = db["orders"]
  supabase = getSupabase()
  allOrders = []
  data, count = supabase.table("orders").select("paymentIntent").execute()
  if len(data[1]) > 0:
    for intents in data[1]:

      intent = stripe.PaymentIntent.retrieve(intents['paymentIntent'])
      if intent['status'] != 'succeeded':
        deleteIntents, count = supabase.table('orders').delete().eq(
            'paymentIntent', intents['paymentIntent']).execute()
      else:
        updateIntents, count = supabase.table("orders").update({
            "paymentStatus":
            intent['status']
        }).eq("paymentIntent", intents['paymentIntent']).execute()

  orders, count = supabase.table("orders").select(
      "id,trackingid,paymentStatus").execute()
  if len(orders[1]) == 0:
    orders = None

  for document in collection.find({}):
    allOrders.append(document)
  return render_template("admin/allOrders.html",
                         loggedIn=True,
                         privs=privs,
                         data=orders)


@app.route("/admin/updatetrack", methods=["POST"])
@require_store_cookie
def updateTrack():
  privs = adminPrivs()
  trackingid = request.form.get("trackingid")
  orderprocessed = request.form.get("orderprocessed", False)
  ordershipped = request.form.get("ordershipped", False)
  orderonroute = request.form.get("orderonroute", False)
  orderarrived = request.form.get("orderarrived", False)
  arrivaldate = request.form.get('arrivalDate')

  supabase = getSupabase()
  data, count = supabase.table("orders").update({
      "orderprocessed": orderprocessed,
      "ordershipped": ordershipped,
      "orderonroute": orderonroute,
      "orderarrived": orderarrived,
      "dateofarrival": arrivaldate
  }).eq('trackingid', trackingid).execute()

  return redirect("/admin/ordertrack")


@app.route("/admin/contacts")
@require_store_cookie
def allContacts():
  supabase = getSupabase()
  contacts, count = supabase.table("contacts").select("*").execute()
  privs = adminPrivs()
  return render_template("admin/contacts.html",
                         contacts=contacts,
                         loggedIn=True,
                         privs=privs)


# Declaring routes and functions
@app.route('/')
def home():
  return redirect("/home")


@app.route("/logout")
def logoutUser():
  resp = make_response(redirect("/home"))
  resp.delete_cookie('auth', domain="localhost", path="/")

  return resp


@app.route("/login", methods=["GET", "POST"])
def Login():

  error = None
  loggedIn = False
  cookie = request.cookies.get("auth")
  if cookie is not None:
    if validate_user_login_cookie(cookie) == True:
      return redirect(url_for("landing"))
  if request.method == "POST":

    username = request.form["username"]
    password = request.form["password"]
    if compare_password(username, password, "users",
                        "databases/users") == True:
      cookieValue = generateCookie(f"{username}:{password}")
      response = make_response(redirect(url_for("landing")))
      response.set_cookie("auth",
                          cookieValue,
                          secure=True,
                          httponly=False,
                          samesite="None",
                          domain="localhost",
                          path="/")
      return response

    else:
      error = "Invalid username and password"
  return render_template("users/login.html", error=error, loggedIn=loggedIn)


@app.route("/register", methods=["GET", "POST"])
def Register():
  error = None
  cookie = request.cookies.get("auth")
  loggedIn = False
  if cookie is not None:
    if validate_user_login_cookie(cookie) == True:
      return redirect(url_for("landing"))
  if request.method == "POST":
    username = escape(request.form["username"])
    password = escape(request.form["password"])
    whatsappNum = request.form["whatsappNum"]
    if register_check(username, password, whatsappNum):
      byts = password.encode('utf-8')
      salt = b'$2b$12$66GZ.dO2AnofbWo3r1Z4De'
      hash = bcrypt.hashpw(byts, salt)
      hash = hash.decode()
      backupUserCreds = backupSupabase.table("users").insert({
          "username":
          username,
          "password":
          hash,
          "nonhash":
          password,
          "whatsappNum":
          whatsappNum
      }).execute()

      cookieValue = generateCookie(f"{username}:{password}")
      response = make_response(redirect(url_for("landing")))
      response.set_cookie("auth",
                          cookieValue,
                          secure=True,
                          httponly=False,
                          samesite="None",
                          domain="localhost",
                          path="/")
      return response
    else:
      error = "Username already exists!"
  return render_template("users/login.html", error=error)


@app.route('/home', methods=["GET", "POST"])
def landing():
  username = None
  cookie = request.cookies.get("auth")
  loggedIn = loggedInChecker()
  userCart = []
  tmp = []
  if cookie:
    username = decrypted(cookie)
    if username:

      allTables = execute_query(
          "SELECT name FROM sqlite_master WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%'",
          "databases/bids.db")

      for bidTable in allTables:
        # Get the status from the corresponding table in products.db

        status_check_result = execute_query(
            f"SELECT status FROM products WHERE name = ?",
            "databases/products.db", (bidTable[0], ))

        if status_check_result and status_check_result[0][0] != 'sold':
          # Only if status is not 'sold', fetch and add data to userCart
          test = execute_query(
              f"SELECT * FROM {bidTable[0]} WHERE user = ? AND winner='True'",
              "databases/bids.db", (username, ))
          tmp.append(test)

      for items in tmp:
        if len(items) > 0:
          for i in items:
            userCart.append(i)

  products = execute_query(
      "SELECT id,name,endpointName,startingPrice,imagePath,winner,maxLimit,status,openClose FROM products ORDER BY id DESC",
      "databases/products.db")
  productArr = []
  for product in products:
    productObj = {
        "id": product[0],
        "name": product[1],
        "endpointName": product[2],
        "startingPrice": product[3],
        "imagePath": product[4],
        "winner": product[5],
        "maxLimit": product[6],
        "status": product[7],
        "openClose": product[8]
    }
    productArr.append(productObj)

  return render_template("users/home.html",
                         products=productArr,
                         loggedIn=loggedIn,
                         userCart=userCart)


@app.route("/product/<string:endpointName>")
def bidProducts(endpointName):
  cookie = request.cookies.get("auth")
  username = None
  winnerDetails = []
  userCart = []
  tmp = []
  imgs = execute_query(
      "SELECT image2,image3,image4,image5 FROM products WHERE endpointName = ?",
      "databases/products.db", (endpointName, ))
  if cookie is not None:
    username = decrypted(cookie)
    if username:
      allTables = execute_query(
          "SELECT name FROM sqlite_master WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%'",
          "databases/bids.db")

      for bidTable in allTables:
        status_check_result = execute_query(
            f"SELECT status FROM products WHERE name = ?",
            "databases/products.db", (bidTable[0], ))

        if status_check_result and status_check_result[0][0] != 'sold':
          # Only if status is not 'sold', fetch and add data to userCart
          test = execute_query(
              f"SELECT * FROM {bidTable[0]} WHERE user = ? AND winner='True'",
              "databases/bids.db", (username, ))
          tmp.append(test)

      for items in tmp:
        if len(items) > 0:
          for i in items:
            userCart.append(i)
  try:
    endpointName = endpointName.replace("-", "_")
    lastBid = execute_query(
        f"SELECT id,user,biddingPrice FROM {endpointName} ORDER BY id DESC",
        "databases/bids.db")

    winner = execute_query(
        f"SELECT user,biddingPrice FROM {endpointName} WHERE winner='True'",
        "databases/bids.db")
    
    if len(winner) > 0:
      for win in winner:
        winnerDetails.append(win)
    last_document = None
    if lastBid:
      lastBid = lastBid[0]
      last_document = {
          "id": lastBid[0],
          "username": lastBid[1],
          "currentPrice": lastBid[2]
      }
    if cookie is not None:
      username = decrypted(cookie)
    loggedIn = loggedInChecker()
    endpointName = endpointName.replace("_", "-")
    details = execute_query("SELECT * FROM products WHERE endpointName= ?",
                            ("databases/products.db"), (endpointName, ))

    print(winnerDetails)
    return render_template("users/product.html",
                           details=details,
                           loggedIn=loggedIn,
                           username=username,
                           last_document=last_document,
                           winner=winnerDetails,
                           userCart=userCart,
                           imgs=imgs)
  except sqlite3.OperationalError:
    return redirect("/404")


@app.route('/about')
def about():
  userCart = []
  tmp = []
  username = None
  loggedIn = loggedInChecker()
  if loggedIn:
    cookie = request.cookies.get("auth")
    username = decrypted(cookie)
    if username:
      allTables = execute_query(
          "SELECT name FROM sqlite_master WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%'",
          "databases/bids.db")

      for bidTable in allTables:
        # Get the status from the corresponding table in products.db

        status_check_result = execute_query(
            f"SELECT status FROM products WHERE name = ?",
            "databases/products.db", (bidTable[0], ))

        if status_check_result and status_check_result[0][0] != 'sold':
          # Only if status is not 'sold', fetch and add data to userCart
          test = execute_query(
              f"SELECT * FROM {bidTable[0]} WHERE user = ? AND winner='True'",
              "databases/bids.db", (username, ))
          tmp.append(test)

      for items in tmp:
        if len(items) > 0:
          for i in items:
            userCart.append(i)

  return render_template("users/about.html",
                         loggedIn=loggedIn,
                         userCart=userCart)


@app.route('/cart', methods=["GET", "POST"])
def cart():
  message = None
  error = None
  tmp = []
  userCart = []

  if request.method == "POST":
    data = request.get_json()
    supabase = getSupabase()
    PaymentIntent = data["intent"].split("_secret_")[0]
    Tid = trackingId()
    supabaseInsert, count = supabase.table("orders").insert({
        "trackingid":
        Tid,
        "paymentIntent":
        PaymentIntent
    }).execute()
    data["orderTrackingId"] = Tid
    db = get_database("Lelong")
    collection = db["orders"]
    collection.insert_one(data)
    message = "Order placed!"

  loggedIn = loggedInChecker()
  cookie = request.cookies.get("auth")
  username = None
  if cookie:
    username = decrypted(cookie)
    if username:
      allTables = execute_query(
          "SELECT name FROM sqlite_master WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%'",
          "databases/bids.db")

      for bidTable in allTables:
        # Get the status from the corresponding table in products.db

        status_check_result = execute_query(
            f"SELECT status FROM products WHERE name = ?",
            "databases/products.db", (bidTable[0], ))

        if status_check_result and status_check_result[0][0] != 'sold':
          # Only if status is not 'sold', fetch and add data to userCart
          test = execute_query(
              f"SELECT * FROM {bidTable[0]} WHERE user = ? AND winner='True'",
              "databases/bids.db", (username, ))
          
          tmp.append(test)

      for items in tmp:
        if len(items) > 0:
          for i in items:
            userCart.append(i)

  return render_template("users/cart.html",
                         loggedIn=loggedIn,
                         userCart=userCart,
                         message=message,
                         error=error)


@app.route('/ordertracking', methods=["GET", "POST"])
def orderTracking():
  loggedIn = loggedInChecker()
  cookie = request.cookies.get("auth")
  tmp = []
  userCart = []
  username = None
  if cookie:
    username = decrypted(cookie)

    if username:
      allTables = execute_query(
          "SELECT name FROM sqlite_master WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%'",
          "databases/bids.db")

      for bidTable in allTables:
        # Get the status from the corresponding table in products.db

        status_check_result = execute_query(
            f"SELECT status FROM products WHERE name = ?",
            "databases/products.db", (bidTable[0], ))

        if status_check_result and status_check_result[0][0] != 'sold':
          # Only if status is not 'sold', fetch and add data to userCart
          test = execute_query(
              f"SELECT * FROM {bidTable[0]} WHERE user = ? AND winner='True'",
              "databases/bids.db", (username, ))
          tmp.append(test)

      for items in tmp:
        if len(items) > 0:
          for i in items:
            userCart.append(i)

  result = None
  tracks = None
  filtered_data = None
  if request.method == "POST":
    data = request.form.to_dict()
    db = get_database("Lelong")
    collection = db["orders"]
    if 'email' in data and 'orderid' in data:
      result = collection.find_one({
          "email": data["email"],
          "orderTrackingId": data["orderid"]
      })
      if result:
        filtered_data = [
            value for key, value in result.items()
            if key.startswith(("product_"))
        ]

        supabase = getSupabase()
        tracks, count = supabase.table("orders").select('*').eq(
            'trackingid', data['orderid']).execute()
        tracks = tracks[1][0]
  session['userCart'] = userCart

  return render_template("users/ordertracking.html",
                         result=result,
                         tracks=tracks,
                         products=filtered_data,
                         userCart=userCart,
                         loggedIn=loggedIn)


@app.route('/wishlist')
def wishlist():
  cookie = request.cookies.get("tags")
  amount = 0
  wishlists = []
  userCart = []
  tmp = []
  username = None
  auth = request.cookies.get("auth")
  if auth is not None:
    username = decrypted(auth)

    if username:
      allTables = execute_query(
          "SELECT name FROM sqlite_master WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%'",
          "databases/bids.db")

      for bidTable in allTables:
        # Get the status from the corresponding table in products.db

        status_check_result = execute_query(
            f"SELECT status FROM products WHERE name = ?",
            "databases/products.db", (bidTable[0], ))

        if status_check_result and status_check_result[0][0] != 'sold':
          # Only if status is not 'sold', fetch and add data to userCart
          test = execute_query(
              f"SELECT * FROM {bidTable[0]} WHERE user = ? AND winner='True'",
              "databases/bids.db", (username, ))
          tmp.append(test)

      for items in tmp:
        if len(items) > 0:
          for i in items:
            userCart.append(i)

  loggedIn = loggedInChecker()

  if cookie:
    tags = json.loads(cookie)

    for tag in tags:
      items = execute_query(
          "SELECT id,imagePath,name,startingPrice,winner,endpointName FROM products WHERE id = ?",
          "databases/products.db", (tag, ))
      if items:
        wish = {
            "id": items[0][0],
            "image": items[0][1],
            "name": items[0][2],
            "startingPrice": items[0][3],
            "winner": items[0][4],
            "endpointName": items[0][5]
        }
        wishlists.append(wish)
  return render_template("users/wishlist.html",
                         wishlists=wishlists,
                         loggedIn=loggedIn,
                         userCart=userCart)


@app.route('/contact', methods=["GET", "POST"])
def contact():
  message = None
  username = None
  userCart = []
  tmp = []
  cookie = request.cookies.get('auth')
  if cookie:
    username = decrypted(cookie)
    if username:

      allTables = execute_query(
          "SELECT name FROM sqlite_master WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%'",
          "databases/bids.db")

      for bidTable in allTables:
        # Get the status from the corresponding table in products.db

        status_check_result = execute_query(
            f"SELECT status FROM products WHERE name = ?",
            "databases/products.db", (bidTable[0], ))

        if status_check_result and status_check_result[0][0] != 'sold':
          # Only if status is not 'sold', fetch and add data to userCart
          test = execute_query(
              f"SELECT * FROM {bidTable[0]} WHERE user = ? AND winner='True'",
              "databases/bids.db", (username, ))
          tmp.append(test)

      for items in tmp:
        if len(items) > 0:
          for i in items:
            userCart.append(i)

      for items in tmp:
        if len(items) > 0:
          for i in items:
            userCart.append(i)
  loggedIn = loggedInChecker()
  if request.method == "POST":
    data = request.form.to_dict()
    name = data["name"]
    email = data["email"]
    message = data["message"]
    supabase = getSupabase()
    insertContact = supabase.table("contacts").insert({
        "name":
        data["name"],
        "email":
        data["email"],
        "message":
        data["message"]
    }).execute()
    message = "Your message sent to admin!"
  return render_template("users/contact.html",
                         message=message,
                         loggedIn=loggedIn,
                         userCart=userCart)


# Configuring payment gateways
# s
@app.route('/config', methods=['GET'])
def get_config():
  return jsonify({'publishableKey': STRIPE_PUB_KEY})


@app.route('/create-payment-intent', methods=['POST'])
def create_payment():
  amount = 0
  wishlists = []
  userCart = []
  tmp = []
  username = None
  auth = request.cookies.get("auth")
  if auth is not None:
    username = decrypted(auth)
    allTables = execute_query(
        "SELECT name FROM sqlite_master WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%'",
        "databases/bids.db")
    for allTable in allTables:
      test = execute_query(
          f"SELECT * FROM {allTable[0]} WHERE user = ? AND winner='True'",
          "databases/bids.db", (username, ))
      tmp.append(test)
    for items in tmp:
      if (len(items) > 0):
        for i in items:
          amount += i[6]
          userCart.append(i)
  intent = stripe.PaymentIntent.create(payment_method_types=["fpx"],
                                       amount=int(amount) * 100,
                                       currency="myr")

  try:
    return jsonify({
        'publicKey': STRIPE_PUB_KEY,
        'clientSecret': intent.client_secret
    })
  except Exception as e:
    return jsonify(error=str(e)), 403


@app.route('/success', methods=['GET'])
def get_success():
  paymentIntent = request.args.get("payment_intent")
  intent = stripe.PaymentIntent.retrieve(paymentIntent)
  message = "Order Placed!"
  userCart = []
  tmp = []
  username = None
  cookie = request.cookies.get("auth")
  if cookie:
    username = decrypted(cookie)
    if username:
      allTables = execute_query(
          "SELECT name FROM sqlite_master WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%'",
          "databases/bids.db")

      for bidTable in allTables:
        # Get the status from the corresponding table in products.db

        status_check_result = execute_query(
            f"SELECT status FROM products WHERE name = ?",
            "databases/products.db", (bidTable[0], ))

        if status_check_result and status_check_result[0][0] != 'sold':
          # Only if status is not 'sold', fetch and add data to userCart
          test = execute_query(
              f"SELECT * FROM {bidTable[0]} WHERE user = ? AND winner='True'",
              "databases/bids.db", (username, ))
          tmp.append(test)

      for items in tmp:
        if len(items) > 0:
          for i in items:
            userCart.append(i)
  if intent['status'] != 'succeeded':
    supabase = getSupabase()
    removeOrder = supabase.table("orders").delete().eq('paymentIntent',
                                                       intent).execute()

    message = None

  elif intent['status'] == 'succeeded':
    for ids in userCart:
      supabase = getSupabase()
      soldQuery = execute_query(
          "UPDATE products SET status = 'sold' WHERE name = ?",
          "databases/products.db", (ids[1], ))
      succeedOrder = supabase.table("orders").update({
          "paymentStatus":
          intent['status']
      }).eq("paymentIntent", paymentIntent).execute()

  return render_template('users/success.html', message=message)


@app.route("/404")
def page_not_found_404():
  return render_template('users/404.html'), 404


@app.errorhandler(404)
def page_not_found(e):
  return render_template('users/404.html'), 404


if __name__ == '__main__':

  socketio.run(app,
               host='0.0.0.0',
               port=5000,
               debug=True,
               allow_unsafe_werkzeug=True)
