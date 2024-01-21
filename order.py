import sqlite3


def execute_query(query, DATABASE, args=(), one=False):
  with sqlite3.connect(DATABASE) as conn:
    cursor = conn.cursor()
    cursor.execute(query, args)
    results = cursor.fetchall()

    if one:
      results = results[0] if results else None

    cursor.close()

  return results

query = execute_query("SELECT name,imagePath,startingPrice from products","databases/products.db")
for qu in query:
  name = qu[0]
  name = name.replace("-","_")
  filename = qu[1]
  startingPrice = qu[2]
  test = create_table = execute_query(
            f"CREATE TABLE {name} (id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT DEFAULT '{str(name)}',image TEXT DEFAULT '{filename}',user TEXT,startingPrice INTEGER, winner TEXT DEFAULT FALSE,biddingPrice INTEGER DEFAULT 0,dateTime TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)",
            "databases/ts.db")
  insert = insertDummy = execute_query(
            f"INSERT INTO {name} (name,user,startingPrice,biddingPrice) VALUES (?, ?, ?, ?)",
          "databases/ts.db", (name, "admin", startingPrice, startingPrice))