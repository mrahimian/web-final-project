import mysql.connector,requests

mydb = mysql.connector.connect(
  host="localhost",
  user="rahim",
  password="$Aa123456",
  database="http_monitor"
)

mycursor = mydb.cursor()

def periodic_request():
    try :
        mycursor.execute("SELECT * FROM url")
        myresult = mycursor.fetchall()

        for x in myresult:
            url = x[1]
            req = requests.get(url)
            status_code = req.status_code
            insert = f"INSERT INTO request (url_id, code) VALUES ({x[0]}, {status_code})"
            mycursor.execute(insert)
            mydb.commit()
            if status_code < 200 or status_code >= 300:
                update = f"UPDATE url SET failed_times = failed_times+1 where id={x[0]}"
                mycursor.execute(update)
            mydb.commit()
    except :
        pass
