from flask import Flask, jsonify, redirect, render_template, request, session, url_for
import mysql.connector, random, string, os, csv
from predict import predictresult, fraudlist
import subprocess
import socket

# --- NEW ---
from flask_mail import Mail, Message  # For sending emails
import re  # For password and phone regex
from werkzeug.security import generate_password_hash, check_password_hash  # For secure passwords

app = Flask(__name__)
app.secret_key = ""


def get_db_connection():
    # Helper function to get a new connection
    connection = mysql.connector.connect(
        host='localhost',
        user='root',
        password='',
        database=''
    )
    return connection


@app.after_request
def add_header(response):
    response.cache_control.no_store = True
    return response


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_uid' in session:
        return redirect(url_for('upload'))
    if request.method == "GET":
        return render_template('login.html')

    link = get_db_connection()
    cursor = link.cursor()
    try:
        email = request.form["email"]
        password = request.form["password"]
        cursor.execute("SELECT * FROM upifraud_2024_user WHERE email = %s", (email,))
        user = cursor.fetchone()
        # user[4] is the hashed password column
        if user and check_password_hash(user[4], password):
            session['user_uid'] = user[1]
            session['user_name'] = user[2]
            session['user_email'] = user[3]
            return redirect(url_for('upload'))
        else:
            return render_template('login.html', error='Invalid email or password')
    except Exception as e:
        error = e
        return render_template('login.html', error=str(e))
    finally:
        cursor.close()
        link.close()


@app.route('/forecast', methods=['GET', 'POST'])
def forecast():
    if 'user_uid' not in session:
        return redirect(url_for('login'))

    link = get_db_connection()
    cursor = link.cursor()
    try:
        cursor.execute("SELECT * FROM upifraud_2024_predict limit 1000")
        data = cursor.fetchall()
        cursor.execute("SHOW COLUMNS FROM upifraud_2024_predict")
        columns = [column[0] for column in cursor.fetchall()]
        return render_template('forecast.html', data=data, columns=columns)
    except Exception as e:
        error = e
        return render_template('error.html', error=error)
    finally:
        cursor.close()
        link.close()


@app.route('/transactions', methods=['GET', 'POST'])
def transactions():
    if 'user_uid' not in session:
        return redirect(url_for('login'))

    link = get_db_connection()
    cursor = link.cursor()
    try:
        # Query the new transaction_time column
        cursor.execute("""
            SELECT username, DATE(transaction_time), TIME(transaction_time), sender, receiver, amount, 
                   result, ipaddress, senderfraud, receiverfraud, risk
            FROM upifraud_2024_history
            ORDER BY transaction_time DESC
            LIMIT 1000
        """)
        data = cursor.fetchall()

        columns = ["User", "Date", "Time", "Sender", "Receiver", "Amount", "Result",
                   "IP Address", "Sender Fraud", "Receiver Fraud", "Risk"]

        return render_template('transactions.html', data=data, columns=columns)
    except Exception as e:
        error = e
        return render_template('error.html', error=error)
    finally:
        cursor.close()
        link.close()


@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_uid' in session:
        return redirect(url_for('upload'))
    if request.method == "GET":
        return render_template('register.html')

    link = get_db_connection()
    cursor = link.cursor()
    try:
        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]
        phone = request.form["phone"]

        # 1. Password Strength Check
        if not (
            len(password) >= 8 and
            re.search(r"[a-z]", password) and
            re.search(r"[A-Z]", password) and
            re.search(r"\d", password) and
            re.search(r"[@$!%*?&]", password)
        ):
            return render_template('register.html', error="Password is not strong enough.")

        # 2. NEW: Backend Phone Validation (10 digits, starts with 6-9)
        if not re.match(r"^[6-9]\d{9}$", phone):
            return render_template('register.html', error="Invalid Phone Number. Must be 10 digits.")

        # 3. Email Verification Check
        if not session.get('email_verified'):
            return render_template('register.html', error="Email not verified.")
        if session.get('otp_email') != email:
            return render_template('register.html', error="Email mismatch.")

        # 4. Check if user already exists
        cursor.execute("SELECT * FROM upifraud_2024_user WHERE email = %s", (email,))
        user = cursor.fetchone()
        if user:
            return render_template('register.html', exists='Email already exists')
        else:
            # 5. Hash the password
            hashed_password = generate_password_hash(password)
            uid = 'uid_'+''.join(random.choices(string.ascii_letters + string.digits, k=10))
            
            cursor.execute(
                "INSERT INTO upifraud_2024_user (uid, name, email, password, phone) VALUES (%s, %s, %s, %s, %s)",
                (uid, name, email, hashed_password, phone)
            )
            link.commit()
            
            # Clear session
            session.pop('email_verified', None)
            session.pop('otp', None)
            session.pop('otp_email', None)
            return render_template('register.html', success='Registration successful')
            
    except Exception as e:
        print(f"!!!!!!!!!! REGISTRATION ERROR: {e} !!!!!!!!!!")
        error = e
        return render_template('register.html', error=str(e))
    finally:
        cursor.close()
        link.close()


@app.route('/send-otp', methods=['POST'])
def send_otp():
    email = request.form['email']
    if not email:
        return jsonify({"status": "error", "message": "Email is required."})
    otp = str(random.randint(100000, 999999))
    session['otp'] = otp
    session['otp_email'] = email
    try:
        msg = Message(
            'Your Registration OTP',
            sender=app.config['MAIL_USERNAME'],
            recipients=[email]
        )
        msg.body = f'Your OTP for registration is: {otp}'
        mail.send(msg)
        return jsonify({"status": "success", "message": "OTP sent!"})
    except Exception as e:
        print(f"Email error: {e}")
        return jsonify({"status": "error", "message": "Could not send email."})


@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    user_otp = request.form['otp']
    if 'otp' in session and session['otp'] == user_otp:
        session['email_verified'] = True
        return jsonify({"status": "success", "message": "Email verified!"})
    else:
        return jsonify({"status": "error", "message": "Invalid OTP."})


@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'user_uid' not in session:
        return redirect(url_for('login'))
    if request.method == "GET":
        return render_template('upload.html')

    link = get_db_connection()
    cursor = link.cursor()
    try:
        file = request.files["file"]
        filepath = os.path.join(os.path.dirname(os.path.abspath(__file__)) + '\\static\\docs', file.filename)
        file.save(filepath)
        rows = []
        with open(filepath, 'r') as csvfile:
            csvreader = csv.reader(csvfile)
            for row in csvreader:
                rows.append(row)
        for row in rows[1:]:
            if row and row[0] and row[0][0] != "":
                query = "insert into upifraud_2024_predict (uid,step,type,amount,nameorig,oldbalanceorg,newbalanceorig,namedest,oldbalancedest,newbalancedest,isfraud,isflaggedfraud) values ('uid_"+"".join(random.choices(string.ascii_letters + string.digits, k=10))+"',"
                for col in row:
                    query = query+"'"+col+"',"
                query = query[:-1] + ");"
                print(query)
                cursor.execute(query)
                link.commit()
        return render_template('upload.html', success='Upload successful', file=file.filename)
    except Exception as e:
        error = e
        return render_template('error.html', error=error)
    finally:
        cursor.close()
        link.close()


@app.route('/cleardataset', methods=['POST'])
def cleardataset():
    if 'user_uid' not in session:
        return redirect(url_for('login'))

    link = get_db_connection()
    cursor = link.cursor()
    try:
        query = "delete from upifraud_2024_predict"
        cursor.execute(query)
        link.commit()
        return render_template('upload.html', success='Dataset Cleared Successfully')
    except Exception as e:
        error = e
        return render_template('error.html', error=error)
    finally:
        cursor.close()
        link.close()


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        s.connect(('8.8.8.8', 80))
        ip_address = s.getsockname()[0]
    except Exception:
        ip_address = '127.0.0.1'
    finally:
        s.close()
    return ip_address


@app.route('/predict', methods=['GET', 'POST'])
def predict():
    if 'user_uid' not in session:
        return redirect(url_for('login'))

    if request.method == "GET":
        uid = 'uid_'+''.join(random.choices(string.ascii_letters + string.digits, k=10))
        return render_template('predict.html', uid=uid)

    link = get_db_connection()
    cursor = link.cursor()
    try:
        uid = request.form["uid"]
        sender = request.form["sender"]
        receiver = request.form["receiver"]
        amount = request.form["amount"]
        email = session["user_email"]
        username = session["user_name"]

        # 1. Get the 'mathematical' verdict from the engine
        result = predictresult([sender, receiver, amount, email])

        fraudlistarray = fraudlist()
        senderfraud = "no"
        receiverfraud = "no"

        # 2. Get the 'historical' verdict from the database
        cursor.execute("SELECT senderfraud,receiverfraud FROM upifraud_2024_history WHERE sender = %s or receiver = %s ORDER BY transaction_time DESC LIMIT 1", (sender, sender))
        senderfraudresult = cursor.fetchone()
        if senderfraudresult and (senderfraudresult[0] == "yes" or senderfraudresult[1] == "yes"):
            senderfraud = "yes"

        cursor.execute("SELECT senderfraud,receiverfraud FROM upifraud_2024_history WHERE receiver = %s or sender = %s ORDER BY transaction_time DESC LIMIT 1", (receiver, receiver))
        receiverfraudresult = cursor.fetchone()
        if receiverfraudresult and (receiverfraudresult[0] == "yes" or receiverfraudresult[1] == "yes"):
            receiverfraud = "yes"

        senderfraud = "yes" if sender in fraudlistarray else senderfraud
        receiverfraud = "yes" if receiver in fraudlistarray else receiverfraud

        # 3. Calculate Risk
        if senderfraud == "yes" and receiverfraud == "yes":
            risk = "high risk"
        elif senderfraud == "yes" or receiverfraud == "yes":
            risk = "risk"
        else:
            risk = "normal"

        # 4. Force Consistency: If it's High Risk, override the math engine and mark it Fraud.
        if risk == "high risk":
            result = "Fraud"

        ipaddress = str(get_local_ip())

        # Insert with NOW() for precise time
        insert_query = """
            INSERT INTO upifraud_2024_history 
            (uid, user, username, transaction_time, sender, receiver, amount, result, ipaddress, senderfraud, receiverfraud, risk) 
            VALUES (%s, %s, %s, NOW(), %s, %s, %s, %s, %s, %s, %s, %s)
        """
        insert_values = (
            uid, email, username, sender, receiver,
            amount, result, ipaddress, senderfraud, receiverfraud, risk
        )
        cursor.execute(insert_query, insert_values)
        link.commit()

        print("----------------------------------------------")
        print(sender+"-"+receiver+"-"+amount+"-"+email)
        n = random.randint(123, 99999)
        subprocess.run(["python", "blockmanager.py", "-s", sender+"-"+receiver+"-"+amount+"-"+email, "-r", str(n)])
        return render_template('result.html', result=result, risk=risk)
    except Exception as e:
        error = e
        return render_template('error.html', error=error)
    finally:
        cursor.close()
        link.close()


@app.route('/check_fraud', methods=['POST'])
def check_fraud():
    data = request.get_json()
    upi_id = data.get('upi_id', '').strip()
    if not upi_id:
        return jsonify({'status': 'ok'})

    VELOCITY_LIMIT_COUNT = 3
    VELOCITY_LIMIT_MINUTES = 2
    db_fraud_flag = False
    file_flag = False

    try:
        static_fraud_list = fraudlist()
        file_flag = upi_id in static_fraud_list
    except Exception:
        pass

    link = get_db_connection()
    cursor = link.cursor()
    try:
        query_fraud = """
            SELECT COUNT(*) FROM upifraud_2024_history
            WHERE (sender = %s OR receiver = %s)
            AND (result = 'Fraud' OR risk = 'high risk' OR risk = 'risk')
        """
        cursor.execute(query_fraud, (upi_id, upi_id))
        if cursor.fetchone()[0] > 0:
            db_fraud_flag = True

        if db_fraud_flag or file_flag:
            return jsonify({'status': 'fraud'})

        query_velocity = f"""
            SELECT COUNT(*) FROM upifraud_2024_history
            WHERE (sender = %s OR receiver = %s)
            AND transaction_time > (NOW() - INTERVAL {VELOCITY_LIMIT_MINUTES} MINUTE)
        """
        cursor.execute(query_velocity, (upi_id, upi_id))
        if cursor.fetchone()[0] >= VELOCITY_LIMIT_COUNT:
            return jsonify({'status': 'velocity'})

        query_history = "SELECT COUNT(*) FROM upifraud_2024_history WHERE sender = %s OR receiver = %s"
        cursor.execute(query_history, (upi_id, upi_id))
        if cursor.fetchone()[0] == 0:
            return jsonify({'status': 'unknown'})

    except Exception as e:
        print(f"Error in /check_fraud: {e}")
    finally:
        if cursor:
            cursor.close()
        if link:
            link.close()
    return jsonify({'status': 'ok'})


@app.route('/check_pair_velocity', methods=['POST'])
def check_pair_velocity():
    data = request.get_json()
    sender = data.get('sender')
    receiver = data.get('receiver')
    if not sender or not receiver:
        return jsonify({'status': 'error', 'message': 'Missing sender or receiver'})

    VELOCITY_COUNT = 2
    VELOCITY_MINUTES = 2

    link = get_db_connection()
    cursor = link.cursor()
    try:
        # 1. Velocity Check (Pair)
        query = f"""
            SELECT COUNT(*) FROM upifraud_2024_history
            WHERE sender = %s AND receiver = %s
            AND transaction_time > (NOW() - INTERVAL {VELOCITY_MINUTES} MINUTE)
        """
        cursor.execute(query, (sender, receiver))
        if cursor.fetchone()[0] >= VELOCITY_COUNT:
            return jsonify({'status': 'velocity_fraud'})

        # 2. Double Fraud Check
        sender_is_fraud = False
        cursor.execute("SELECT COUNT(*) FROM upifraud_2024_history WHERE (sender=%s OR receiver=%s) AND (result='Fraud' OR risk='high risk' OR risk='risk')", (sender, sender))
        if cursor.fetchone()[0] > 0:
            sender_is_fraud = True

        receiver_is_fraud = False
        cursor.execute("SELECT COUNT(*) FROM upifraud_2024_history WHERE (sender=%s OR receiver=%s) AND (result='Fraud' OR risk='high risk' OR risk='risk')", (receiver, receiver))
        if cursor.fetchone()[0] > 0:
            receiver_is_fraud = True

        static_list = fraudlist()
        if sender in static_list:
            sender_is_fraud = True
        if receiver in static_list:
            receiver_is_fraud = True

        if sender_is_fraud and receiver_is_fraud:
            return jsonify({'status': 'double_fraud', 'result': 'FRAUD', 'risk': 'HIGH RISK'})

        return jsonify({'status': 'ok'})
    except Exception as e:
        print(f"Error in /check_pair_velocity: {e}")
        return jsonify({'status': 'error', 'message': str(e)})
    finally:
        if cursor:
            cursor.close()
        if link:
            link.close()


@app.route('/logout')
def logout():
    session.pop('user_uid', None)
    session.pop('user_name', None)
    session.pop('user_email', None)
    session.pop('email_verified', None)
    session.pop('otp', None)
    session.pop('otp_email', None)
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)