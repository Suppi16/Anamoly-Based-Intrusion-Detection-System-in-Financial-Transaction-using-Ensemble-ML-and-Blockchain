import mysql.connector
import csv

# --- NO MORE GLOBAL CONNECTION ---

def get_db_connection():
    # Helper function to get a new connection
    connection = mysql.connector.connect(
        host='localhost',
        user='root',
        password='',
        database='upifraud_2024'
        # No autocommit, we will commit manually
    )
    return connection

def predictresult(data):
    """
    data = [sender, receiver, amount, email]
    Checks if either sender or receiver shows fraudulent behavior.
    """
    # --- GET NEW CONNECTION ---
    link = get_db_connection()
    cursor = link.cursor()
    result = "Normal"

    sender = data[0]
    receiver = data[1]
    amount = float(data[2])

    print("\n----- Fraud Detection Started -----")
    print(f"Sender: {sender}, Receiver: {receiver}, Amount: {amount}")

    def check_user_fraud(user, role):
        # Count previous transactions by this user (as sender or receiver)
        cursor.execute("""
            SELECT COUNT(*) FROM upifraud_2024_history
            WHERE sender = %s OR receiver = %s
        """, (user, user))
        count = cursor.fetchone()[0]
        print(f"{role} ({user}) transaction count:", count)

        if count < 5:
            print(f"{role}: Not enough history, marked Normal.")
            return "Normal"

        # Calculate average transaction amount
        cursor.execute("""
            SELECT ROUND(AVG(amount)) FROM upifraud_2024_history
            WHERE sender = %s OR receiver = %s
            ORDER BY id DESC LIMIT 10
        """, (user, user))
        avg_amount = cursor.fetchone()[0]
        if avg_amount is None:
            print(f"{role}: No valid transaction data found.")
            return "Normal"

        print(f"{role} average amount: {avg_amount}")
        threshold = avg_amount * 1.5
        print(f"{role} threshold (avg × 1.5): {threshold}")

        # Compare with input amount
        if amount > threshold:
            print(f"{role} flagged as FRAUD! (amount {amount} > {threshold})")
            return "Fraud"
        else:
            print(f"{role} normal (amount {amount} ≤ {threshold})")
            return "Normal"

    # Check sender and receiver separately
    sender_status = check_user_fraud(sender, "Sender")
    receiver_status = check_user_fraud(receiver, "Receiver")

    # Final result
    if sender_status == "Fraud" or receiver_status == "Fraud":
        result = "Fraud"

    # --- CLOSE CONNECTION AND CURSOR ---
    cursor.close()
    link.close()
    
    print("Final Result:", result)
    print("----- Fraud Detection Complete -----\n")
    return result


def fraudlist():
    """Reads fraudlist.csv if available"""
    data_array = []
    try:
        with open('fraudlist.csv', 'r') as csvfile:
            csvreader = csv.reader(csvfile)
            data_array = [row[0] for row in csvreader if row]
    except FileNotFoundError:
        # It's fine if the file doesn't exist, we'll just return an empty list.
        data_array = []
    return data_array