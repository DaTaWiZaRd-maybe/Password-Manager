import sqlite3
import bcrypt



def create_tables():
    
    conn = sqlite3.connect("password-manager.db")#Connect it with database
    cursor=conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT ,
        username TEXT UNIQUE,
        master_password TEXT
    )''')#making users table
    
    cursor.execute('''CREATE TABLE IF NOT EXISTS passwords (
        id INTEGER PRIMARY KEY AUTOINCREMENT ,
        website TEXT,
        username TEXT ,
        password TEXT
    )''')#making passwords table
    conn.commit()
    conn.close()

def hash_password(password: str) -> str:
    
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed

def check_password(password : str, hashed: bytes) -> bool:
    
    return bcrypt.checkpw(password.encode(), hashed)

def setup_master():
    
    conn = sqlite3.connect("password-manager.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    user = cursor.fetchone()
    
    if user is None : # first run → table empty
        master = input("Set new Master password = ")
        hashed = hash_password(master)
        cursor.execute(
            "INSERT INTO users (username, master_password) VALUES (?, ?)",
            ("admin", hashed.decode())
        )
        conn.commit()
        print("New Master password set")
            
    else: # subsequent runs → ask for login
        master = input("Enter your master password = ")
        if check_password(master, user[2].encode()):
            print("Login Success")
        else:
            print("Wrong password. Exiting.")
            exit()
        conn.close()
        
def add_password(website, username, password):
    
    conn = sqlite3.connect("password-manager.db")
    cursor = conn.cursor()
    cursor.execute('''INSERT INTO passwords (website, username, password) VALUES (?,?,?)''',(website, username, password)
    )
    conn.commit()
    conn.close()
    
    print(f"Password for {website} saved!")
    
def get_password(website):
    
    conn = sqlite3.connect("password-manager.db")
    cursor = conn.cursor()
    cursor.execute("SELECT username, password FROM passwords WHERE website = ?", (website,))
    record = cursor.fetchone()
    conn.close()
    
    if record:
        print(f"Website = {website}\n username: {record[0]}\n password: {record[1]}")

    else:
        print(f"No password found for {website}")

def list_passwords():

    conn = sqlite3.connect("password-manager.db")
    cursor = conn.cursor()
    cursor.execute("SELECT username, website FROM passwords")
    records = cursor.fetchall()
    
    if records :
        print("Saved Accounts = \n")
        
        for i in records :
            print(f"Username = {i[0]} | Website = {i[1]}")
            
    else:
        print("No Accounts")
        
if __name__ == "__main__":
    
    print("Creating tables...")
    
    create_tables()
    print("Tables created.")
    
    setup_master()
    print("Master setup complete.\n")

    while True:
        print("\nChoose an option:")
        print("1. Add new password")
        print("2. Get a password")
        print("3. List all accounts")
        print("4. Exit")

        choice = input("Option = ")

        if choice == "1":
            website = input("Website: ")
            username = input("Username: ")
            password = input("Password: ")
            add_password(website, username, password)
            
        elif choice == "2":
            website = input("Enter website to search: ")
            get_password(website)
            
        elif choice == "3":
            list_passwords()
            
        elif choice == "4":
            print("Exiting Password Manager.")
            break
        
        else:
            print("Invalid choice. Try again.")

        
    
                    
        
    
